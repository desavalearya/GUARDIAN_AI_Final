"""Shared loaders and scoring for live SMTP/.eml and Model Lab.

URL artifacts under models/url/ are never loaded here.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.config import settings
from backend.detection.attachment_features import extract_office_features, extract_pdf_features
from backend.detection.types import verdict_from_score

log = logging.getLogger(__name__)

_office_model = None
_pdf_model = None
_email_model = None
_email_tokenizer = None
_pdf_order: list[str] | None = None
_office_order: list[str] | None = None
_pdf_thresholds: tuple[float, float] | None = None


def model_path(*parts: str) -> Path:
    return Path(settings.model_dir).joinpath(*parts)


def pdf_dir() -> Path:
    v3 = model_path("PDF_v3")
    if (v3 / "pdf_malware_model.joblib").exists():
        return v3
    return model_path("pdf")


def _ensure_numpy_core_alias() -> None:
    """Joblib pickles from NumPy 2 may look for numpy._core on NumPy 1.x."""
    try:
        import numpy._core  # noqa: F401
        return
    except Exception:
        pass
    try:
        import numpy.core as core

        sys.modules.setdefault("numpy._core", core)
        for name in ("multiarray", "_multiarray_umath", "umath", "numeric"):
            mod = getattr(core, name, None)
            if mod is not None:
                sys.modules.setdefault(f"numpy._core.{name}", mod)
    except Exception:
        log.debug("numpy._core alias not applied", exc_info=True)


def pdf_thresholds() -> tuple[float, float]:
    global _pdf_thresholds
    if _pdf_thresholds is None:
        path = pdf_dir() / "pdf_thresholds.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            _pdf_thresholds = (
                float(data.get("suspicious", 0.4)),
                float(data.get("malicious", 0.7)),
            )
        else:
            _pdf_thresholds = (0.4, 0.7)
    return _pdf_thresholds


def pdf_feature_order() -> list[str]:
    global _pdf_order
    if _pdf_order is None:
        path = pdf_dir() / "pdf_feature_order.json"
        _pdf_order = json.loads(path.read_text(encoding="utf-8"))
    return _pdf_order


def office_feature_order() -> list[str]:
    global _office_order
    if _office_order is None:
        path = model_path("doc", "office_feature_order.json")
        _office_order = json.loads(path.read_text(encoding="utf-8"))
    return _office_order


def load_office_model():
    global _office_model
    if _office_model is None:
        import joblib

        path = model_path("doc", "office_malware_rf.joblib")
        if not path.exists():
            raise FileNotFoundError(f"Office model not found: {path}")
        _office_model = joblib.load(path)
        log.info("Loaded Office model from %s", path)
    return _office_model


def load_pdf_model():
    global _pdf_model
    if _pdf_model is None:
        import joblib

        _ensure_numpy_core_alias()
        path = pdf_dir() / "pdf_malware_model.joblib"
        if not path.exists():
            path = pdf_dir() / "pdf_malware_rf.joblib"
        if not path.exists():
            raise FileNotFoundError(f"PDF model not found under {pdf_dir()}")
        _pdf_model = joblib.load(path)
        log.info("Loaded PDF model from %s", path)
    return _pdf_model


def load_email_model():
    global _email_model, _email_tokenizer
    if _email_model is None:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        model_dir = model_path("email")
        if not (model_dir / "config.json").exists():
            raise FileNotFoundError(f"Email model not found: {model_dir}")
        try:
            _email_tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
        except Exception:
            _email_tokenizer = AutoTokenizer.from_pretrained(str(model_dir), use_fast=False)
        _email_model = AutoModelForSequenceClassification.from_pretrained(str(model_dir))
        _email_model.eval()
        log.info("Loaded XLM-R email model from %s", model_dir)
    return _email_model, _email_tokenizer


def _predict_proba_matrix(model: Any, feature_names: list[str], values: list[float]) -> list[float]:
    import numpy as np
    import pandas as pd

    frame = pd.DataFrame([dict(zip(feature_names, values))])
    try:
        proba = model.predict_proba(frame)[0]
    except Exception:
        proba = model.predict_proba(np.array([values]))[0]
    return [float(x) for x in proba]


def _top_features(model: Any, feature_names: list[str], values: list[float], limit: int = 10) -> list[dict[str, Any]]:
    import numpy as np

    importances = getattr(model, "feature_importances_", None)
    if importances is None and hasattr(model, "calibrated_classifiers_"):
        try:
            est = model.calibrated_classifiers_[0].estimator
            if hasattr(est, "named_steps"):
                est = list(est.named_steps.values())[-1]
            importances = getattr(est, "feature_importances_", None)
        except Exception:
            importances = None
    if importances is None:
        return []
    order = np.argsort(importances)[::-1][:limit]
    return [
        {
            "name": feature_names[idx],
            "value": float(values[idx]),
            "importance": float(importances[idx]),
        }
        for idx in order
        if idx < len(feature_names)
    ]


@dataclass
class TextScore:
    phishing_probability: float
    verdict: str
    explanation: str
    confidence: float
    model_version: str
    used_ml: bool


@dataclass
class FileScore:
    malicious_probability: float
    verdict: str
    explanation: str
    confidence: float
    model_version: str
    used_ml: bool
    filename: str
    features: dict[str, float] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    top_features: list[dict[str, Any]] = field(default_factory=list)


def score_text(text: str) -> TextScore:
    model, tokenizer = load_email_model()
    import torch

    inputs = tokenizer(
        text or "",
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    with torch.no_grad():
        outputs = model(**inputs)
        probas = torch.softmax(outputs.logits, dim=1)[0]
        phishing_prob = float(probas[1].item())
        confidence = float(max(probas[0].item(), probas[1].item()))

    verdict = verdict_from_score(phishing_prob)
    if phishing_prob >= 0.75:
        explanation = "XLM-R high-confidence phishing language."
    elif phishing_prob >= 0.4:
        explanation = "XLM-R sees phishing-like language."
    else:
        explanation = "XLM-R treats this text as benign."
    return TextScore(
        phishing_probability=round(phishing_prob, 4),
        verdict=verdict,
        explanation=explanation,
        confidence=round(confidence, 4),
        model_version="xlm-r-v1",
        used_ml=True,
    )


def score_pdf(content: bytes, filename: str = "attachment.pdf") -> FileScore:
    names = pdf_feature_order()
    extraction = extract_pdf_features(content, names)
    model = load_pdf_model()
    values = [float(extraction.features.get(name, 0.0)) for name in names]
    probabilities = _predict_proba_matrix(model, names, values)
    malicious_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
    susp_t, mal_t = pdf_thresholds()
    if malicious_prob >= mal_t:
        verdict = "malicious"
        explanation = f"PDF v3 matches malicious structure (score {malicious_prob:.2f})."
    elif malicious_prob >= susp_t:
        verdict = "suspicious"
        explanation = f"PDF v3 has suspicious structure (score {malicious_prob:.2f})."
    else:
        verdict = "clean"
        explanation = f"PDF v3 structure looks benign (score {malicious_prob:.2f})."
    meta = extraction.as_meta()
    meta["thresholds"] = {"suspicious": susp_t, "malicious": mal_t}
    meta["filename"] = filename
    return FileScore(
        malicious_probability=round(malicious_prob, 4),
        verdict=verdict,
        explanation=explanation,
        confidence=round(max(probabilities), 4),
        model_version="pdf-v3",
        used_ml=True,
        filename=filename,
        features=extraction.features,
        meta=meta,
        top_features=_top_features(model, names, values),
    )


def score_office(content: bytes, filename: str) -> FileScore:
    names = office_feature_order()
    extraction = extract_office_features(content, filename, names)
    model = load_office_model()
    values = [float(extraction.features[name]) for name in names]
    probabilities = _predict_proba_matrix(model, names, values)
    malicious_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
    triggered = sorted(name.strip() for name, value in extraction.features.items() if value)
    if not extraction.has_macros:
        verdict = "clean"
        explanation = "No VBA macro project; Office model not applied."
        shown = 0.0
        used = False
    elif malicious_prob >= 0.7:
        verdict = "malicious"
        explanation = f"Malicious macro indicators (score {malicious_prob:.2f}). Triggered: {', '.join(triggered) or 'none'}"
        shown = malicious_prob
        used = True
    elif malicious_prob >= 0.4:
        verdict = "suspicious"
        explanation = f"Macros with some suspicious indicators (score {malicious_prob:.2f})."
        shown = malicious_prob
        used = True
    else:
        verdict = "clean"
        explanation = f"Macros present but no malicious patterns (score {malicious_prob:.2f})."
        shown = malicious_prob
        used = True
    meta = extraction.as_meta()
    meta["triggered_features"] = triggered
    meta["model_consulted"] = used
    return FileScore(
        malicious_probability=round(shown, 4),
        verdict=verdict,
        explanation=explanation,
        confidence=round(max(probabilities), 4),
        model_version="office-xgb-v1",
        used_ml=used,
        filename=filename,
        features=extraction.features,
        meta=meta,
        top_features=_top_features(model, names, values),
    )
