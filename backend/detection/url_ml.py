"""URL risk model v1 (XGBoost). Uses models/url/v1 only — not the parked root artifacts."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from backend.config import settings

log = logging.getLogger(__name__)

COMMON_DOMAIN_CAP = 0.12
EXTRA_SAFE = {
    "github.com",
    "wikipedia.org",
    "gov.in",
    "nic.in",
}

_booster = None
_fe = None
_failed = False


def url_v1_dir() -> Path:
    return Path(settings.model_dir) / "url" / "v1"


def available() -> bool:
    d = url_v1_dir()
    return (d / "url_model.json").exists() and (d / "feature_extractor.py").exists()


def _ensure() -> Any:
    global _booster, _fe, _failed
    if _failed:
        raise RuntimeError("url v1 previously failed to load")
    if _booster is not None:
        return _booster
    d = url_v1_dir()
    if not available():
        _failed = True
        raise FileNotFoundError(f"URL v1 model not found under {d}")
    sys.path.insert(0, str(d))
    import feature_extractor as fe
    import xgboost as xgb

    if not hasattr(fe, "extract_features"):
        fe.extract_features = fe.extract_url_features
    bst = xgb.Booster()
    bst.load_model(str(d / "url_model.json"))
    _fe = fe
    _booster = bst
    log.info("Loaded URL XGBoost v1 from %s", d)
    return _booster


def _known_good(feats: dict) -> bool:
    if (
        feats.get("is_common_domain") == 1
        and feats.get("brand_spoof") == 0
        and feats.get("has_ip_address") == 0
        and feats.get("is_shortener") == 0
        and feats.get("has_suspicious_tld") == 0
        and feats.get("num_at_symbols") == 0
    ):
        return True
    return False


def _host_safe(url: str) -> bool:
    try:
        from urllib.parse import urlparse

        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except Exception:
        return False
    if host in EXTRA_SAFE:
        return True
    return any(host.endswith("." + d) for d in EXTRA_SAFE)


def score_url(url: str) -> float:
    import xgboost as xgb

    bst = _ensure()
    assert _fe is not None
    feats_df = _fe.featurize_dataframe([url])
    dmat = xgb.DMatrix(feats_df, feature_names=_fe.FEATURE_NAMES)
    try:
        raw = float(bst.predict(dmat, iteration_range=(0, int(bst.best_iteration) + 1))[0])
    except Exception:
        raw = float(bst.predict(dmat)[0])
    f = _fe.extract_url_features(url)
    if _known_good(f) or _host_safe(url):
        raw = min(raw, COMMON_DOMAIN_CAP)
    return float(min(1.0, max(0.0, raw)))


def score_urls(urls: list[str]) -> list[float]:
    return [score_url(u) for u in urls]
