#!/usr/bin/env python3
"""Evaluate PDF v3 from all angles before replacing v1 in production."""

from __future__ import annotations

import io
import json
import sys
import warnings
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
warnings.filterwarnings("ignore")

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
V3_DIR = ROOT / "models" / "PDF_v3"
V1_DIR = ROOT / "models" / "pdf"
IEEE = Path(r"C:\Users\Suhani Buche\Downloads\IEEE_Conference_Template__1_ (1).pdf")

ORDER = json.loads((V3_DIR / "pdf_feature_order.json").read_text())
THRESH = json.loads((V3_DIR / "pdf_thresholds.json").read_text())
CARD = json.loads((V3_DIR / "pdf_model_card.json").read_text())


def extract_v3(content: bytes) -> dict[str, float]:
    """PDFiD-style counts matching v3 feature_order (lowercase names)."""
    text = content.decode("latin-1", errors="ignore")
    low = text.lower()
    feats = {name: 0.0 for name in ORDER}

    def c(token: str) -> float:
        return float(low.count(token.lower()))

    header = text[:1024]
    feats["header"] = 1.0 if "%pdf" in header.lower() else 0.0
    feats["obj"] = c("obj")
    feats["endobj"] = c("endobj")
    feats["stream"] = c("stream")
    feats["endstream"] = c("endstream")
    feats["xref"] = c("xref")
    feats["trailer"] = c("trailer")
    feats["startxref"] = c("startxref")
    feats["encrypt"] = c("/encrypt")
    feats["isencrypted"] = 1.0 if feats["encrypt"] > 0 else 0.0
    feats["objstm"] = c("/objstm")
    feats["js"] = c("/js")
    feats["javascript"] = c("/javascript")
    feats["aa"] = float(low.count("/aa") - low.count("/aaa"))
    feats["openaction"] = c("/openaction")
    feats["launch"] = c("/launch")
    feats["acroform"] = c("/acroform")
    feats["xfa"] = c("/xfa")
    feats["jbig2decode"] = c("/jbig2decode")
    feats["richmedia"] = c("/richmedia")
    feats["embeddedfile"] = c("/embeddedfile")
    feats["embeddedfiles"] = c("/embeddedfiles") + feats["embeddedfile"]
    feats["images"] = c("/image") + c("/xobject")
    feats["text"] = c("/font") + c("bt\n") + c("bt\r")
    feats["colors"] = c("/colors") + c("/colorspace")
    return feats


def vec(feats: dict[str, float]) -> np.ndarray:
    return np.array([[float(feats[n]) for n in ORDER]])


def verdict(p: float) -> str:
    if p >= THRESH["malicious"]:
        return "MALICIOUS"
    if p >= THRESH["suspicious"]:
        return "SUSPICIOUS"
    return "CLEAN"


def make_pdf(body: str) -> bytes:
    return f"%PDF-1.4\n{body}\n%%EOF\n".encode("latin-1")


def hr(title: str) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def main() -> int:
    model_path = V3_DIR / "pdf_malware_model.joblib"
    model = joblib.load(model_path)

    hr("1. ARTIFACT + CARD")
    print(f"  path          : {model_path}")
    print(f"  size_kb       : {model_path.stat().st_size / 1024:.1f}")
    print(f"  type          : {type(model).__name__}")
    print(f"  module        : {type(model).__module__}")
    print(f"  version       : {CARD.get('version')}")
    print(f"  sources       : {CARD.get('training_sources')}")
    print(f"  excluded bias : {CARD.get('excluded_bias_prone_features')}")
    print(f"  calibration   : {CARD.get('calibration')}")
    print(f"  susp thresh   : {THRESH['suspicious']:.4f}")
    print(f"  mal thresh    : {THRESH['malicious']:.4f}")
    print(f"  card recall   : {CARD.get('internal_malicious_recall')}")
    print(f"  card FPR      : {CARD.get('internal_false_positive_rate')}")
    print(f"  academic FPR  : {CARD.get('external_academic_hard_fpr')}")
    print(f"  generic FPR   : {CARD.get('external_generic_hard_fpr')}")

    inner = model
    if hasattr(model, "calibrated_classifiers_"):
        print("  calibrated    : YES (CalibratedClassifierCV)")
        try:
            inner = model.calibrated_classifiers_[0].estimator
            print(f"  base estimator: {type(inner).__name__}")
        except Exception as exc:
            print(f"  base unwrap   : {exc}")
            inner = model
    elif hasattr(model, "estimator"):
        inner = model.estimator
        print(f"  wrapped base  : {type(inner).__name__}")

    n_in = getattr(inner, "n_features_in_", getattr(model, "n_features_in_", None))
    print(f"  n_features_in : {n_in}  (order file has {len(ORDER)})")
    if n_in is not None and int(n_in) != len(ORDER):
        print("  MISMATCH: feature_order.json length != model.n_features_in_")

    names = getattr(inner, "feature_names_in_", getattr(model, "feature_names_in_", None))
    if names is not None:
        names = list(names)
        print(f"  feature_names : {names}")
        if names != ORDER:
            print("  MISMATCH vs pdf_feature_order.json")

    hr("2. FEATURE IMPORTANCE (if available)")
    importances = getattr(inner, "feature_importances_", None)
    if importances is None:
        print("  no feature_importances_ on this estimator")
    else:
        ranked = sorted(zip(ORDER, importances), key=lambda kv: -kv[1])
        for name, imp in ranked:
            bar = "#" * int(imp * 40)
            print(f"  {name:<16} {imp:.4f} {bar}")

    hr("3. SANITY VECTORS")
    zeros = {n: 0.0 for n in ORDER}
    zeros["header"] = 1.0
    p0 = float(model.predict_proba(vec(zeros))[0][1])
    print(f"  all-zero + header=1     p={p0:.4f}  {verdict(p0)}")

    js = dict(zeros)
    js["js"] = 2.0
    js["javascript"] = 2.0
    js["openaction"] = 1.0
    js["launch"] = 1.0
    pjs = float(model.predict_proba(vec(js))[0][1])
    print(f"  JS+OpenAction+Launch    p={pjs:.4f}  {verdict(pjs)}")

    encrypt = dict(zeros)
    encrypt["encrypt"] = 1.0
    encrypt["isencrypted"] = 1.0
    pe = float(model.predict_proba(vec(encrypt))[0][1])
    print(f"  encrypted only          p={pe:.4f}  {verdict(pe)}")

    hr("4. SYNTHETIC PDF BYTES")
    synthetics = {
        "minimal_clean": make_pdf("1 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n0"),
        "js_openaction": make_pdf(
            "1 0 obj<</OpenAction<</S/JavaScript/JS(app.alert(1))>>/JS 2 0 R>>endobj\n"
            "2 0 obj<</S/JavaScript>>endobj"
        ),
        "launch": make_pdf("1 0 obj<</Launch<</Win<</F(cmd.exe)>>>>>>endobj"),
        "embeddedfile": make_pdf("1 0 obj<</Type/EmbeddedFile/Length 4>>stream\nMZ\x90endstream endobj"),
        "acroform_xfa": make_pdf("1 0 obj<</AcroForm<</XFA true>>>>endobj"),
        "objstm_xrefstream": make_pdf("/Type /XRef /Type /ObjStm stream\nendstream"),
    }
    for name, blob in synthetics.items():
        feats = extract_v3(blob)
        p = float(model.predict_proba(vec(feats))[0][1])
        fired = [k for k, v in feats.items() if v and k not in {"header", "obj", "endobj", "stream", "endstream"}]
        print(f"  {name:<22} p={p:.4f}  {verdict(p):<12} fired={fired}")

    hr("5. REAL FILE: IEEE conference template (v1 false positive)")
    if IEEE.exists():
        data = IEEE.read_bytes()
        feats = extract_v3(data)
        p = float(model.predict_proba(vec(feats))[0][1])
        print(f"  file   : {IEEE.name}  ({len(data)/1024:.0f} KB)")
        print(f"  p      : {p:.4f}  verdict={verdict(p)}")
        print("  nonzero features:")
        for k in ORDER:
            if feats[k]:
                print(f"    {k:<16} {feats[k]:.1f}")
        # Compare v1 if present
        v1_path = V1_DIR / "pdf_malware_rf.joblib"
        if v1_path.exists():
            print("  (v1 used PdfSize/MetadataSize and scored this file ~0.67 SUSPICIOUS)")
    else:
        print("  IEEE file missing")

    extra = [
        Path(r"C:\Users\Suhani Buche\Downloads"),
    ]
    hr("6. OTHER LOCAL PDFs IN DOWNLOADS (benign-looking filenames)")
    pdfs = []
    downloads = Path(r"C:\Users\Suhani Buche\Downloads")
    if downloads.exists():
        pdfs = list(downloads.glob("*.pdf"))[:8]
    if not pdfs:
        print("  no extra PDFs found")
    for path in pdfs:
        try:
            data = path.read_bytes()
            if not data.startswith(b"%PDF"):
                continue
            p = float(model.predict_proba(vec(extract_v3(data)))[0][1])
            print(f"  {p:.4f}  {verdict(p):<12}  {path.name[:60]}")
        except Exception as exc:
            print(f"  skip {path.name}: {exc}")

    hr("7. VERDICT")
    print("  See scores above. Expected for a well-trained v3:")
    print("  - IEEE / academic PDFs -> CLEAN (card claims 0.0 hard FPR)")
    print("  - JS/Launch synthetic -> MALICIOUS or at least SUSPICIOUS")
    print("  - Encrypted-only should not auto-block unless other signals fire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
