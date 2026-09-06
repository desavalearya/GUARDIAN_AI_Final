#!/usr/bin/env python3
"""Validate the new Office/PDF extractors against the real files, old vs new."""

from __future__ import annotations

import io
import json
import sys
import warnings
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import joblib
import numpy as np

from backend.detection.attachment_features import (
    extract_office_features,
    extract_pdf_features,
)

DOCX = Path(r"C:\Users\Suhani Buche\Downloads\SY_AIML_A11-Patent.docx")
PDF = Path(r"C:\Users\Suhani Buche\Downloads\IEEE_Conference_Template__1_ (1).pdf")


def hr(t: str) -> None:
    print()
    print("=" * 72)
    print(t)
    print("=" * 72)


def verdict(p: float) -> str:
    return "MALICIOUS" if p >= 0.7 else "SUSPICIOUS" if p >= 0.4 else "CLEAN"


def run_office() -> None:
    order = json.loads((ROOT / "models" / "doc" / "office_feature_order.json").read_text())
    model = joblib.load(ROOT / "models" / "doc" / "office_malware_rf.joblib")

    hr(f"OFFICE: {DOCX.name}")
    res = extract_office_features(DOCX.read_bytes(), DOCX.name, order)
    print(f"  container          : {res.container}")
    print(f"  extraction method  : {res.extraction_method}")
    print(f"  has_macros         : {res.has_macros}")
    print(f"  macro source bytes : {res.macro_source_bytes:,}")
    for n in res.notes:
        print(f"  note               : {n}")

    active = {k: v for k, v in res.features.items() if v}
    print(f"  ACTIVE FEATURES    : {active or 'none (all zero)'}")

    vec = np.array([[res.features[f] for f in order]])
    p = float(model.predict_proba(vec)[0][1])
    print()
    print(f"  NEW  malicious_prob = {p:.4f}  -> {verdict(p)}")
    print("  OLD  malicious_prob = 0.6650  -> SUSPICIOUS   (phantom hits from ZIP bytes)")


def run_pdf() -> None:
    order = json.loads((ROOT / "models" / "pdf" / "pdf_feature_order.json").read_text())
    model = joblib.load(ROOT / "models" / "pdf" / "pdf_malware_rf.joblib")

    hr(f"PDF: {PDF.name}")
    res = extract_pdf_features(PDF.read_bytes(), order)
    print("  EXTRACTED FEATURES:")
    for f in order:
        print(f"    {f:<18} {res.features[f]:>14,.2f}")
    print()
    for n in res.notes:
        print(f"  note: {n}")

    vec = np.array([[res.features[f] for f in order]])
    p = float(model.predict_proba(vec)[0][1])
    print()
    print(f"  NEW  malicious_prob = {p:.4f}  -> {verdict(p)}")
    print("  OLD  malicious_prob = 0.7763  -> MALICIOUS")


def main() -> int:
    run_office()
    run_pdf()
    return 0


if __name__ == "__main__":
    sys.exit(main())
