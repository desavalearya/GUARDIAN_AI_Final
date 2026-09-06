#!/usr/bin/env python3
"""Deeper PDF v3 checks: pipeline internals + realistic vs sparse vectors."""

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
V3 = ROOT / "models" / "PDF_v3"
ORDER = json.loads((V3 / "pdf_feature_order.json").read_text())
THRESH = json.loads((V3 / "pdf_thresholds.json").read_text())
IEEE = Path(r"C:\Users\Suhani Buche\Downloads\IEEE_Conference_Template__1_ (1).pdf")
sys.path.insert(0, str(ROOT / "scripts"))
from eval_pdf_v3 import extract_v3, vec, verdict  # noqa: E402


def unwrap(model):
    est = model
    print(f"top: {type(est).__name__}")
    if hasattr(est, "calibrated_classifiers_"):
        cc = est.calibrated_classifiers_[0]
        print(f"  calibrated_classifiers_[0]: {type(cc).__name__} attrs={dir(cc)[:0]}")
        for attr in ("estimator", "base_estimator", "clf"):
            if hasattr(cc, attr):
                est = getattr(cc, attr)
                print(f"  via {attr}: {type(est).__name__}")
                break
    if hasattr(est, "named_steps"):
        print("  pipeline steps:", list(est.named_steps.keys()))
        for name, step in est.named_steps.items():
            print(f"    {name}: {type(step).__name__}")
        last = list(est.named_steps.values())[-1]
        return est, last
    return est, est


def main() -> int:
    model = joblib.load(V3 / "pdf_malware_model.joblib")
    pipe, last = unwrap(model)
    print(f"last estimator: {type(last).__name__}")
    if hasattr(last, "feature_importances_"):
        ranked = sorted(zip(ORDER, last.feature_importances_), key=lambda kv: -kv[1])
        print("\nfeature importances:")
        for n, i in ranked:
            print(f"  {n:<16} {i:.4f}")
    elif hasattr(last, "coef_"):
        coef = np.ravel(last.coef_)
        ranked = sorted(zip(ORDER, coef), key=lambda kv: -abs(kv[1]))
        print("\ncoefficients:")
        for n, i in ranked:
            print(f"  {n:<16} {i:+.4f}")

    ieee = extract_v3(IEEE.read_bytes())
    print("\nIEEE as realistic benign baseline, then add attack tokens:")
    p = float(model.predict_proba(vec(ieee))[0][1])
    print(f"  IEEE as-is              p={p:.4f} {verdict(p)}")
    for token in ("js", "javascript", "openaction", "launch", "embeddedfile", "encrypt"):
        f = dict(ieee)
        f[token] = max(f[token], 2.0)
        if token == "encrypt":
            f["isencrypted"] = 1.0
        p = float(model.predict_proba(vec(f))[0][1])
        print(f"  IEEE + {token:<14} p={p:.4f} {verdict(p)}")

    combo = dict(ieee)
    combo["js"] = 2
    combo["javascript"] = 2
    combo["openaction"] = 1
    combo["launch"] = 1
    p = float(model.predict_proba(vec(combo))[0][1])
    print(f"  IEEE + JS/OA/Launch     p={p:.4f} {verdict(p)}")

    print("\nclass balance / classes_:", getattr(last, "classes_", getattr(model, "classes_", None)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
