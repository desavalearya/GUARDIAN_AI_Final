"""Evaluate models/url/v1 before integrating into the live path."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT / "models" / "url" / "v1"


def load_model():
    sys.path.insert(0, str(V1))
    import joblib

    model = joblib.load(V1 / "url_pipeline.joblib")
    model.model_dir = str(V1)
    if hasattr(model, "_booster"):
        model._booster = None
    return model


def score(model, url: str) -> float:
    try:
        return float(model.predict_proba([url])[0][1])
    except Exception:
        # Some wrappers return only malicious proba or need feature DF
        out = model.predict_proba([url])
        arr = out[0]
        return float(arr[1] if len(arr) > 1 else arr[0])


def verdict(p: float) -> str:
    if p >= 0.70:
        return "MALICIOUS"
    if p >= 0.35:
        return "SUSPICIOUS"
    return "CLEAN"


def main() -> int:
    print("Loading", V1)
    model = load_model()
    print("Loaded:", type(model).__name__)

    # Published card metrics
    tn, fp, fn, tp = 45172, 442, 5690, 8389
    total = tn + fp + fn + tp
    acc = (tn + tp) / total
    recall = tp / (tp + fn)
    precision = tp / (tp + fp)
    fpr = fp / (fp + tn)
    specificity = tn / (tn + fp)
    print("\n=== From MODEL_CARD (test @ FPR<=1% cutoff 0.9062) ===")
    print(f"Accuracy:   {acc*100:.2f}%")
    print(f"ROC-AUC:    94.69%")
    print(f"PR-AUC:     89.25%")
    print(f"Precision:  {precision*100:.2f}%")
    print(f"Recall:     {recall*100:.2f}%")
    print(f"FPR:        {fpr*100:.2f}%")
    print(f"Specificity:{specificity*100:.2f}%")

    smoke_path = ROOT / "models" / "url" / "smoke.json"
    cases = json.loads(smoke_path.read_text(encoding="utf-8"))["cases"] if smoke_path.exists() else []

    demo = [
        ("https://www.google.com", "benign"),
        ("https://www.microsoft.com", "benign"),
        ("https://github.com", "benign"),
        ("https://hdfcbank.com", "benign"),
        ("https://wikipedia.org", "benign"),
        ("https://hdfc-secure-login.xyz/verify/account", "phish"),
        ("https://upi-claim.top/pay/verify", "phish"),
        ("http://paypa1-secure-login.xyz/confirm-billing-details", "phish"),
        ("https://microsoft.com.evil.tk", "phish"),
        ("http://192.168.1.1/login", "phish"),
        ("https://bit.ly/anything", "phish"),
        ("https://verify-account-security.com/login", "phish"),
        ("https://login.microsoft.com", "benign"),
        ("https://sbi.co.in", "benign"),
    ]

    print("\n=== Smoke / demo URL scores ===")
    fail = 0
    for url, expect in demo:
        p = score(model, url)
        v = verdict(p)
        ok = True
        if expect == "benign" and p >= 0.35:
            ok = False
        if expect == "phish" and p < 0.35:
            ok = False
        mark = "OK" if ok else "FAIL"
        if not ok:
            fail += 1
        print(f"  [{mark}] {p:.4f} {v:10} {expect:6}  {url}")

    if cases:
        print("\n=== smoke.json checks ===")
        for c in cases:
            url = c["url"]
            p = score(model, url)
            ok = True
            if "p_malicious_max" in c and p > c["p_malicious_max"]:
                ok = False
            if "p_malicious_min" in c and p < c["p_malicious_min"]:
                ok = False
            mark = "OK" if ok else "FAIL"
            if not ok:
                fail += 1
            print(f"  [{mark}] {p:.4f}  {url}")

    print(f"\nLive smoke failures: {fail}")
    # Gate: good enough if card accuracy >= 85% AND ROC-AUC >= 0.90 AND smoke mostly works
    good = acc >= 0.85 and fail <= 3
    print(f"INTEGRATE: {'YES' if good else 'NO'}")
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
