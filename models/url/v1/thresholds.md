# PhishProof URL Model Thresholds

| Verdict | Probability Range | Action |
|---|---|---|
| **clean** | `p < 0.35` | Pass through without warning |
| **suspicious** | `0.35 <= p < 0.70` | Flag warning header / quarantine preview |
| **malicious** | `p >= 0.70` | Hard block / rewrite link |

- **Calibrated Low-FPR Operating Point:** `0.9062` (achieves FPR <= 1% on benign traffic)
