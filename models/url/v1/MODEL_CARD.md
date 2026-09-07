# Model Card: URL Risk Classifier (url-xgb-v1)

## Architecture
- Classifier: XGBoost Booster (`binary:logistic`)
- Features: 37 lexical/structural features (offline, fast CPU-only)
- Inference Cap: Known-good domains capped at 0.12

## Test Performance Metrics
- **ROC-AUC:** 0.9469
- **PR-AUC:** 0.8925
- **Optimal Cutoff (FPR <= 1%):** 0.9062
- **Test Set Confusion Matrix (@ opt):**
  - TN: 45172 | FP: 442
  - FN: 5690 | TP: 8389
