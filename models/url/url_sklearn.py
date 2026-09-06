
import os
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin

COMMON_DOMAIN_CAP = 0.12

def _known_good(f):
    return (
        f["is_common_domain"] == 1
        and f["brand_spoof"] == 0
        and f["has_ip_address"] == 0
        and f["is_shortener"] == 0
        and f["has_suspicious_tld"] == 0
        and f["num_at_symbols"] == 0
    )

class UrlRiskModel(BaseEstimator, ClassifierMixin):
    """sklearn-compatible wrapper. Input: iterable of URL strings.
    predict_proba(urls)[:, 1] = p_malicious in [0, 1]."""

    def __init__(self, model_dir=None, cap=COMMON_DOMAIN_CAP):
        self.model_dir = model_dir
        self.cap = cap
        self.classes_ = np.array([0, 1])
        self._booster = None

    def _ensure_loaded(self):
        if self._booster is not None:
            return
        import xgboost as xgb
        from feature_extractor import FEATURE_NAMES, extract_features, featurize_dataframe
        self._FEATURE_NAMES = FEATURE_NAMES
        self._extract_features = extract_features
        self._featurize_dataframe = featurize_dataframe
        path = os.path.join(self.model_dir, "url_model.json")
        bst = xgb.Booster()
        bst.load_model(path)
        self._booster = bst

    def _raw_scores(self, urls):
        import xgboost as xgb
        self._ensure_loaded()
        feats = self._featurize_dataframe(list(urls))
        dmat = xgb.DMatrix(feats, feature_names=self._FEATURE_NAMES)
        try:
            return self._booster.predict(dmat, iteration_range=(0, int(self._booster.best_iteration) + 1))
        except Exception:
            return self._booster.predict(dmat)

    def predict_proba(self, urls):
        urls = list(urls)
        raw = self._raw_scores(urls)
        p1 = []
        for u, r in zip(urls, raw):
            p = float(r)
            if _known_good(self._extract_features(u)):
                p = min(p, float(self.cap))
            p = min(1.0, max(0.0, p))
            p1.append(p)
        p1 = np.asarray(p1, dtype=float)
        return np.column_stack([1.0 - p1, p1])

    def predict(self, urls):
        return (self.predict_proba(urls)[:, 1] >= 0.5).astype(int)


def load_url_model(model_dir):
    import joblib, sys
    sys.path.insert(0, model_dir)
    path = os.path.join(model_dir, "url_pipeline.joblib")
    model = joblib.load(path)
    model.model_dir = model_dir
    model._booster = None
    return model
