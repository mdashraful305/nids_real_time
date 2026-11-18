"""
src/engine/weighted_hybrid.py
==============================
WeightedHybridEnsemble — module-level, pickle-safe.

Import this in BOTH Colab (Cell 1 already does via try/import) and
main_unified.py before any joblib save/load so joblib records the
class as:
  src.engine.weighted_hybrid.WeightedHybridEnsemble

instead of __main__.WeightedHybridEnsemble (Colab notebook scope).
"""

import numpy as np


class WeightedHybridEnsemble:
    """
    Soft-voting ensemble combining XGBoost and Random Forest,
    weighted by their macro-F1 scores on the validation set.

    Pickle-safe because this class is defined at module level in a
    proper .py file, not inside a function or a notebook cell.
    """

    def __init__(self, xgb_m, rf_m, wx, wr):
        self.xgb_model = xgb_m
        self.rf_model  = rf_m
        self.w_xgb     = wx
        self.w_rf      = wr
        self.classes_  = xgb_m.classes_

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return (
            self.w_xgb * self.xgb_model.predict_proba(X)
            + self.w_rf  * self.rf_model.predict_proba(X)
        )

    def predict(self, X: np.ndarray) -> np.ndarray:
        return np.argmax(self.predict_proba(X), axis=1)

    @property
    def feature_importances_(self) -> np.ndarray:
        return (
            self.w_xgb * self.xgb_model.feature_importances_
            + self.w_rf  * self.rf_model.feature_importances_
        )