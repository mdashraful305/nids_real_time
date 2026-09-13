# src/engine/universal_ensemble.py
# Defines UniversalEnsemble at module level so joblib.dump() and
# joblib.load() both resolve it as:
#   src.engine.universal_ensemble.UniversalEnsemble
# Import this in BOTH the notebook and main_unified.py before
# saving or loading the pkl.

import numpy as np


class UniversalEnsemble:
    """
    Multi-dataset voting ensemble.
    Each dataset's XGBoost sub-model operates in its own feature space.
    At inference time the ensemble detects which feature set matches the
    input and routes to the correct sub-model, then maps predictions into
    the shared universal label vocabulary.
    """

    def __init__(self, sub_models, sub_features, sub_le,
                 sub_weights, le_universal, label_map):
        self.sub_models   = sub_models
        self.sub_features = sub_features
        self.sub_le       = sub_le
        self.sub_weights  = sub_weights
        self.le_universal = le_universal
        self.label_map    = label_map
        self.classes_     = le_universal.classes_
        self.n_classes_   = len(le_universal.classes_)

    def _get_matching_dataset(self, feature_names: list) -> str:
        feat_set = set(feature_names)
        best_ds, best_overlap = None, -1
        for ds, ds_feats in self.sub_features.items():
            overlap = len(feat_set & set(ds_feats))
            if overlap > best_overlap:
                best_overlap = overlap
                best_ds = ds
        return best_ds

    def predict_proba_from_dataset(self, X: np.ndarray,
                                   dataset_name: str) -> np.ndarray:
        model     = self.sub_models[dataset_name]
        le_sub    = self.sub_le[dataset_name]
        raw_proba = model.predict_proba(X)

        uni_classes_list = list(self.le_universal.classes_)
        universal_proba  = np.zeros(
            (len(X), self.n_classes_), dtype=np.float32
        )
        for sub_idx, sub_class in enumerate(le_sub.classes_):
            uni_class = self.label_map.get(sub_class, sub_class)
            if uni_class in uni_classes_list:
                uni_idx = uni_classes_list.index(uni_class)
                universal_proba[:, uni_idx] += raw_proba[:, sub_idx]
        return universal_proba

    def predict_proba(self, X: np.ndarray,
                      dataset_name: str = None) -> np.ndarray:
        ds = dataset_name or list(self.sub_models.keys())[0]
        return self.predict_proba_from_dataset(X, ds)

    def predict(self, X: np.ndarray,
                dataset_name: str = None) -> np.ndarray:
        return np.argmax(self.predict_proba(X, dataset_name), axis=1)

    def predict_from_features(self, X: np.ndarray,
                              feature_names: list) -> np.ndarray:
        ds       = self._get_matching_dataset(feature_names)
        ds_feats = self.sub_features[ds]
        aligned  = np.zeros((len(X), len(ds_feats)), dtype=np.float32)
        for i, col in enumerate(ds_feats):
            if col in feature_names:
                aligned[:, i] = X[:, feature_names.index(col)]
        return self.predict_proba_from_dataset(aligned, ds)