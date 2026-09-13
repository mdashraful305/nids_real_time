"""
src/engine/universal_ensemble.py
=================================
UniversalEnsemble — module-level, pickle-safe.

MUST be imported in both Colab and main_unified.py BEFORE any joblib
save or load, so Python records and resolves the class as:
  src.engine.universal_ensemble.UniversalEnsemble

COLAB: before train_universal_model() + save_universal_output()
  import sys
  sys.path.insert(0, '/content/drive/MyDrive/nids_role3_clean')
  from src.engine.universal_ensemble import UniversalEnsemble

LOCAL: already done at top of main_unified.py


WHAT THIS CLASS ACTUALLY IS
───────────────────────────
A **schema-routed multi-dataset classifier**, not a voting ensemble.

CICIDS2017, UNSW-NB15 and NSL-KDD share zero feature columns after
mutual-information selection ("Flow Duration" vs "dur" vs "duration"), so a
sample can only ever be scored by the one sub-model whose schema it matches.
There is nothing to vote between.

The previous docstring claimed "votes are combined with macro-F1 weights from
each sub-model's validation set performance". That was never true in code:
`sub_weights` was computed, normalised, saved and then never read by any
prediction path, and `predict_proba()` silently defaulted to
`list(sub_models.keys())[0]`. The claim is removed rather than the weights —
they remain useful for reporting per-dataset reliability, and
`predict_proba_weighted()` below is the one place a genuine weighted
combination applies (a sample carrying features from more than one schema,
which does not arise in the current datasets but is well-defined if it ever
does).

Describe this in the thesis as a router. It is a legitimate contribution —
one deployable artefact covering three heterogeneous schemas — and it does
not need to be called an ensemble to be one.


PER-DATASET SCALERS
───────────────────
Each sub-model was trained on data scaled by ITS OWN RobustScaler, fitted on
that dataset's training split. Applying one dataset's scaler to another's
feature vector is meaningless: different widths, different units, different
distributions.

The training notebook nonetheless saved a single scaler:

    "scaler": pipeline_outputs[list(pipeline_outputs.keys())[0]]["data"]["scaler"]

...i.e. whichever dataset happened to be inserted first. The pipeline then
applied it inside a bare `try/except: pass`, so routing to UNSW-NB15 or
NSL-KDD raised a shape mismatch that was swallowed, and RAW UNSCALED values
were fed to a model trained on scaled input. Silently, with a confident
probability out the other end.

`sub_scalers` fixes this. Old pickles do not carry it, so every access is
guarded with getattr() — and `transform()` REFUSES to guess when the correct
scaler for a route is unavailable.
"""

import numpy as np


class UniversalEnsemble:
    """Schema-routed multi-dataset classifier — one XGBoost sub-model per dataset."""

    # Minimum fraction of a dataset's features that must be present before
    # routing to it. Raw overlap counts with no normalisation let a dataset
    # with many features win purely by being large.
    MIN_ROUTE_COVERAGE = 0.60

    def __init__(self, sub_models, sub_features, sub_le,
                 sub_weights, le_universal, label_map, sub_scalers=None):
        self.sub_models   = sub_models
        self.sub_features = sub_features
        self.sub_le       = sub_le
        self.sub_weights  = sub_weights
        self.le_universal = le_universal
        self.label_map    = label_map
        # dataset -> fitted scaler. None only when loading a legacy pkl.
        self.sub_scalers  = sub_scalers or {}
        self.classes_     = le_universal.classes_
        self.n_classes_   = len(le_universal.classes_)

    # ── introspection ────────────────────────────────────────────────────────

    @property
    def datasets(self) -> list:
        return list(self.sub_models.keys())

    def has_scaler(self, dataset_name: str) -> bool:
        return bool(getattr(self, "sub_scalers", None)) and \
            self.sub_scalers.get(dataset_name) is not None

    def describe(self) -> str:
        lines = ["UniversalEnsemble (schema-routed, one sub-model per dataset)"]
        weights = getattr(self, "sub_weights", {}) or {}
        for ds in self.datasets:
            lines.append(
                f"  {ds:<12} features={len(self.sub_features[ds]):<4} "
                f"classes={len(self.sub_le[ds].classes_):<3} "
                f"val-F1-weight={weights.get(ds, float('nan')):.3f} "
                f"scaler={'yes' if self.has_scaler(ds) else 'MISSING'}"
            )
        return "\n".join(lines)

    # ── routing ──────────────────────────────────────────────────────────────

    def _get_matching_dataset(self, feature_names: list) -> str:
        """
        Route by BEST COVERAGE, not raw overlap count.

        The previous implementation compared `len(feat_set & set(ds_feats))`
        across datasets with no normalisation and no tie-break, starting from
        best_overlap = -1. Two consequences:
          • a dataset with 60 features beat one with 20 simply by being
            larger, even at lower proportional match;
          • when nothing overlapped — the normal case with mismatched column
            naming — every candidate scored 0, so the winner was whichever key
            dict iteration yielded first, which varies between pkl builds.

        Coverage is fraction-of-the-dataset's-features-present, so the scores
        are comparable, and ties break on dataset name for determinism.

        Returns None when no dataset reaches MIN_ROUTE_COVERAGE — the caller
        must treat that as "cannot classify", not as a reason to pick one.
        """
        from src.ingestion.cicflow_reader import build_feature_lookup, resolve_feature

        lookup = build_feature_lookup(feature_names)
        scored = []
        for ds in sorted(self.sub_features):          # sorted -> deterministic
            ds_feats = self.sub_features[ds]
            if not len(ds_feats):
                continue
            n_present = sum(
                1 for f in ds_feats if resolve_feature(f, lookup) is not None
            )
            scored.append((n_present / len(ds_feats), ds, n_present))

        if not scored:
            return None
        scored.sort(key=lambda t: (-t[0], t[1]))
        best_cov, best_ds, _ = scored[0]
        return best_ds if best_cov >= self.MIN_ROUTE_COVERAGE else None

    def route_report(self, feature_names: list) -> dict:
        """Coverage per dataset — for logging why a route was or was not taken."""
        from src.ingestion.cicflow_reader import build_feature_lookup, resolve_feature

        lookup = build_feature_lookup(feature_names)
        out = {}
        for ds, ds_feats in self.sub_features.items():
            if not len(ds_feats):
                out[ds] = 0.0
                continue
            n = sum(1 for f in ds_feats if resolve_feature(f, lookup) is not None)
            out[ds] = round(n / len(ds_feats), 4)
        return out

    # ── scaling ──────────────────────────────────────────────────────────────

    def transform(self, X: np.ndarray, dataset_name: str,
                  allow_unscaled: bool = False) -> np.ndarray:
        """
        Apply the scaler belonging to `dataset_name`.

        Raises if that scaler is unavailable. The alternative — quietly
        returning X unscaled — is what made the earlier failure invisible: a
        model trained on RobustScaler output was handed raw byte counts and
        still produced a confident label.

        allow_unscaled=True is an explicit, logged opt-out for legacy pkls.
        """
        scalers = getattr(self, "sub_scalers", None) or {}
        scaler = scalers.get(dataset_name)

        if scaler is None:
            if allow_unscaled:
                return X
            raise KeyError(
                f"No scaler stored for sub-model '{dataset_name}'.\n"
                "Each sub-model was trained on data scaled by its OWN "
                "RobustScaler; using another dataset's scaler (or none) feeds "
                "the model a distribution it never saw and yields a confident "
                "but meaningless prediction.\n"
                "This pkl predates per-dataset scalers. Re-export it from the "
                "training notebook with:\n"
                "    'sub_scalers': {ds: out['data']['scaler'] "
                "for ds, out in pipeline_outputs.items()}\n"
                "or pass allow_unscaled=True to proceed deliberately (results "
                "for this dataset are then not trustworthy)."
            )

        expected = getattr(scaler, "n_features_in_", None)
        if expected is not None and X.shape[1] != expected:
            raise ValueError(
                f"Scaler for '{dataset_name}' expects {expected} features but "
                f"got {X.shape[1]}. This is the shape mismatch that a bare "
                "`except: pass` used to swallow — refusing to continue with "
                "unscaled data."
            )
        return scaler.transform(X)

    # ── prediction ───────────────────────────────────────────────────────────

    def predict_proba_from_dataset(self, X: np.ndarray,
                                   dataset_name: str) -> np.ndarray:
        """Map one sub-model's class probabilities into universal label space."""
        model     = self.sub_models[dataset_name]
        le_sub    = self.sub_le[dataset_name]
        raw_proba = model.predict_proba(X)
        uni_list  = list(self.le_universal.classes_)
        out = np.zeros((len(X), self.n_classes_), dtype=np.float32)
        for i, cls in enumerate(le_sub.classes_):
            uni = self.label_map.get(cls, cls)
            if uni in uni_list:
                out[:, uni_list.index(uni)] += raw_proba[:, i]
        return out

    def predict_proba(self, X: np.ndarray,
                      dataset_name: str = None) -> np.ndarray:
        """
        Score X with the named sub-model.

        `dataset_name` is now REQUIRED. It previously defaulted to
        `list(self.sub_models.keys())[0]` — an arbitrary dict-order choice
        that silently scored, say, UNSW-NB15 vectors with the CICIDS2017
        model. If you do not know the schema, call predict_from_features()
        and let routing decide, or check route_report() first.
        """
        if dataset_name is None:
            raise ValueError(
                "dataset_name is required. Defaulting to the first sub-model "
                "silently mis-routed samples whose schema did not match it; "
                "use predict_from_features() to route by schema instead."
            )
        return self.predict_proba_from_dataset(X, dataset_name)

    def predict(self, X: np.ndarray,
                dataset_name: str = None) -> np.ndarray:
        return np.argmax(self.predict_proba(X, dataset_name), axis=1)

    def predict_from_features(self, X: np.ndarray,
                              feature_names: list,
                              scale: bool = True,
                              allow_unscaled: bool = False) -> np.ndarray:
        """
        Route by schema, align columns, scale with that dataset's scaler, and
        return universal-space probabilities.

        Raises if no dataset matches well enough — a routed prediction from a
        schema no sub-model recognises is noise wearing a confidence score.
        """
        from src.ingestion.cicflow_reader import build_feature_lookup, resolve_feature

        ds = self._get_matching_dataset(feature_names)
        if ds is None:
            raise ValueError(
                "No sub-model matches this feature schema at >= "
                f"{self.MIN_ROUTE_COVERAGE:.0%} coverage.\n"
                f"Per-dataset coverage: {self.route_report(feature_names)}\n"
                "Check that column names were normalised "
                "(src/ingestion/cicflow_reader.COLUMN_ALIASES) before routing."
            )

        ds_feats = self.sub_features[ds]
        lookup   = build_feature_lookup(feature_names)
        names    = list(feature_names)
        aligned  = np.zeros((len(X), len(ds_feats)), dtype=np.float32)
        for i, feat in enumerate(ds_feats):
            col = resolve_feature(feat, lookup)
            if col is not None and col in names:
                aligned[:, i] = X[:, names.index(col)]

        if scale:
            aligned = self.transform(aligned, ds, allow_unscaled=allow_unscaled)
        return self.predict_proba_from_dataset(aligned, ds)

    def predict_proba_weighted(self, X_by_dataset: dict) -> np.ndarray:
        """
        Genuine macro-F1-weighted combination across sub-models.

        Only meaningful when a sample carries features for MORE THAN ONE
        schema, which the three current datasets never do — their selected
        feature sets are disjoint. Provided so `sub_weights` has one honest
        consumer, and so a future dataset pair with overlapping schemas can
        be combined without inventing new machinery.

        X_by_dataset : {dataset_name: aligned+scaled array}, all same n_rows.
        """
        if not X_by_dataset:
            raise ValueError("X_by_dataset is empty")

        weights = getattr(self, "sub_weights", {}) or {}
        n_rows = len(next(iter(X_by_dataset.values())))
        acc = np.zeros((n_rows, self.n_classes_), dtype=np.float32)
        total_w = 0.0
        for ds, X in X_by_dataset.items():
            w = float(weights.get(ds, 1.0))
            acc += w * self.predict_proba_from_dataset(X, ds)
            total_w += w
        return acc / total_w if total_w else acc
