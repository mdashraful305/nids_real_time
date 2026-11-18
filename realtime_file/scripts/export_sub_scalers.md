# Re-exporting the universal model with per-dataset scalers

**Why this is required before any 3-dataset result is reportable.**

Each sub-model was trained on features scaled by *its own* `RobustScaler`,
fitted on that dataset's training split. `train_universal_model()` in the
notebook saved only one:

```python
"scaler": pipeline_outputs[list(pipeline_outputs.keys())[0]]["data"]["scaler"],
```

That is whichever dataset happened to be inserted first — CICIDS2017 in
practice. The pipeline then applied it inside a bare `try/except: pass`, so
routing to UNSW-NB15 or NSL-KDD raised a shape mismatch, the exception was
swallowed, and **raw unscaled values were fed to a model trained on scaled
input** — which still returns a confident probability.

So the current `universal_nids_output.pkl` can only produce trustworthy
predictions for CICIDS2017. Fixing this is what makes UNSW-NB15 and NSL-KDD
usable at all.

---

## Change in the notebook

In `train_universal_model()`, inside the per-dataset collection loop
(where `sub_models[ds_name] = best_model` is set), also capture the scaler:

```python
sub_models[ds_name]   = best_model
sub_features[ds_name] = feat_names
sub_le[ds_name]       = le
sub_weights[ds_name]  = val_f1
sub_scalers[ds_name]  = data["scaler"]      # ← ADD (init sub_scalers = {} above)
```

Pass them to the constructor:

```python
ensemble = UniversalEnsemble(
    sub_models, sub_features, sub_le,
    sub_weights, le_universal, UNIVERSAL_LABEL_MAP,
    sub_scalers=sub_scalers,                 # ← ADD
)
```

And add them to `save_dict` so they survive independently of the pickled
object (older pickles have no `sub_scalers` attribute, and the pipeline reads
this top-level key as a fallback):

```python
save_dict = {
    "ensemble":     ensemble,
    ...
    "sub_scalers":  sub_scalers,             # ← ADD
    "scaler":       pipeline_outputs[...]["data"]["scaler"],   # keep for
                                                               # backward compat
}
```

---

## Re-export without retraining

The sub-models do not change — only the metadata. If the three per-dataset
pkls are still on Drive, rebuild the universal pkl in a couple of minutes:

```python
import joblib, sys
sys.path.insert(0, '/content/drive/MyDrive/NIDS_Output/nids_role3')
from src.engine.universal_ensemble import UniversalEnsemble

outs = {
    "CICIDS2017": joblib.load("nids_cicids_output.pkl"),
    "UNSW-NB15":  joblib.load("nids_unsw_output.pkl"),
    "NSL-KDD":    joblib.load("nids_nslkdd_output.pkl"),
}

uni = joblib.load("universal_nids_output.pkl")
uni["sub_scalers"] = {ds: o["data"]["scaler"] for ds, o in outs.items()}
uni["ensemble"].sub_scalers = uni["sub_scalers"]

joblib.dump(uni, "universal_nids_output.pkl", compress=3)
print(uni["ensemble"].describe())
```

`describe()` must show `scaler=yes` for all three. If it shows `MISSING`, the
pipeline will refuse to score that dataset rather than silently feed it
unscaled input.

---

## Verify before running experiments

```python
import joblib, sys
sys.path.insert(0, '.')
from src.engine.universal_ensemble import UniversalEnsemble

o = joblib.load("universal_nids_output.pkl")
ens = o["ensemble"]
print(ens.describe())

for ds in ens.datasets:
    n = getattr(ens.sub_scalers[ds], "n_features_in_", None)
    assert n == len(ens.sub_features[ds]), (
        f"{ds}: scaler expects {n} features, sub_features lists "
        f"{len(ens.sub_features[ds])}"
    )
print("OK — every sub-model has a width-matched scaler")
```

A width mismatch here means the scaler and the feature list came from
different runs; re-export both together rather than patching one.
