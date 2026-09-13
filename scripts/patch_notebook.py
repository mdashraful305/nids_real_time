#!/usr/bin/env python3
"""
scripts/patch_notebook.py
==========================
Applies the Phase 1-5 fixes to NIDS_Model_Train.ipynb and writes a new
notebook ready to run in Colab.

Editing Cell 1 by hand is not realistic — it is a single 78 KB cell — and a
mistyped edit inside it fails in ways that look like a data problem. This
script makes the five surgical changes, verifies each one landed, and refuses
to write anything if a single anchor is missing.

WHAT IT CHANGES
───────────────
1. UNIVERSAL_LABEL_MAP -> imported from src.engine.label_map, so training and
   evaluation share ONE taxonomy. The two copies had already drifted: the
   evaluator's held CICIDS2017 labels only, so no UNSW-NB15 or NSL-KDD attack
   family could ever be scored.

2. sub_scalers collected per dataset in train_universal_model(). Each
   sub-model was trained on its OWN RobustScaler; the notebook saved only the
   first dataset's, and the pipeline applied it under `except: pass` — so
   routing to UNSW-NB15 or NSL-KDD fed raw unscaled values to a model trained
   on scaled input, silently.

3. sub_scalers passed to the UniversalEnsemble constructor.

4. "sub_scalers" added to the saved dict, so it survives independently of the
   pickled object.

5. psutil added to the install list (cross-platform peak-RSS measurement; the
   evaluator otherwise reports 0 MB).

USAGE
─────
    python scripts/patch_notebook.py \
        --in  ../NIDS_Model_Train.ipynb \
        --out ../NIDS_Model_Train_PATCHED.ipynb
"""

import os
import sys
import json
import argparse


# (description, anchor, replacement, must_occur)
PATCHES = [
    (
        "1. Import shared taxonomy instead of the inline copy",
        "UNIVERSAL_LABEL_MAP = {",
        None,     # handled specially — the dict body is replaced wholesale
        1,
    ),
    (
        "2. Collect a scaler per dataset",
        """    sub_models          = {}
    sub_features        = {}
    sub_le              = {}
    sub_weights         = {}
    all_universal_labels = set()""",
        """    sub_models          = {}
    sub_features        = {}
    sub_le              = {}
    sub_weights         = {}
    sub_scalers         = {}      # PATCH: one scaler per dataset
    all_universal_labels = set()""",
        1,
    ),
    (
        "3. Store each dataset's own scaler",
        """        sub_models[ds_name]   = best_model
        sub_features[ds_name] = feat_names
        sub_le[ds_name]       = le
        sub_weights[ds_name]  = val_f1""",
        """        sub_models[ds_name]   = best_model
        sub_features[ds_name] = feat_names
        sub_le[ds_name]       = le
        sub_weights[ds_name]  = val_f1
        # PATCH: each sub-model was fitted on data scaled by THIS dataset's
        # RobustScaler. Saving only the first dataset's scaler meant routing
        # to any other one silently fed the model unscaled input.
        sub_scalers[ds_name]  = data["scaler"]""",
        1,
    ),
    (
        "4. Pass sub_scalers to the ensemble",
        """    ensemble = UniversalEnsemble(
        sub_models, sub_features, sub_le,
        sub_weights, le_universal, UNIVERSAL_LABEL_MAP,
    )""",
        """    ensemble = UniversalEnsemble(
        sub_models, sub_features, sub_le,
        sub_weights, le_universal, UNIVERSAL_LABEL_MAP,
        sub_scalers=sub_scalers,      # PATCH
    )""",
        1,
    ),
    (
        "5. Save sub_scalers alongside the ensemble",
        """        "feature_names":     sub_features.get(
                                 "CICIDS2017",
                                 list(sub_features.values())[0]
                             ),""",
        """        "feature_names":     sub_features.get(
                                 "CICIDS2017",
                                 list(sub_features.values())[0]
                             ),
        # PATCH: per-dataset scalers, stored at the top level too so they
        # survive even when an older pickled ensemble object lacks the
        # attribute. main_unified.py reads this key as a fallback.
        "sub_scalers":       sub_scalers,""",
        1,
    ),
    (
        "6. Install psutil for cross-platform memory measurement",
        """        "joblib>=1.3.0", "requests>=2.31.0", "tqdm>=4.66.0",
    ]""",
        """        "joblib>=1.3.0", "requests>=2.31.0", "tqdm>=4.66.0",
        "psutil>=5.9.0",   # PATCH: peak-RSS measurement in ThesisEvaluator
    ]""",
        1,
    ),
]


LABEL_MAP_REPLACEMENT = '''# ── PATCH: single source of truth for the attack taxonomy ────────────────────
# UNIVERSAL_LABEL_MAP used to be defined inline here AND again in
# src/evaluator/thesis_evaluator.py as LABEL_TO_FAMILY, with a comment saying
# the two "must stay in sync" and nothing enforcing it. They had drifted: the
# evaluator's copy listed CICIDS2017 labels only, so per-family accuracy for
# UNSW-NB15 (Fuzzers/Analysis/Backdoor/...) and NSL-KDD (neptune/smurf/satan/...)
# could never be computed. Both now import the same dict.
try:
    from src.engine.label_map import UNIVERSAL_LABEL_MAP
    print(f"OK  UNIVERSAL_LABEL_MAP imported from src.engine.label_map "
          f"({len(UNIVERSAL_LABEL_MAP)} labels, "
          f"{len(set(UNIVERSAL_LABEL_MAP.values()))} families)")
except ImportError as _exc:
    raise ImportError(
        "Could not import src.engine.label_map — NIDS_PROJECT_PATH is wrong.\\n"
        "Set it to the folder containing src/, e.g.\\n"
        "  NIDS_PROJECT_PATH = '/content/drive/MyDrive/NIDS_Output/nids_role3'\\n"
        "then re-run this cell. Training and evaluation MUST share one "
        "taxonomy; falling back to an inline copy is what let them drift.\\n"
        f"Original error: {_exc}"
    )

'''


# Patches applied to the OTHER cells (not the big Cell 1).
# (description, anchor, replacement)
OTHER_CELL_PATCHES = [
    (
        "7. Fix the wrong project path in the UniversalEnsemble import cell",
        "sys.path.insert(0, '/content/drive/MyDrive/nids_role3')",
        "sys.path.insert(0, '/content/drive/MyDrive/NIDS_Output/nids_role3')",
    ),
    (
        "8. Point the offline run at LABELLED flows and pin the sub-model",
        """  --eve_dir  /content/drive/MyDrive/NIDS_Output/nids_role3/data/eve_logs/ \\
  --flow_dir /content/drive/MyDrive/NIDS_Output/nids_role3/data/cicflow_csv/ \\
  --workers 4""",
        """  --eve_dir  /content/drive/MyDrive/NIDS_Output/nids_role3/data/eve_logs/ \\
  --flow_dir /content/drive/MyDrive/NIDS_Output/nids_role3/data/cicflow_csv_labelled/ \\
  --dataset  CICIDS2017 \\
  --workers 4

# NOTE: --flow_dir now points at cicflow_csv_LABELLED. Raw CICFlowMeter output
# carries no Label column, and the pipeline will refuse to run against it
# rather than invent ground truth. Create the labelled copy first:
#   !python scripts/label_flows.py \\
#       --flow_csv   data/cicflow_csv/Friday-WorkingHours_flows.csv \\
#       --cic_labels data/cic_labels/friday/ \\
#       --out        data/cicflow_csv_labelled/Friday-WorkingHours_flows.csv
#
# --dataset pins Role 1 to a named sub-model. Evaluation runs should always
# pin it: the route is a property of the capture, and recording it explicitly
# is what makes the number reproducible.""",
    ),
]


def parse_args():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_in = os.path.join(os.path.dirname(here), "NIDS_Model_Train.ipynb")
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="src", default=default_in)
    p.add_argument("--out", dest="dst", default=None)
    return p.parse_args()


def replace_label_map(src: str) -> tuple:
    """Replace the whole inline UNIVERSAL_LABEL_MAP dict with the import."""
    start = src.find("UNIVERSAL_LABEL_MAP = {")
    if start == -1:
        return src, False

    # find the closing brace of the dict at column 0
    end = src.find("\n}\n", start)
    if end == -1:
        return src, False
    end += len("\n}\n")

    return src[:start] + LABEL_MAP_REPLACEMENT + src[end:], True


def main():
    args = parse_args()
    src_path = args.src
    dst_path = args.dst or src_path.replace(".ipynb", "_PATCHED.ipynb")

    if not os.path.exists(src_path):
        print(f"ERROR: notebook not found: {src_path}")
        return 1

    print("=" * 72)
    print("  PATCHING NOTEBOOK FOR COLAB")
    print("=" * 72)
    print(f"  in  : {src_path}")
    print(f"  out : {dst_path}\n")

    with open(src_path, encoding="utf-8") as fh:
        nb = json.load(fh)

    # everything lives in the big code cell
    target_idx = None
    for i, cell in enumerate(nb["cells"]):
        if cell["cell_type"] != "code":
            continue
        body = "".join(cell["source"])
        if "def train_universal_model" in body:
            target_idx = i
            break

    if target_idx is None:
        print("ERROR: could not find the cell defining train_universal_model().")
        return 1

    print(f"  Target cell: #{target_idx}\n")
    body = "".join(nb["cells"][target_idx]["source"])
    original_len = len(body)

    ok = True

    # patch 1 — label map
    desc = PATCHES[0][0]
    if "from src.engine.label_map import UNIVERSAL_LABEL_MAP" in body:
        print(f"  SKIP  {desc}  (already applied)")
    else:
        body, done = replace_label_map(body)
        print(f"  {'OK  ' if done else 'FAIL'}  {desc}")
        ok &= done

    # patches 2..6 — plain text substitutions
    for desc, anchor, repl, must in PATCHES[1:]:
        if repl is None:
            continue
        if repl in body:
            print(f"  SKIP  {desc}  (already applied)")
            continue
        n = body.count(anchor)
        if n != must:
            print(f"  FAIL  {desc}  (anchor found {n}x, expected {must})")
            ok = False
            continue
        body = body.replace(anchor, repl, 1)
        print(f"  OK    {desc}")

    if not ok:
        print("\n  One or more patches did not apply. Nothing written.")
        print("  The notebook may already differ from the expected version —")
        print("  apply the changes by hand using COLAB_SETUP.md instead.")
        return 1

    # ── verify the result ────────────────────────────────────────────────────
    print("\n  Verifying ...")
    checks = [
        ("label map imported",
         "from src.engine.label_map import UNIVERSAL_LABEL_MAP" in body),
        ("no inline label map left",
         "UNIVERSAL_LABEL_MAP = {" not in body),
        ("sub_scalers initialised", "sub_scalers         = {}" in body),
        ("sub_scalers populated", 'sub_scalers[ds_name]  = data["scaler"]' in body),
        ("sub_scalers passed to ensemble", "sub_scalers=sub_scalers" in body),
        ("sub_scalers saved", '"sub_scalers":       sub_scalers,' in body),
        ("psutil installed", "psutil>=5.9.0" in body),
    ]
    for name, cond in checks:
        print(f"    {'OK  ' if cond else 'FAIL'}  {name}")
        ok &= cond

    if not ok:
        print("\n  Verification failed. Nothing written.")
        return 1

    # write back, preserving the line-per-element source format
    lines = body.splitlines(keepends=True)
    nb["cells"][target_idx]["source"] = lines

    # ── patches to the smaller cells ─────────────────────────────────────────
    print("\n  Patching the other cells ...")
    for desc, anchor, repl in OTHER_CELL_PATCHES:
        hits = 0
        for cell in nb["cells"]:
            if cell["cell_type"] != "code":
                continue
            cell_body = "".join(cell["source"])
            if repl in cell_body:
                hits = -1
                break
            if anchor in cell_body:
                cell["source"] = cell_body.replace(
                    anchor, repl, 1
                ).splitlines(keepends=True)
                hits += 1
        if hits == -1:
            print(f"    SKIP  {desc}  (already applied)")
        elif hits == 0:
            print(f"    WARN  {desc}  (anchor not found — check by hand)")
        else:
            print(f"    OK    {desc}")

    with open(dst_path, "w", encoding="utf-8") as fh:
        json.dump(nb, fh, indent=1, ensure_ascii=False)

    print(f"\n  Cell size: {original_len:,} -> {len(body):,} chars")
    print(f"  Written  : {dst_path}")
    print("\n  NEXT: upload this notebook to Colab and follow COLAB_SETUP.md")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
