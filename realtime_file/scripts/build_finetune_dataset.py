"""
scripts/build_finetune_dataset.py
===================================
Builds a fine-tuning JSONL dataset automatically from artifacts your
pipeline already produces — no manual labeling required.

Sources used:
  data/chunks/*.txt                 — the exact prompt text sent to the LLM
                                       for every window (already saved by
                                       LogChunker when save_to_disk=True)
  data/results/thesis_per_window_*.csv — ground truth per window
                                       (gt_binary, gt_family) from ThesisEvaluator

For every window that HAS ground truth, this script:
  1. Loads the matching chunk_*.txt (the input side of the training pair)
  2. Builds the CORRECT JSON verdict from gt_binary/gt_family (the output
     side) — NOT from what the LLM guessed, since the whole point is to
     teach the model the right answer where it was previously wrong
  3. Writes one JSONL line: {"prompt": ..., "completion": ...}
  4. Splits into train/val, stratified by gt_family so rare classes
     (Bot, Web Attack) appear in both splits

Usage
-----
python scripts/build_finetune_dataset.py \
    --chunks_dir data/chunks/ \
    --csv data/results/thesis_per_window_20260715_053912.csv \
    --out_dir data/finetune/ \
    --val_split 0.2
"""

import argparse
import json
import os
import re
import random
from collections import defaultdict

import pandas as pd


# Must match UNIVERSAL_LABEL_MAP families used elsewhere in the project.
# Maps a gt_family string to the correct attack_type the LLM should output.
FAMILY_TO_ATTACK_TYPE = {
    "Benign":       "Normal",
    "DoS":          "DoS",
    "DDoS":         "DDoS",
    "PortScan":     "PortScan",
    "Brute Force":  "Brute Force",
    "Web Attack":   "Web Attack",
    "Bot":          "Bot",
    "Infiltration": "Infiltration",
    "Heartbleed":   "Heartbleed",
    "Unknown":      "Unknown",
}


def build_correct_completion(gt_binary: str, gt_family: str) -> dict:
    """
    Construct the CORRECT structured JSON output for a window, derived
    from ground truth — this is the training TARGET, teaching the model
    what it should have said instead of what it may have guessed.
    """
    is_attack = gt_binary == "attack"
    attack_type = FAMILY_TO_ATTACK_TYPE.get(gt_family, "Unknown")

    return {
        "verdict": "attack" if is_attack else "benign",
        "attack_type": attack_type if is_attack else "Normal",
        "confidence": 95,  # ground-truth-derived, so high confidence is correct
        "key_indicators": (
            [f"ground-truth family: {gt_family}"] if is_attack else []
        ),
        "explanation": (
            f"This window contains {gt_family} traffic based on labelled "
            f"flow ground truth."
            if is_attack else
            "No malicious activity present in this window's ground truth."
        ),
        "recommended_action": (
            "Investigate source IPs and correlate with SHAP feature attribution."
            if is_attack else "None."
        ),
    }


def find_chunk_file(chunks_dir: str, window_start: str) -> str:
    """
    Match a CSV row's window_start timestamp to its corresponding
    chunk_<idx>_<HHMMSS>.txt file. LogChunker names files using the
    window start time formatted as %H%M%S.
    """
    # window_start in the CSV looks like "2017-07-07 11:59:39+00:00"
    try:
        time_part = window_start.split(" ")[1].split("+")[0].split(".")[0]
        hhmmss = time_part.replace(":", "")
    except Exception:
        return None

    # chunk files are named chunk_NNNN_HHMMSS.txt — search by the HHMMSS suffix
    for fname in os.listdir(chunks_dir):
        if fname.endswith(f"_{hhmmss}.txt"):
            return os.path.join(chunks_dir, fname)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chunks_dir", required=True,
                     help="Directory containing chunk_*.txt files")
    ap.add_argument("--csv", required=True, nargs="+",
                     help="One or more thesis_per_window_*.csv files "
                          "(pass multiple to combine several days)")
    ap.add_argument("--out_dir", default="data/finetune/")
    ap.add_argument("--val_split", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # ── Step 1: load and combine all ground-truth CSVs ────────────────────────
    dfs = [pd.read_csv(p) for p in args.csv]
    df = pd.concat(dfs, ignore_index=True)
    print(f"Loaded {len(df)} ground-truth windows from {len(args.csv)} file(s)")

    # ── Step 2: build (prompt, completion) pairs ───────────────────────────────
    examples = []
    missing_chunks = 0

    for _, row in df.iterrows():
        chunk_path = find_chunk_file(args.chunks_dir, str(row["window_start"]))
        if chunk_path is None or not os.path.exists(chunk_path):
            missing_chunks += 1
            continue

        with open(chunk_path, "r", encoding="utf-8") as f:
            prompt_text = f.read()

        completion = build_correct_completion(row["gt_binary"], row["gt_family"])

        examples.append({
            "prompt": prompt_text,
            "completion": json.dumps(completion, ensure_ascii=False),
            "gt_family": row["gt_family"],   # kept for stratified split, dropped before saving
        })

    print(f"Built {len(examples)} training examples "
          f"({missing_chunks} windows skipped — no matching chunk file found)")

    if not examples:
        print("No examples built — check that chunks_dir matches the run "
              "that produced the CSV(s), and that save_to_disk was enabled.")
        return

    # ── Step 3: stratified train/val split by gt_family ───────────────────────
    random.seed(args.seed)
    by_family = defaultdict(list)
    for ex in examples:
        by_family[ex["gt_family"]].append(ex)

    train, val = [], []
    for family, items in by_family.items():
        random.shuffle(items)
        n_val = max(1, int(len(items) * args.val_split)) if len(items) > 1 else 0
        val.extend(items[:n_val])
        train.extend(items[n_val:])

    random.shuffle(train)
    random.shuffle(val)

    # ── Step 4: write JSONL (drop the helper gt_family field before saving) ───
    def write_jsonl(path, rows):
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps({
                    "prompt": r["prompt"],
                    "completion": r["completion"],
                }, ensure_ascii=False) + "\n")

    train_path = os.path.join(args.out_dir, "train.jsonl")
    val_path   = os.path.join(args.out_dir, "val.jsonl")
    write_jsonl(train_path, train)
    write_jsonl(val_path, val)

    # ── Step 5: report class balance ───────────────────────────────────────────
    print(f"\nTrain: {len(train)} examples  ->  {train_path}")
    print(f"Val:   {len(val)} examples  ->  {val_path}")
    print("\nClass distribution:")
    for family, items in sorted(by_family.items(), key=lambda x: -len(x[1])):
        print(f"  {family:<15} {len(items):>5} total")


if __name__ == "__main__":
    main()