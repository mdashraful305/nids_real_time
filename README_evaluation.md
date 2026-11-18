# NIDS reviewer-fix package

Two files, built to close the peer-review dossier's points **in code** so the
numbers exist before you touch the manuscript:

1. **`NIDS_Model_Train_FIXED_v4.ipynb`** — your training notebook with 7 analysis
   cells appended (Part 13). The original 44 cells are untouched; the new cells
   read the objects those cells already produce, so only the SMOTE-ablation cell
   retrains anything (one fast XGBoost per dataset).
2. **`evaluate_nids.py`** — one evaluation entry point for offline replay **and**
   both real-time approaches, plus benign-FPR, latency percentiles, and the LLM
   prompt/parse audit. Drop it in the project root (next to `src/`, `config/`,
   `universal_nids_output.pkl`).

> This container had no datasets/GPU/Ollama, so the code is authored and
> syntax/-import-validated but **not executed on your data**. Run order and
> expected outputs are below. The notebook's new cells and the script's `src`
> imports, CLI, prompt constant, and scoring/latency helpers were all verified.

---

## Notebook — Part 13 cells and what each answers

Run Parts 1–4 first (so `results_cicids`, `results_unsw`, `results_nslkdd`,
`universal_out` exist), then run Part 13 top to bottom. Every cell writes a
CSV/JSON into `BASE_DIR`.

| Cell | Output | Dossier point |
|------|--------|---------------|
| 13.1 | `provenance.json` | Hardware/seed/version/Optuna disclosure (latencies had none) |
| 13.2 | `matched_label_evaluation.csv` | Standalone vs ensemble scored in the **same** label space → kills the "97.14% is a label-merge artefact" objection |
| 13.3 | `label_mapping_table.csv` | The native→merged taxonomy the 97.14% depends on |
| 13.4 | `smote_ablation.csv` | SMOTE with/without on identical split |
| 13.5 | `hybrid_shap_*.csv`, `hybrid_shap_overlap.csv` | SHAP for the **deployed hybrid**, not XGBoost alone |
| 13.6 | `cv_summary.csv` | CV mean±std vs held-out test (run Part 3 first) |
| 13.7 | `plain_xgb_baseline_fair.csv` | Plain-XGB baseline on the **identical** split/labels |

---

## evaluate_nids.py — modes

```bash
# 0. One-time: disclose the exact Role 3 prompt + decoding for the appendix
python evaluate_nids.py prompt-dump

# 1. Offline replay (Track B) — ablation, CIs, McNemar, latency, LLM audit
export NIDS_FUSION_MODE=role1_gated
python evaluate_nids.py offline --pkl universal_nids_output.pkl \
    --eve-dir data/eve_friday/ --flow-dir data/flow_friday/ --dataset CICIDS2017

# 2a. Real-time Approach 1 (NFStream inline). Start nids_web.py in another
#     terminal, then score the history it writes:
python evaluate_nids.py realtime --approach 1 --duration 300 \
    --history nids_history.json --attacker-ip 192.168.1.50

# 2b. Real-time Approach 2 (CICFlowMeter rotation). Start the 4 live terminals,
#     then score the unified alerts:
python evaluate_nids.py realtime --approach 2 --duration 300 \
    --alerts data/results/unified_alerts.jsonl

# 3. THE missing measurement: benign-only false-positive rate + alert volume.
#    Run the live pipeline against attack-free traffic, then:
python evaluate_nids.py benign-fpr --duration 3600 \
    --alerts data/results/unified_alerts.jsonl --eve /var/log/suricata/eve.json

# 4. Latency with p50/p95/p99/std and hardware captured
python evaluate_nids.py latency --pkl universal_nids_output.pkl \
    --flows data/cicflow_csv_labelled/CICIDS2017_friday_flows.csv \
    --ollama-url http://localhost:11434 --ollama-model qwen2.5:1.5b

# 5. LLM parse-failure audit (explains a 7B "recall collapse")
python evaluate_nids.py llm-audit --results-dir data/results
```

| Mode | Dossier point it answers |
|------|--------------------------|
| `prompt-dump` | Full prompt/temperature/JSON-schema disclosure (prompt appeared once in 35 pages) |
| `offline` | Keeps Track B but emits the LLM parse audit and a note that role1_gated's McNemar p=1 is an identity |
| `realtime --approach 1/2` | Both live paths scored with **one** metric definition; dashboard "%" labelled as confidence, not detection rate |
| `benign-fpr` | Live Role 1 / Role 3 / Suricata FPR **and** alerts/hour for the alert-fatigue argument |
| `latency` | p50/p95/p99/std + hardware; distinguishes batched vs per-flow |
| `llm-audit` | valid-JSON vs parse-error vs real verdict counts |

---

## Still requires a NEW capture/run (cannot be back-filled from existing data)

- **benign-fpr** needs an attack-free capture (several hours). This is the single
  biggest remaining gap the dossier named.
- **SMOTE ablation / hybrid SHAP / matched-label / fair baseline** run from your
  existing trained objects — no recapture, just run Part 13.
- **7B recall audit**: if you still have the 7B run's `unified_alerts.jsonl`,
  `llm-audit` classifies it now; otherwise re-run offline with `--ollama-model
  qwen2.5:7b`.

## Writing-only points (no code)

Title "Cross-Dataset" → "Multi-Dataset Schema Routing"; reframe the Universal
Ensemble as a schema router; threat-model paragraph for prompt injection;
state the Suricata ruleset; name the 60.5%/60.0% figures as model confidence,
not detection rate; disclose the remote Ollama endpoint if a tunnel was used.
