# Real-Time NIDS Simulation Dataset (`realtime_data/`)

Run ID: `live_20261116_combined`

## Folder Layout
- `pcaps/`
  - `capture_full.pcap` — merged raw capture on live interface (`segments/` combined via `mergecap`)
  - `segments/` — `341` individual 5-second classic PCAP segments
- `csv/`
  - `cicflow_csv/` — `63` CICFlowMeter 82-column flow CSVs extracted for Approach B
  - `approach_a_flows.csv` — `92237` complete per-flow records (metadata, verdicts, top SHAP, all 52 features)
  - `approach_a_r3.csv` — `624` Role-3 LLM evaluation rows (verdict, raw verdict, latency, queue wait, error status)
  - `approach_b_alerts.csv` — `32` Approach-B 20-second window decision-engine rows
- `json/`
  - `run_meta.json`, `flows.jsonl`, `r3.jsonl`, `phases.jsonl` — complete append-only Approach-A run logs
  - `nids_history.json` — Approach-A dashboard snapshot
  - `unified_alerts.jsonl` — Approach-B window-level decision-engine output
  - `role1_proba_debug.jsonl` — per-flow full class probability distribution & SHAP benign-push diagnostics
  - `suricata/` — Suricata 7.0.3 `eve.json`, `fast.log`, `stats.log`, `suricata.log`
- `chunks/` — `32` Approach-B plain-text window chunks fed to Role 3
- `reports/` — **`FINAL_REALTIME_REPORT.md`** (consolidated journal-ready summary covering architecture, fixes, all 4 attack classes, and A-vs-B tradeoffs), `EXPERIMENT_REPORT.md`, `experiment_report.json`, `LIVE_FULL_REPORT.md`, `LIVE_TEST_SUMMARY.md`, `settings_live.yaml`, and `eval/` (`evaluate_nids.py` reports)
- `logs/` — runtime service logs (`nids_web_5000.log`, `main_unified_live.log`, `live_b_worker.log`, `suricata_stdout.log`, `app_5001.log`, `ready.json`, `drain_complete.json`)
