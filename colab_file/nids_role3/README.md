# NIDS — Unified Pipeline (Role 1 + Role 2 + Role 3)

Three roles working together as one system.

```
Raw traffic
    │
    ├── Role 1: XGBoost/RF  → per-flow verdict (fast, accurate)
    ├── Role 2: SHAP+Ollama → plain-English explanation of Role 1
    └── Role 3: LLM analyst → 30-second log window analysis
                                (catches multi-step attacks)
                  │
          Decision engine
          (conflict resolution)
                  │
          UnifiedAlert
         (severity + explanation + action)
                  │
         ┌────────┴────────┐
     Console SOC       EveBox + HTML report
```

---

## Folder structure

```
nids_role3/
├── config/
│   └── settings.yaml
├── data/
│   ├── raw_pcap/
│   ├── cicflow_csv/
│   ├── eve_logs/
│   ├── chunks/
│   └── results/
│       ├── unified_alerts.jsonl
│       └── report_<ts>.html
├── src/
│   ├── ingestion/
│   │   ├── suricata_reader.py
│   │   └── cicflow_reader.py
│   ├── chunker/
│   │   └── log_chunker.py
│   ├── llm/
│   │   └── ollama_analyst.py
│   ├── evaluator/
│   │   └── evaluator.py
│   ├── engine/
│   │   └── decision_engine.py
│   ├── pipeline/
│   │   └── unified_pipeline.py
│   ├── dashboard/
│   │   └── soc_dashboard.py
│   ├── live/
│   │   └── live_monitor.py
│   └── utils/
│       ├── config_loader.py
│       └── logger.py
├── scripts/
│   ├── 01_replay_pcap.sh
│   ├── 02_run_cicflowmeter.sh
│   └── 03_check_ollama.sh
├── tests/
│   └── test_chunker.py
├── main_offline.py          — Role 3 only
├── main_live.py             — Role 3 only live
└── main_unified.py          — ALL 3 roles
```

---

## Quick start

```bash
# 1. Install
pip install -r requirements.txt

# 2. Check environment
bash scripts/03_check_ollama.sh

# 3. Save your NIDS v3 notebook output (in the notebook)
import joblib
joblib.dump(results_cicids, 'nids_v3_output.pkl', compress=3)

# 4. Generate CICIDS2017 logs
bash scripts/01_replay_pcap.sh
bash scripts/02_run_cicflowmeter.sh

# 5. Run offline evaluation (all 3 roles)
python main_unified.py --mode offline --nids_pkl nids_v3_output.pkl

# 6. View dashboard
python main_unified.py --mode dashboard
python main_unified.py --mode dashboard --detail 5
python main_unified.py --mode dashboard --html

# 7. Run live on real traffic
sudo suricata -i eth0 -D -l /var/log/suricata/
python main_unified.py --mode live --nids_pkl nids_v3_output.pkl
```

---

## Conflict resolution

| Role 1     | Role 3     | Severity | Action      |
|------------|------------|----------|-------------|
| attack     | attack     | HIGH     | Alert now   |
| attack     | benign     | MEDIUM   | Review flag |
| benign     | attack     | MEDIUM   | Review flag |
| suspicious | suspicious | MEDIUM   | Review flag |
| benign     | benign     | NONE     | Suppress    |

---

## EveBox integration

Set in config/settings.yaml:
  live.webhook_url: "http://localhost:5636/api/events"

HIGH/MEDIUM alerts are pushed as unified_nids_alert events into EveBox.
