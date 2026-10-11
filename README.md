# Unified NIDS Pipeline for Thesis Work

This repository implements a Network Intrusion Detection System that combines a trained machine-learning detector with a local LLM-based analyst. The system is designed for offline evaluation on CICIDS2017-style traffic and for live monitoring with Suricata.

The core idea is not a generic “all-in-one IDS,” but a thesis-oriented fusion pipeline:

- Role 1: ML-based intrusion classifier loaded from a saved model pickle
- Role 3: LLM-based security analyst that reads time-windowed security logs
- Decision engine: merges evidence from both roles into a single unified verdict, severity, and recommended action

This repo reflects the actual project implementation in the current codebase: the pipeline is built around CICFlowMeter, Suricata eve logs, local Ollama inference, and thesis evaluation/report generation.

## Data and code availability

The notebook, notebook data and generated outputs, and primary real-time data are documented in [DATA_AND_CODE_LINKS.md](DATA_AND_CODE_LINKS.md). That document also contains a journal-ready data-availability statement and a pre-submission checklist for access permissions, provenance, anonymization, versioning, and archival citation.

---

## Thesis scope and system design

The project studies whether combining a fast statistical detector with a language-model analyst improves intrusion detection quality over either method alone.

At a high level:

```text
Raw traffic / captured logs
        │
        ├── Suricata eve.json
        │      └── alerts, HTTP/TLS/DNS events, protocol observations
        │
        ├── CICFlowMeter CSV
        │      └── per-flow feature vectors for ML classification
        │
        ├── Role 1: ML model (XGBoost / ensemble / routed sub-model)
        │      └── predicts whether a flow or window is malicious
        │
        ├── Role 3: Ollama LLM analyst
        │      └── interprets the 60s log window and returns JSON verdict
        │
        └── Unified decision engine
               └── resolves conflicts, assigns severity, emits alert
```

This repository includes both:

- offline evaluation on historical dataset captures
- live monitoring on a real Suricata stream

---

## What is actually implemented in this repo

### Offline evaluation

The main evaluation workflow is driven by:

- `main_unified.py --mode offline`
- `src/pipeline/unified_pipeline.py`
- `src/evaluator/thesis_evaluator.py`

It does the following:

1. Loads Suricata eve logs from `data/eve_logs`
2. Loads CICFlowMeter CSVs from `data/cicflow_csv`
3. Aligns them into time windows
4. Runs the ML model from the saved pickle (`--nids_pkl`)
5. Optionally invokes the LLM for suspicious or relevant windows
6. Applies the decision engine to produce a final verdict
7. Saves metrics and results under `data/results`

### Live monitoring

This repo contains two real-time live paths, and both are relevant depending on the experiment.

#### Approach A — standalone live dashboard (`nids_web.py`)

This is the direct packet-capture dashboard path implemented in [nids_web.py](nids_web.py). It uses NFStream, performs per-flow ML classification inline, pushes suspicious flows to an LLM queue, and streams results to the browser dashboard.

Typical usage:

```bash
source .venv/bin/activate
sudo bash scripts/reset_live_state.sh

sudo .venv/bin/python nids_web.py \
  --iface <interface_name> \
  --pkl universal_nids_output.pkl \
  --ollama-url http://localhost:11434
```

This is a direct live monitoring path and is separate from the Suricata-based thesis pipeline.

#### Approach B — unified thesis live pipeline (`main_unified.py` + `app.py`)

This is the full thesis pipeline, which is centered around Suricata, rotated PCAP capture, CICFlowMeter flow generation, and the unified decision engine. It is implemented in [main_unified.py](main_unified.py), [src/pipeline/unified_pipeline.py](src/pipeline/unified_pipeline.py), and the dashboard entry point [app.py](app.py).

Recommended workflow:

```bash
source .venv/bin/activate
sudo bash scripts/reset_live_state.sh

# Terminal 1 — Suricata
bash scripts/start_suricata.sh \
  --iface <interface_name> \
  --port 5001 \
  --ollama-url http://localhost:11434

# Terminal 2 — capture
bash scripts/start_capture.sh \
  --iface <interface_name> \
  --rotate 20 \
  --port 5001 \
  --ollama-url http://localhost:11434

# Terminal 3 — flow processor daemon
bash scripts/flow_processor.sh

# Terminal 4 — live NIDS core
source .venv/bin/activate
python main_unified.py --mode live \
  --nids_pkl universal_nids_output.pkl \
  --cicflow_csv data/cicflow_csv/ \
  --ollama_url http://localhost:11434 \
  --window_seconds 20

# Terminal 5 — dashboard
source .venv/bin/activate
python app.py
```

This is the live approach that matches the thesis pipeline's end-to-end architecture.

### Dashboard / analysis output

The project also includes dashboards and result summaries for both live modes:

- `app.py` — unified dashboard for the thesis live pipeline
- `nids_web.py` — standalone live packet-inspection dashboard
- `main_unified.py --mode dashboard` — dashboard view for the unified pipeline

These are for reviewing recent alerts and output summaries during experiments or demonstrations.

---

## Repository structure

```text
.
├── app.py                     # web dashboard entry point
├── main_unified.py            # main unified pipeline entry point
├── main_offline.py            # historical / offline role-3-only path
├── main_live.py               # live monitoring path
├── config/
│   └── settings.yaml          # all pipeline defaults and paths
├── data/
│   ├── chunks/                # saved LLM-readable log chunks
│   ├── cicflow_csv/           # CICFlowMeter-derived feature CSVs
│   ├── eve_logs/              # Suricata eve.json inputs
│   └── results/               # evaluation outputs and alerts
├── scripts/
│   ├── 01_replay_pcap.sh      # generate PCAP replay / Suricata events
│   ├── 02_run_cicflowmeter.sh # run CICFlowMeter on captures
│   ├── 03_check_ollama.sh     # validate local Ollama setup
│   └── ...                    # additional benchmarking and analysis scripts
├── src/
│   ├── chunker/
│   ├── dashboard/
│   ├── engine/
│   ├── evaluator/
│   ├── ingestion/
│   ├── live/
│   ├── llm/
│   ├── pipeline/
│   └── utils/
├── tools/
│   └── CICFlowMeterV3-0.0.4-SNAPSHOT.jar
├── requirements.txt
├── README.md
└── nids_history.json
```

---

## Prerequisites

Before running the pipeline, make sure the following are installed and configured:

- Python environment with dependencies from `requirements.txt`
- Ollama installed and running locally
- A local model pulled into Ollama, e.g. `qwen2.5:1.5b` or another configured model
- Suricata installed for live capture or offline `.eve.json` analysis
- Java runtime for CICFlowMeter if you are generating flows locally

Typical Ollama setup:

```bash
ollama serve
ollama pull qwen2.5:1.5b
```

If you are running the offline evaluation with many windows, this project also expects parallel LLM requests to be enabled when desired:

```bash
export OLLAMA_NUM_PARALLEL=4
```

---

## Configuration

The main configuration file is:

- `config/settings.yaml`

This file sets:

- Ollama endpoint and model
- Suricata paths
- CICFlowMeter paths
- window size (`chunker.window_seconds`)
- flow/alert caps passed to the LLM
- output directories
- evaluation thresholds

Key settings include:

- `ollama.url`: default `http://localhost:11434`
- `ollama.model`: model name to use for the LLM analyst
- `chunker.window_seconds`: default window size used to group events
- `paths.cicflow_csv_dir`: local CICFlowMeter output directory
- `paths.eve_logs_dir`: Suricata eve log directory
- `paths.results_dir`: final analysis outputs

---

## Quick start

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

### 2) Check Ollama and model availability

```bash
bash scripts/03_check_ollama.sh
```

### 3) Prepare the ML model output

This project expects a saved pickle containing the trained detection model output from the research pipeline. Typical usage is:

```bash
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl
```

The `--nids_pkl` file is the exported model artifact used by the pipeline. It must match the serializer expectations in the project.

### 4) Generate offline data if needed

If you want to recreate the offline traffic data from capture files:

```bash
bash scripts/01_replay_pcap.sh
bash scripts/02_run_cicflowmeter.sh
```

### 5) Run offline evaluation

```bash
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl
```

Useful options:

```bash
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --quick
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --workers 1
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --no_llm_gating
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --low_memory
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --no_low_memory
```

### 6) Run live mode

There are two live options in this project.

#### A. Standalone real-time dashboard

```bash
source .venv/bin/activate
sudo bash scripts/reset_live_state.sh
sudo .venv/bin/python nids_web.py \
  --iface wlp0s20f3 \
  --pkl universal_nids_output.pkl \
  --ollama-url https://poet-normal-eligible-medieval.trycloudflare.com
```

#### B. Unified thesis pipeline

```bash
source .venv/bin/activate
sudo bash scripts/reset_live_state.sh

bash scripts/start_suricata.sh --iface <interface_name> --port 5001 --ollama-url http://localhost:11434
bash scripts/start_capture.sh --iface <interface_name> --rotate 20 --port 5001 --ollama-url http://localhost:11434
bash scripts/flow_processor.sh

python main_unified.py --mode live \
  --nids_pkl universal_nids_output.pkl \
  --cicflow_csv data/cicflow_csv/ \
  --ollama_url https://poet-normal-eligible-medieval.trycloudflare.com \
  --window_seconds 20
```

### 7) Run dashboard mode

```bash
python main_unified.py --mode dashboard
python main_unified.py --mode dashboard --detail 5
python main_unified.py --mode dashboard --html
```

---

## Inputs, outputs, and result files

### Input data

The project consumes:

- Suricata eve logs: `data/eve_logs/`
- CICFlowMeter flow CSVs: `data/cicflow_csv/`
- a saved ML artifact: `--nids_pkl`

### Output artifacts

The pipeline writes results to the project’s data directories, including:

- `data/chunks/` for per-window chunk text used by the LLM
- `data/results/` for evaluation summaries and traces
- `logs/` for runtime logs
- `unified_alerts.jsonl` for generated unified alerts

The exact files may vary by run, but the output structure is designed for thesis analysis, debugging, and alert review.

---

## Important project notes

### LLM gating and performance tuning

The code deliberately includes optimization logic for large offline datasets:

- windows with no Suricata alert and no ML attack signal are skipped for LLM inference
- only suspicious windows are sent to the LLM by default
- parallel workers can be enabled for concurrent LLM requests
- low-memory SQLite indexing is available for large captures

This is a real engineering feature of the thesis implementation and is not just a convenience wrapper.

### Dataset assumptions

This work is built around CICIDS2017-style research data and uses the same conventions as the project codebase:

- Suricata event time alignment
- CICFlowMeter flow features
- ground-truth mapping against CIC labels
- per-window attack evaluation rather than only per-flow classification

### Status

This is a research pipeline rather than a polished production IDS. It is designed to support experimental evaluation and live detection workflows in a thesis context.

---

## Typical thesis workflow

1. Train or export the ML classifier and save the pickle
2. Recreate or load CICIDS2017 traffic data
3. Run offline evaluation with `main_unified.py --mode offline`
4. Inspect metrics and alert summaries in `data/results`
5. Start one of the live monitoring setups above
6. Compare fused ML+LLM decisions against baseline single-role outputs

### Two live workflows used in this project

- `nids_web.py` = direct packet-sniffing dashboard for quick real-time testing using `<interface_name>` and the local Ollama endpoint
- `main_unified.py --mode live` + `app.py` = thesis-style live pipeline using Suricata + CICFlowMeter + unified alerting with the local Ollama URL

These are two distinct real-time implementations already present in the codebase and should not be confused.

---

## Useful commands summary

```bash
# offline evaluation
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl

# quick sanity check
python main_unified.py --mode offline --nids_pkl universal_nids_output.pkl --quick

# live monitoring
python main_unified.py --mode live --nids_pkl universal_nids_output.pkl

# dashboard view
python main_unified.py --mode dashboard

# check Ollama connectivity
bash scripts/03_check_ollama.sh
```

For full accuracy and reproducibility, use the configuration in `config/settings.yaml` and keep the dataset and model artifact consistent with the experiment being evaluated.
