# Run the live NIDS on a local network (with simulated attacks)

This is the step-by-step for the real-time experiment: stand up the tri-role
pipeline on one machine, generate benign + attack traffic from a second machine
(or VM) on the same LAN, and score the result. It covers **both** capture
approaches and the **benign-only** run that is still missing from your results.

> You need your trained model `universal_nids_output.pkl` in the project root.
> It is not in this zip (it's ~99 MB on your Drive). Copy it in first.

---

## 0. One-time setup (detector machine)

```bash
cd nids_realtime
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# system tools
sudo apt-get install -y suricata tcpdump
# CICFlowMeter: install per your existing setup (Approach B only)

# Ollama + the model you benchmarked
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &            # leave running
ollama pull qwen2.5:1.5b  # the headline model (7b optional)

# put your trained model here:
cp /path/to/universal_nids_output.pkl .
```

Find your capture interface with `ip addr` (e.g. `eth0`, `wlp0s20f3`).

---

## 1. Pick an approach

| | Approach A — `nids_web.py` | Approach B — `main_unified.py` |
|---|---|---|
| Capture | NFStream inline, per-flow | tcpdump → CICFlowMeter, 60 s windows |
| Role 1 | runs per flow (live) | runs per window (batched) |
| Output | `nids_history.json` + browser dashboard | `data/results/unified_alerts.jsonl` + `app.py` dashboard |
| Use it for | fastest time-to-verdict, per-flow detail | the Suricata-fused thesis pipeline |

Run **both** if you want the Approach-1-vs-Approach-2 comparison; they load the
same model.

### Approach A — standalone live dashboard

```bash
source .venv/bin/activate
sudo bash scripts/reset_live_state.sh
sudo .venv/bin/python nids_web.py \
  --iface eth0 --pkl universal_nids_output.pkl \
  --ollama-url http://localhost:11434
# dashboard: http://localhost:5000 ; writes nids_history.json continuously
```

### Approach B — unified Suricata pipeline (4 terminals)

```bash
# T1 — Suricata
bash scripts/start_suricata.sh --iface eth0 --port 5001 --ollama-url http://localhost:11434
# T2 — rotated packet capture
bash scripts/start_capture.sh  --iface eth0 --rotate 20 --port 5001 --ollama-url http://localhost:11434
# T3 — flow processor daemon
bash scripts/flow_processor.sh
# T4 — live NIDS core
source .venv/bin/activate
python main_unified.py --mode live --nids_pkl universal_nids_output.pkl \
  --cicflow_csv data/cicflow_csv/ --dataset CICIDS2017
```

> Pin `--dataset CICIDS2017` so Role 1 routes to the CICIDS sub-model (its 52
> features match live CICFlowMeter output). Without it, routing is ambiguous.

---

## 2. Generate traffic from a second host (attacker VM on the same LAN)

Let `TARGET` = detector machine's LAN IP. **Only do this on a network you own.**
Keep each attack in its own time window and note the start/stop clock time — you
score by comparing flagged flows against the attacker IP and those windows.

```bash
TARGET=192.168.1.50

# ── benign baseline FIRST (for the FPR run — see step 4) ──
#   just use the network normally for ~1 hour: browse, curl, scp, a video call.
#   Generate NO attacks during this window.

# Brute force (Hydra) — SSH/FTP
hydra -l testuser -P rockyou.txt ssh://$TARGET
hydra -l testuser -P rockyou.txt ftp://$TARGET

# Port scan (nmap)
nmap -sS -p 1-65535 $TARGET          # SYN scan
nmap -sV $TARGET                     # service/version

# DoS / flood (hping3) — short bursts only
sudo hping3 -S --flood -p 80 $TARGET        # SYN flood
sudo hping3 --udp --flood -p 53 $TARGET     # UDP flood

# Web attack (on a test web app you host on TARGET)
nikto -h http://$TARGET
# or sqlmap against a deliberately vulnerable test endpoint you control
```

Record a small log like:

```
brute-force SSH   16:10:00 – 16:12:00
port scan         16:15:00 – 16:17:00
SYN flood         16:20:00 – 16:21:00
web (nikto)       16:25:00 – 16:28:00
```

---

## 3. Score the attack run

```bash
# Approach A
python evaluate_nids.py realtime --approach 1 --duration 1800 \
  --history nids_history.json --attacker-ip 192.168.1.80

# Approach B
python evaluate_nids.py realtime --approach 2 --duration 1800 \
  --alerts data/results/unified_alerts.jsonl
```

`--attacker-ip` is the second host's IP; it lets the scorer separate attacker
flows (hits) from everyone else (false positives). Output JSON lands in
`data/results/eval/`.

---

## 4. The run you are missing: benign-only false-positive rate

Capture **attack-free** traffic for a fixed window, then:

```bash
# Approach B benign capture already written to unified_alerts.jsonl:
python evaluate_nids.py benign-fpr --duration 3600 \
  --alerts data/results/unified_alerts.jsonl \
  --eve /var/log/suricata/eve.json

# or Approach A:
python evaluate_nids.py benign-fpr --duration 3600 --history nids_history.json
```

This reports Role 1 / Role 3 / Suricata **false-positive rate and alerts-per-hour**
on benign traffic — the evidence your paper needs to claim a low FPR. Every
non-benign verdict here is a false positive by definition.

---

## 5. Supporting measurements

```bash
# exact Role 3 prompt + decoding for the appendix
python evaluate_nids.py prompt-dump

# stage latency with p50/p95/p99 + hardware
python evaluate_nids.py latency --pkl universal_nids_output.pkl \
  --flows data/cicflow_csv/<a_flow_file>.csv \
  --ollama-url http://localhost:11434 --ollama-model qwen2.5:1.5b

# LLM parse audit (valid JSON vs error vs verdict counts)
python evaluate_nids.py llm-audit --results-dir data/results
```

---

## What to report from this experiment

1. Per-attack detection (which role caught brute-force / scan / DoS / web), by
   Approach A and B, with the metric defined once (see the scorer output).
2. **Benign FPR + alerts/hour** per role (step 4) — the headline gap-closer.
3. Latency p50/p95/p99 on this hardware (step 5).
4. The benchmark-to-live gap: compare live detection to your offline CICIDS
   numbers and discuss feature drift honestly (single-run attacks, one host).

Label dashboard confidence percentages as **model confidence**, not detection
rate — the scorer notes this in its output so you don't mislabel them.
