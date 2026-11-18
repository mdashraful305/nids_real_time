# Live Experiment Report — `live_20261116_combined`

- **Duration**: 2624.3 s (0.73 h)
- **Host**: `192.168.1.169` (`wlp0s20f3`, backend `dumpcap`)
- **Detected Attacker IP**: `192.168.1.194`
- **Ollama**: `https://presenting-characteristics-kathy-anybody.trycloudflare.com` | model `qwen2.5:1.5b` (remote tunnel)
- **SHAP source**: `xgb_component`

## 1. Approach A (`nids_web.py`) — Complete Flow Log
- Total flows captured: **92237** (91613 UI-suppressed during bursts, all preserved in `flows.jsonl`)
- Role 1 (ML model alone) attacks: **4** | Heuristic overrides: **91402** | Combined R1 attacks: **91405**
- Role 3 (LLM) evaluated: **624** | Valid JSON: **623** (99.84%) | Errors: **1** | LLM Attack/Suspicious: **18**
- Agreement counts: `{'agree_benign': 605, 'agree_attack': 18}`

## 2. Per-Phase / Per-Attack Detection

| Phase / Attack | Source | Flows | R1 Model Hits | R1+Heur Hits (%) | R3 Eval | R3 Hits (%) | TTA R1 (s) | TTA R3 (s) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| DoS / Flood | auto_burst | 105 | 0 | 0 (0.0%) | 104 | 0 (0.0%) | None | None |
| Traffic burst #2 (ports=[0]) | auto_burst | 4 | 0 | 0 (0.0%) | 4 | 0 (0.0%) | None | None |
| Brute Force (SSH) | auto_burst | 104 | 0 | 72 (69.2%) | 34 | 2 (5.9%) | 2.23 | 9.42 |
| Web Attack / Scan | auto_burst | 164 | 0 | 139 (84.8%) | 31 | 6 (19.4%) | 7.52 | 14.27 |
| Web Attack / Scan | auto_burst | 4 | 0 | 0 (0.0%) | 4 | 0 (0.0%) | None | None |
| PortScan (1000 ports) | auto_burst | 1002 | 0 | 975 (97.3%) | 28 | 1 (3.6%) | 2.16 | 8.72 |
| Brute Force (SSH) | auto_burst | 15 | 0 | 0 (0.0%) | 15 | 0 (0.0%) | None | None |
| PortScan (1000 ports) | auto_burst | 1043 | 1 | 1019 (97.7%) | 27 | 3 (11.1%) | 5.51 | 12.09 |
| PortScan (998 ports) | auto_burst | 1010 | 0 | 987 (97.7%) | 26 | 3 (11.5%) | 3.32 | 10.75 |
| Brute Force (SSH) | auto_burst | 50 | 3 | 3 (6.0%) | 48 | 1 (2.1%) | 1.84 | 6.96 |
| Traffic burst #11 (ports=[53, 123, 161]) | auto_burst | 4 | 0 | 0 (0.0%) | 4 | 0 (0.0%) | None | None |
| DoS / SYN Flood | auto_burst | 88537 | 0 | 88210 (99.6%) | 103 | 2 (1.9%) | 14.58 | 19.59 |

## 3. Benign-Side False Positives
- Non-attacker flows observed: **177**
- Role 1 (ML+Heur) FP: **0** (FPR **0.0%**, **0.0/h**) [ML-only FP: 0]
- Role 3 (LLM) FP: **0/177** (FPR **0.0%**, **0.0/h**)

## 4. Latency Breakdown (ms)

| Stage | N | Mean | p50 | p95 | p99 | Max |
|---|---:|---:|---:|---:|---:|---:|
| role1_amortized_per_flow | 92237 | 1.691 | 1.559 | 1.834 | 4.316 | 105.894 |
| capture_to_verdict | 92237 | 74565.606 | 74394.09 | 144497.52 | 152435.44 | 153407.35 |
| role3_llm_roundtrip | 623 | 4400.696 | 4609.3 | 6247.55 | 6764.896 | 7168.0 |
| role3_queue_wait | 623 | 20129.348 | 11723.4 | 75083.36 | 104714.812 | 112356.6 |
| ollama_server_total_duration | 623 | 4054.394 | 4319.424 | 5920.733 | 6410.56 | 6856.102 |

## 5. Approach B (Unified Suricata + CICFlowMeter + Decision Engine)
- Windows evaluated: **32**
- Role 1 attack windows: **14** | Role 3 attack windows: **16** | Final attack windows: **17**
- Severity distribution: `{'LOW': 3, 'HIGH': 13, 'NONE': 15, 'MEDIUM': 1}`

## 6. Suricata Alerts
- Total EVE events: **123761** | Alert events: **28999**
  - `14484x` SURICATA STREAM 3way handshake SYNACK resend with different ack
  - `14464x` SURICATA STREAM 3way handshake SYN resend different seq on SYN recv
  - `29x` ET SCAN Possible Nmap User-Agent Observed
  - `10x` SURICATA ICMPv4 unknown code
  - `5x` ET WEB_SERVER ColdFusion administrator access
  - `4x` SURICATA Applayer Detect protocol only one direction
  - `1x` SURICATA HTTP Host header invalid
  - `1x` ET WEB_SERVER ColdFusion componentutils access
  - `1x` ET WEB_SPECIFIC_APPS Wordpress LiteSpeed Cache Plugin debug.log Access Attempt (CVE-2024-44000)

## 7. Live Train-vs-Deploy Feature Drift Check
- Flows checked: **92237** | Features >=10x shifted vs training RobustScaler: **4/52**
  - `Flow IAT Min`: train_med=4, live_med=83
  - `Fwd IAT Mean`: train_med=49, live_med=1.71e+05
  - `Fwd IAT Min`: train_med=3, live_med=2.681e+04
  - `Init_Win_bytes_backward`: train_med=0, live_med=6.424e+04
