# Real-Time Hybrid NIDS Experimental Report (`live_20261116_combined`)

This consolidated technical report documents the full real-time LAN evaluation of our three-role hybrid Intrusion Detection System (**Role 1: Universal ML Ensemble + Stateful Behavioral Guard**, **Role 2: Signed SHAP Explainer**, **Role 3: LLM Security Analyst** + **Suricata 7.0.3 DPI**), comparing **Approach A** (fast per-flow streaming) against **Approach B** (cross-modal DPI + 82-feature flow windowing) across **all 4 attack families** (**PortScan**, **Web Attack**, **Brute Force**, and **DoS SYN Flood**) plus live LAN background traffic.

---

## 1. Testbed & Execution Configuration

* **Capture Interface & Host**: `wlp0s20f3` (`192.168.1.169`, LAN `192.168.1.0/24`), unprivileged `dumpcap` with `5 s` PCAP segment rotation and self-traffic BPF exclusion.
* **Attacker Host**: Separate physical/LAN host `192.168.1.194`.
* **Local Inference Hardware**: `12th Gen Intel(R) Core(TM) i3-1215U` (8 logical CPUs, `7.44 GB` RAM, CPU-only locally, Python `3.14.5`).
* **Role 3 LLM Endpoint**: Remote GPU node running `qwen2.5:1.5b` via Ollama tunneled over Cloudflare (`https://presenting-characteristics-kathy-anybody.trycloudflare.com`).
* **ML Model**: `universal_nids_output.pkl` (11-class unified label space routed to `CICIDS2017` `52` features, XGBoost component SHAP `xgb_component`, `RobustScaler`).
* **Combined Sessions (`live_20261116_combined`)**:
  * **Session 1 (`live_20261116_092302`)**: `09:23:05` – `09:45:02 UTC` (`1,277.1 s` active) — PortScan, Web Attack, Brute Force, and LAN background (`3,617` Approach-A flows; `23` Approach-B windows / `3,481` CICFlowMeter flows).
  * **Session 2 (`live_20261116_095911`)**: `09:59:15` – `10:07:34 UTC` (`454.4 s` active) — DoS SYN Flood and LAN background (`88,620` Approach-A flows; `9` Approach-B windows / `88,546` CICFlowMeter flows).
  * **Combined Totals**: `1,731.5 s` (`0.48 h`) active capture+analysis across both sessions (`1,817.0 s` active epoch span in `run_meta.json`, `2,624.3 s` end-to-end wall span including inter-session transition), `260k` packets (`341` 5s segments merged via `mergecap`), `0` UUID collisions, `0` dropped drain records.
* **Two-Phase Capture Stop & Dual-Pipeline Drain (`logs/drain_complete.json`)**:
  * Both sessions terminated via Two-Phase Drain (`dumpcap` capture halts first while PCAP extraction, Suricata continuous processing, CSV conversion, and queued Role-3 LLM calls run to zero remaining items).
  * Confirmed **`approach_a_complete: true`** and **`approach_b_complete: true`** in both sessions (`0` running NIDS/capture child processes afterward).

---

## 2. System Architecture & Engineering Fixes Validated Live

Prior diagnostic runs uncovered six structural issues typical when moving offline CICIDS2017 models into real LAN networks. All fixes below were implemented and verified live in `live_20261116_combined`:

1. **Train-vs-Deploy Feature Shift & Lack of Raw SYN Floods in CICIDS2017**:
   * Static CICIDS2017 supervised `argmax` alone struggles on live LAN floods and scans (`4/52` features shifted $\ge 10\times$ vs. training `RobustScaler` medians — `Flow IAT Min`: `4` vs `83`, `Fwd IAT Mean`: `49` vs `170,995`, `Fwd IAT Min`: `3` vs `26,806`, `Init_Win_bytes_backward`: `0` vs `64,240`).
   * Static ML alone still fired `4` true **Brute Force** hits (`44.4%–53.2%`) on SSH (`port 22`), while our **Stateful Capture-Timestamp Behavioral Guard** + **Suricata DPI** + **Role 3 LLM** recovered full live detection across all 4 attack classes at `0.0%` benign FPR.
2. **Capture-Timestamp Sliding Windows + Flood Reply Throttling (`behavioral_guard.py`, `nids_web.py`)**:
   * Approach A sliding windows (`15 s` general / `30 s` web & auth) run strictly on packet capture timestamps rather than wall-clock time, preventing flood backlogs from resetting burst counters.
   * Victim-server half-open SYN-ACK replies (`192.168.1.169:80 -> attacker:ephemeral`) are recognized as server responses (`is_server_reply`) and capture-time throttled from clogging Role 3's LLM queue (`skipped_server_reply_throttle`), while Priority-0/1 attack alerts pre-empt background Role-3 traffic (`queue_wait` improved from `352.0 s` pre-fix to `32.4 s` during Session 2 SYN flood / `20.1 s` combined).
3. **Signed Role-2 SHAP Framing & Canonical LLM Normalization**:
   * `nids_web.py` computes signed XGBoost SHAP log-odds contributions (`supporting Benign` vs. `opposing Benign`) and provides flow-context metadata (role, 15s rate, distinct destination ports, half-open SYN counts), paired with `normalize_llm_verdict()` canonicalizing messy small-LLM outputs.
4. **Approach B Role-1 Continuity & Cross-Modal Time Correlation (`unified_pipeline.py`)**:
   * Live attack-burst feature drift logs diagnostics without disabling `self._role1_ready`, keeping ML + SHAP active across all `32/32` windows.
   * `live_b_worker.py` (`worker_busy`) and Suricata event staging prevent premature flushing of orphan alert chunks (`0` windows had `alerts > 0, flows = 0`), pairing every Suricata signature burst with its corresponding CICFlowMeter CSV window in strict UTC.
5. **Suricata Checksum & Alert-Group Aggregation (`suricata -k none`, `suricata_threshold.conf`, `log_chunker.py`)**:
   * Disabling NIC checksum verification false positives (`-k none` + suppressing `2200074/2200076/2200077/2200078/2227001`) reduced invalid-checksum noise from `160,596` events to **`0`** while preserving HTTP stream inspection.
   * Flood alert grouping collapses redundant `SYN`/`SYNACK` resend lines with varying ephemeral client reply ports into `[Nx] ... client-reply-ports` summaries while printing true uncapped totals and severity-prioritized `ET` signatures.

---

## 3. Comparative Results: Approach A vs. Approach B (Speed vs. Depth Tradeoff)

| Metric | Approach A (`nids_web.py`) — Fast Per-Flow Streaming | Approach B (`unified_pipeline.py`) — Cross-Modal DPI + Flows |
|---|---|---|
| **Ingestion & Extraction** | `5 s` PCAP rotation + fast `dpkt` extractor | `5 s` Suricata 7.0.3 DPI + `20 s` `python-cicflowmeter` CSVs (`82` cols) |
| **Total Evaluated** | `92,237` flows (`91,820` attacker `192.168.1.194`, `240` reply flows, `177` benign flows) | `32` 20 s windows (`63` CSVs, `123,761` EVE events, `28,999` Suricata alerts) |
| **Role 1 Detection (Hybrid)** | **`91,405 / 91,820` (`99.55%`)** attacker hits (`4` ML-only SSH Brute Force + `91,402` heuristic overrides) | **`14`** Role-1 attack windows (`DoS/Flood`, `PortScan`, `Web Attack`, `Brute Force`; `0` ML shutoffs) |
| **Role 3 LLM Compliance** | `624` evaluated (`91,387` burst-suppressed), **`623/624` (`99.84%`) valid JSON** (`1` token-limit repetition error `ca27aad5`) | **`32/32` (`100.0%`) valid JSON** (`0` errors, `0` skipped windows) |
| **Role 3 Agreement** | **`18 / 18` (`100.0%`)** on Role-1 attack flows sent to Role 3 (`agree_benign: 605`, `agree_attack: 18`) | `16` non-benign windows (`12` suspicious, `4` attack), `17` combined (`13 HIGH`, `1 MEDIUM`, `3 LOW`, `15 NONE`) |
| **Benign False Positives** | **`0 / 177` (`0.0%`, `0.0 / h`)** across both Role 1 and Role 3 | **`0`** false positives on all `15` pure quiet/benign background windows (`15/15 NONE / Benign`) |
| **Processing Latency** | **Part 1 (scans/brute/web)**: amortized **`3.291 ms/flow`** (`p50 = 1.283 ms`), export-to-verdict mean **`3.71 s`**<br>**Part 2 (88k flood)**: amortized **`1.626 ms/flow`**, TTA **`14.58 s` (R1) / `19.59 s` (R3)** | **Normal windows**: ~`20–55 s` (`20 s` batching + up to `35 s` alignment + `~4.4 s` LLM)<br>**88k SYN flood**: ~`3 min` CSV conversion (capturing all `88,539` flood flows + `28,948` Suricata flood alerts together) |

### Standalone Stage Microbenchmark (`eval_latency_20261116_161114.json`, `N = 500` live flows)
* **Role 1 Single-Flow Latency (`N = 500`, CPU)**: mean `84.01 ms`, p50 `82.83 ms`, p95 `100.70 ms`, max `148.03 ms`
* **Role 1 Batched Latency (`N = 1` batch of `500`, CPU)**: **`0.1964 ms/flow`** (`428x` throughput speedup over single-flow loop)
* **Role 2 Signed SHAP (`N = 200`, CPU)**: mean `9.72 ms/flow`, p50 `8.83 ms`, p95 `14.75 ms`, max `31.05 ms`
* **Role 3 Remote GPU LLM (`N = 10`, `qwen2.5:1.5b` via tunnel)**: mean `1,652.25 ms`, p50 `1,454.38 ms`, p95 `2,403.21 ms`, `0` errors
* **Live Role-3 Overall (`N = 623`)**: roundtrip mean `4,400.70 ms` (`p50 = 4,609.30 ms`), Ollama server inference `4,054.39 ms` (`p50 = 4,319.42 ms`), queue wait mean `20,129.35 ms` (`p50 = 11,723.40 ms`).

---

## 4. Per-Attack & Cross-Modal Detection Breakdown

*(Grouped strictly by true attacker activity in `flows.jsonl`, `chunks/`, and Suricata logs rather than the naive sequential auto-labeler heuristics in `LIVE_TEST_SUMMARY.md`.)*

| Attack Category | UTC Window(s) | Observed Traffic & Signatures | Approach A Detection | Approach B Detection (Windows + Suricata) |
|---|---|---|---|---|
| **Web Attack (Slow Probes & Nikto)** | `09:25:36–09:27:15`<br>`09:29:06–09:29:28`<br>`09:30:01–09:30:34`<br>`09:35:59–09:36:18` | `105` slow port-80 probes (`~1/s`); `104` port-80 web probes; `164` Nikto HTTP scan flows; `50` mixed HTTP/SSH/POP3 probes | **Detected on 3/4 active bursts**: `72/104` (`69.2%`, TTA `2.23 s`), `139/164` (`84.8%`, TTA `7.52 s`), `3/50` (`4` ML Brute Force hits in mixed probe). *(Slow `~1/s` HTTP scan stayed below `15 s` threshold: `0/105`.)* | **Detected ALL (`7 HIGH` + `1 LOW`)**: caught the `~1/s` slow scan across **4 consecutive `HIGH Web Attack` (`97%`) windows (`W01–W04`)**; paired **5x ColdFusion**, **1x ColdFusion componentutils**, **1x WordPress CVE-2024-44000**, **1x HTTP Host header invalid** directly into flow chunks (`W09`, `W10`, `W19`) |
| **PortScan (Nmap 1000-port + Service/ICMP Probes)** | `09:31:40`<br>`09:32:43–09:32:49`<br>`09:33:13–09:33:24`<br>`09:34:27–09:34:39` | `3` full ~1,000-port TCP scans (`1,002`, `1,043`, `1,010` flows) + `15` Nmap `-sV` service/OS probes (`W13`/`W16`) | **Detected on all 3 port scans**: `975/1002` (`97.3%`, TTA `2.16 s`), `1019/1043` (`97.7%`, TTA `5.51 s`, `1` ML hit), `987/1010` (`97.7%`, TTA `3.32 s`). *(15-flow Nmap HTTP script probe was Benign at flow layer.)* | **Detected scans + probes (`3 HIGH` + `2 LOW`)**: `PortScan (Heuristics) HIGH` (`997`, `1,011`, `1,005` flows in `W12, W14, W17`) + caught `4x ET SCAN Possible Nmap User-Agent` (`/nmaplowercheck`) (`W13 LOW`) and `2x SURICATA ICMPv4 unknown code` + `GET ?/` (`W16 LOW`) |
| **Brute Force (SSH/Auth)** | `09:33:18–09:33:19` (`W15`) & `09:35:59–09:36:00` | Rapid multi-attempt connections on ports `22, 110, 995` (`14` flows in `W15`; `50` flows with `3` SSH sessions `14–16 pkts` in Burst 10) | **Detected via Static ML**: **`4` supervised ML-only hits** (`Brute Force @ 44.4%–53.2%`, TTA **`1.84 s`** R1 / `6.96 s` R3) | **Detected (`HIGH 100%` `agree=True`)**: `W15` (`09:34:32`, `14` flows, Role 1 + Role 3 both classified `attack: Brute Force`) |
| **DoS / SYN Flood (`hping3`)** | `10:01:12–10:01:21` | `88,537` half-open SYN flood flows to port `80` in `~8.6 s` (`28,948` Suricata stream flood alerts) | **`88,210 / 88,537` (`99.6%`)** `DoS/Flood`, TTA **`14.58 s` (R1) / `19.59 s` (R3)**, `103` R3 calls (`0` queue stall) | **`HIGH 99%` (`agree=True`) + `MEDIUM 100%`**: **`W23`** paired **`58,202` flows + `28,948` Suricata SYN/SYN-ACK flood alerts** in `chunk_0023`; **`W24`** flagged remaining `30,107` flows |
| **Benign / Quiet LAN Traffic** | Inter-burst & tail windows (`mDNS`, `NetBIOS`, `ICMP`, `DNS`) | `177` non-attacker Approach-A flows; `15` quiet Approach-B windows (`W05, W06, W08, W11, W18, W20–W22, W25–W31`) | **`0 / 177` (`0.0%`, `0.0/h`)** false positives on BOTH Role 1 and Role 3 | **`15 / 15` (`100%`) `NONE / Benign`** with `agree=True` (**`0`** pure-benign false positives) |

### Complementary Architectural Finding for the Paper
1. **Approach A wins on latency (`1.6–3.3 ms/flow` Role 1, `<15 s` TTA even under an `88k`-flow SYN flood)** — ideal as a low-latency inline edge detector.
2. **Approach B wins on low-and-slow visibility & deep payload attribution** — its `20 s` aggregation windows caught the `~1/s` HTTP probe burst (`4 HIGH` windows missed by Approach A's `15 s` threshold), while Suricata DPI caught `15`-flow Nmap HTTP script scans (`ET SCAN Nmap User-Agent`) and `ColdFusion` / `WordPress CVE-2024-44000` exploits directly correlated with their exact flow records, at the cost of `~20 s` windowing + heavier `python-cicflowmeter` CSV extraction time under floods (`~3 min`).

---

## 5. Suricata 7.0.3 Signatures & Role-3 Audit Summary

* **Suricata Total Events (`eve.json`)**: `123,761` events, `28,999` alert events (`0` invalid-checksum false positives):
  * `14,484x` `SURICATA STREAM 3way handshake SYNACK resend with different ack`
  * `14,464x` `SURICATA STREAM 3way handshake SYN resend different seq on SYN recv`
  * `29x` `ET SCAN Possible Nmap User-Agent Observed`
  * `10x` `SURICATA ICMPv4 unknown code`
  * `5x` `ET WEB_SERVER ColdFusion administrator access`
  * `4x` `SURICATA Applayer Detect protocol only one direction`
  * `1x` `SURICATA HTTP Host header invalid`
  * `1x` `ET WEB_SERVER ColdFusion componentutils access`
  * `1x` `ET WEB_SPECIFIC_APPS Wordpress LiteSpeed Cache Plugin debug.log Access Attempt (CVE-2024-44000)`
* **Approach A LLM Audit (`r3.jsonl`)**: `624` total calls (`623` valid JSON = `99.84%`, `1` `parse_json_error` on flow `ca27aad5` from repetitive token truncation at `num_predict=400`); `verdict_counts`: `benign=605`, `attack=18`; `agreement_counts`: `agree_benign=605`, `agree_attack=18`.
* **Approach B LLM Audit (`eval_llm_audit_20261116_160936.json`)**: `32` windows scored (`suspicious=12`, `benign=16`, `attack=4`), **`llm_error_windows=0`**, **`llm_skipped_windows=0`**.
* **Prompt Disclosures**: Complete verbatim system prompts & decoding parameters for both approaches are archived in [eval_realtime_approach1_20261116_160942.json](eval/eval_realtime_approach1_20261116_160942.json), [eval_realtime_approach2_20261116_160943.json](eval/eval_realtime_approach2_20261116_160943.json), and [role3_prompt_disclosure.txt](eval/role3_prompt_disclosure.txt).

---

## 6. Archive Structure (`realtime_data/`, `551 MB`)

* `pcaps/capture_full.pcap` (`25 MB`, `260k` packets) & `pcaps/segments/` (`341` 5s PCAPs)
* `csv/approach_a_flows.csv` (`92,237` rows), `csv/approach_a_r3.csv` (`624` rows), `csv/approach_b_alerts.csv` (`32` rows), `csv/cicflow_csv/` (`63` 82-col CSVs)
* `json/flows.jsonl`, `json/r3.jsonl`, `json/role1_proba_debug.jsonl`, `json/unified_alerts.jsonl`, `json/nids_history.json`, `json/run_meta.json`, `json/suricata/{eve.json,fast.log,stats.log,suricata.log}`
* `chunks/` (`32` UTC cross-modal chunks `#0000..#0031`)
* `reports/{FINAL_REALTIME_REPORT.md,EXPERIMENT_REPORT.md,experiment_report.json,LIVE_FULL_REPORT.md,LIVE_TEST_SUMMARY.md,settings_live.yaml}` & `reports/eval/*`
* `logs/{drain_complete.json,nids_web_5000_*.log,main_unified_live_*.log,live_b_worker_*.log,app_5001_*.log,suricata_*.log}`
