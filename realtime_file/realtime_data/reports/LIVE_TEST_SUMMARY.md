# Live attack detection — summary

**Target (NIDS host):** 192.168.1.169  
**Attacker (auto-detected):** 192.168.1.194  
**Attack bursts found:** 9 (grouped by >20s quiet gaps)  
**Generated:** 2026-11-16T10:09:48.577958+00:00

Attack type is inferred from destination port and arrival order (see script docstring) — a best-effort labelling for this project's known 4-attack test sequence, not a general classifier.

---

## Detection table

| Attack | Window (UTC) | Flows | Approach A (heuristic/ML) | Approach B (window verdict) | Suricata signatures |
|---|---|---|---|---|---|
| Web Attack | 09:25:36–09:27:15 | 105 | NO (105 flows, all Benign) | **YES** — Web Attack (Heuristics) @ 97% (HIGH) | 0 / not available |
| Web Attack | 09:29:06–09:29:28 | 104 | **YES** — Web Attack (Heuristics) @ 100% (72/104 flows) | NO (1 window(s), all benign) | 0 / not available |
| Web Attack | 09:30:01–09:30:34 | 165 | **YES** — Web Attack (Heuristics) @ 100% (139/165 flows) | **YES** — Web Attack (Heuristics) @ 100% (HIGH) | 11 alert line(s) |
| PortScan | 09:31:40–09:31:40 | 1002 | **YES** — PortScan (Heuristics) @ 100% (975/1002 flows) | NO (1 window(s), all benign) | 0 / not available |
| DoS | 09:32:43–09:32:49 | 15 | NO (15 flows, all Benign) | **YES** — PortScan (Heuristics) @ 100% (HIGH) | 4 alert line(s) |
| Brute Force | 09:33:13–09:33:24 | 1043 | **YES** — PortScan (Heuristics) @ 100% (1019/1043 flows) | **YES** — PortScan (Heuristics) @ 92% (HIGH) | 10 alert line(s) |
| PortScan | 09:34:27–09:34:39 | 1010 | **YES** — PortScan (Heuristics) @ 100% (987/1010 flows) | **YES** — Brute Force (Heuristics) @ 100% (HIGH) | 0 / not available |
| DoS | 09:35:59–09:36:00 | 50 | **YES** — Brute Force @ 53% (3/50 flows) | **YES** — Web Attack (Heuristics) @ 97% (HIGH) | 20 alert line(s) |
| DoS | 10:01:12–10:01:21 | 88537 | **YES** — DoS/Flood (Heuristics) @ 100% (88210/88537 flows) | **YES** — DoS/Flood (Heuristics) @ 100% (MEDIUM) | 28948 alert line(s) |

---

## Notes for the thesis write-up

- **Detected** means at least one flow/window in that attack's time range got a non-benign verdict — report the exact confidence/label from the table, not just yes/no.
- Approach B's window may lag high-volume flood bursts by up to a few minutes due to full 82-feature `python-cicflowmeter` extraction + Suricata DPI correlation — windows are matched with capture-endpoint affinity up to 420 s.
- Suricata counts are line-matches on the attacker's IP in `fast.log` within the burst window; treat as indicative (fast.log has no timezone marker).
- If a burst's label looks wrong (e.g. port-80 order swapped), rerun with `--gap` adjusted or pass `--attacker` explicitly — the clustering assumes clean gaps between attacks per ATTACKER_COMMANDS.md.
