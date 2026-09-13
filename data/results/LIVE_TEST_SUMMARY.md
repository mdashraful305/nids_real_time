# Live attack detection — summary

**Target (NIDS host):** 192.168.1.169  
**Attacker (auto-detected):** 192.168.1.194  
**Attack bursts found:** 12 (grouped by >20s quiet gaps)  
**Generated:** 2026-08-21T09:40:31.060243+00:00

Attack type is inferred from destination port and arrival order (see script docstring) — a best-effort labelling for this project's known 4-attack test sequence, not a general classifier.

---

## Detection table

| Attack | Window (local) | Flows | Approach A (heuristic/ML) | Approach B (window verdict) | Suricata signatures |
|---|---|---|---|---|---|
| PortScan | 09:24:41–09:26:45 | 245 | NO (245 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| Other (port 0) | 09:27:31–09:27:31 | 1 | NO (1 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| DoS | 09:28:11–09:28:36 | 47 | NO (47 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| Web Attack | 09:29:32–09:29:44 | 24 | NO (24 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| Web Attack | 09:30:32–09:30:50 | 34 | NO (34 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| Other (port 0) | 09:31:32–09:31:32 | 1 | NO (1 flows, all Benign) | no window observed in range | 0 / not available |
| Other (port 0) | 09:32:32–09:32:32 | 1 | NO (1 flows, all Benign) | no window observed in range | 0 / not available |
| Other (port 0) | 09:33:32–09:33:32 | 1 | NO (1 flows, all Benign) | no window observed in range | 0 / not available |
| Other (port 0) | 09:36:34–09:36:34 | 1 | NO (1 flows, all Benign) | no window observed in range | 0 / not available |
| Other (port 0) | 09:37:35–09:37:35 | 1 | NO (1 flows, all Benign) | no window observed in range | 0 / not available |
| Web Attack | 09:38:05–09:38:29 | 44 | NO (44 flows, all Benign) | **YES** — PortScan @ 95% (LOW) | 0 / not available |
| Web Attack | 09:39:35–09:39:53 | 36 | NO (36 flows, all Benign) | no window observed in range | 0 / not available |

---

## Notes for the thesis write-up

- **Detected** means at least one flow/window in that attack's time range got a non-benign verdict — report the exact confidence/label from the table, not just yes/no.
- Approach B's window may lag the attack by up to ~90s (pcap rotation + processing) — windows are matched with that padding.
- Suricata counts are line-matches on the attacker's IP in `fast.log` within the burst window; treat as indicative (fast.log has no timezone marker).
- If a burst's label looks wrong (e.g. port-80 order swapped), rerun with `--gap` adjusted or pass `--attacker` explicitly — the clustering assumes clean gaps between attacks per ATTACKER_COMMANDS.md.
