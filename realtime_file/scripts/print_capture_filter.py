#!/usr/bin/env python3
"""
scripts/print_capture_filter.py
================================
Prints a BPF filter excluding this NIDS pipeline's own traffic — dashboard
access, and this host's own WAN-bound traffic (Ollama calls whether local or
via a rotating-IP Cloudflare tunnel, DNS lookups, anything else outbound to
the internet) — so it can be dropped straight into a tcpdump command line.

Usage
-----
    python scripts/print_capture_filter.py --port 5001 --ollama-url http://localhost:11434

    sudo tcpdump -i wlp0s20f3 -Z root \\
        -w /tmp/raw_pcap/live_capture_%Y%m%d%H%M%S.pcap -G 60 \\
        $(python scripts/print_capture_filter.py --port 5001 --ollama-url http://localhost:11434)
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.utils.capture_filter import build_self_exclusion_bpf


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=5001,
                    help="Dashboard port to exclude (5001 for app.py, 5000 for nids_web.py)")
    p.add_argument("--ollama-url", default="http://localhost:11434")
    p.add_argument("--exclude", action="append", default=[],
                    help="Extra BPF clause to also exclude, e.g. 'host 192.168.1.50'. Repeatable.")
    args = p.parse_args()
    print(build_self_exclusion_bpf(args.port, args.ollama_url, args.exclude))


if __name__ == "__main__":
    main()
