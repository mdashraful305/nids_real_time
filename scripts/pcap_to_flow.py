#!/usr/bin/env python3
# scripts/pcap_to_flow.py
# ==============================================================================
# Processes a PCAP file and extracts 52-feature flow statistics to a CSV.
# Uses the python 'cicflowmeter' package API directly to avoid CLI bugs
# and Java JNI compatibility issues.
# ==============================================================================

import sys
import os

def main():
    if len(sys.argv) < 3:
        print("Usage: python pcap_to_flow.py <input_pcap> <output_csv>")
        sys.exit(1)

    input_pcap = sys.argv[1]
    output_csv = sys.argv[2]

    if not os.path.exists(input_pcap):
        print(f"Error: PCAP file not found: {input_pcap}")
        sys.exit(1)

    # Ensure output folder exists
    out_dir = os.path.dirname(output_csv)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    import subprocess
    import shutil
    import tempfile

    # ── PcapNg detection ──────────────────────────────────────────────────────
    # Magic bytes:
    #   Classic PCAP : d4 c3 b2 a1  or  a1 b2 c3 d4  (little/big endian)
    #   PcapNg       : 0a 0d 0d 0a  (Section Header Block)
    # cicflowmeter's dpkt/scapy backend cannot read PcapNg.
    # Detect and convert to classic PCAP with editcap before processing.
    PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

    def is_pcapng(path):
        try:
            with open(path, 'rb') as f:
                return f.read(4) == PCAPNG_MAGIC
        except Exception:
            return False

    def convert_pcapng_to_pcap(src, dst):
        """Convert PcapNg → classic PCAP using editcap -F pcap."""
        editcap = shutil.which('editcap')
        if not editcap:
            raise RuntimeError('editcap not found — cannot convert PcapNg to PCAP')
        res = subprocess.run(
            [editcap, '-F', 'pcap', src, dst],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        if not os.path.exists(dst) or os.path.getsize(dst) == 0:
            raise RuntimeError(
                f'editcap PcapNg→PCAP conversion failed: {res.stderr.strip()}'
            )

    def run_sniffer(pcap_path, csv_path):
        from cicflowmeter.sniffer import create_sniffer

        if os.path.exists(csv_path):
            try:
                os.remove(csv_path)
            except Exception:
                pass

        sniffer, session = create_sniffer(
            input_file=pcap_path,
            input_interface=None,
            output_mode="csv",
            output=csv_path,
            fields=None,
            verbose=False
        )
        sniffer.start()
        sniffer.join()

        if hasattr(session, '_gc_stop'):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        session.flush_flows()

        if os.path.exists(csv_path):
            if os.path.getsize(csv_path) == 0:
                header = (
                    "src_ip,dst_ip,src_port,dst_port,protocol,timestamp,flow_duration,"
                    "flow_byts_s,flow_pkts_s,fwd_pkts_s,bwd_pkts_s,tot_fwd_pkts,tot_bwd_pkts,"
                    "totlen_fwd_pkts,totlen_bwd_pkts,fwd_pkt_len_max,fwd_pkt_len_min,"
                    "fwd_pkt_len_mean,fwd_pkt_len_std,bwd_pkt_len_max,bwd_pkt_len_min,"
                    "bwd_pkt_len_mean,bwd_pkt_len_std,pkt_len_max,pkt_len_min,pkt_len_mean,"
                    "pkt_len_std,pkt_len_var,fwd_header_len,bwd_header_len,fwd_seg_size_min,"
                    "fwd_act_data_pkts,flow_iat_mean,flow_iat_max,flow_iat_min,flow_iat_std,"
                    "fwd_iat_tot,fwd_iat_max,fwd_iat_min,fwd_iat_mean,fwd_iat_std,bwd_iat_tot,"
                    "bwd_iat_max,bwd_iat_min,bwd_iat_mean,bwd_iat_std,fwd_psh_flags,"
                    "bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,fin_flag_cnt,syn_flag_cnt,"
                    "rst_flag_cnt,psh_flag_cnt,ack_flag_cnt,urg_flag_cnt,ece_flag_cnt,"
                    "down_up_ratio,pkt_size_avg,init_fwd_win_byts,init_bwd_win_byts,"
                    "active_max,active_min,active_mean,active_std,idle_max,idle_min,"
                    "idle_mean,idle_std,fwd_byts_b_avg,fwd_pkts_b_avg,bwd_byts_b_avg,"
                    "bwd_pkts_b_avg,fwd_blk_rate_avg,bwd_blk_rate_avg,fwd_seg_size_avg,"
                    "bwd_seg_size_avg,cwr_flag_count,subflow_fwd_pkts,subflow_bwd_pkts,"
                    "subflow_fwd_byts,subflow_bwd_byts\n"
                )
                with open(csv_path, "w") as f:
                    f.write(header)
            return True
        return False

    # ── Convert PcapNg → classic PCAP if needed ───────────────────────────────
    work_pcap  = input_pcap
    temp_conv  = None
    if is_pcapng(input_pcap):
        print('⚠️  PcapNg format detected — converting to classic PCAP first...')
        _fd, temp_conv = tempfile.mkstemp(suffix='.pcap')
        os.close(_fd)
        try:
            convert_pcapng_to_pcap(input_pcap, temp_conv)
            work_pcap = temp_conv
            print('  ✓ Conversion OK')
        except Exception as conv_err:
            print(f'❌ PcapNg conversion failed: {conv_err}')
            if temp_conv and os.path.exists(temp_conv):
                os.remove(temp_conv)
            sys.exit(1)

    try:
        if run_sniffer(work_pcap, output_csv):
            print(f"✓ Generated flow CSV: {output_csv}")
        else:
            raise ValueError("Output CSV is empty or was not created.")

    except Exception as e:
        print(f"⚠️ Primary processing failed: {e}")

        editcap_path = shutil.which("editcap")
        if not editcap_path:
            print("❌ Error processing flows and editcap is not available to repair PCAP.")
            sys.exit(1)

        print("🔧 Attempting to repair PCAP file using editcap -F pcap ...")

        temp_fd, temp_pcap = tempfile.mkstemp(suffix=".pcap")
        os.close(temp_fd)

        try:
            # Force classic PCAP output (-F pcap) AND translate link-layer to Ethernet (-T ether)
            # This fixes both PcapNg edge cases AND unknown link-layer types (e.g. Type 197 on Wi-Fi).
            res = subprocess.run(
                [editcap_path, '-T', 'ether', '-F', 'pcap', work_pcap, temp_pcap],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )

            if not os.path.exists(temp_pcap) or os.path.getsize(temp_pcap) == 0:
                print("❌ Repair failed: editcap did not produce a valid file.")
                sys.exit(1)

            print("Attempting to process repaired PCAP...")
            if run_sniffer(temp_pcap, output_csv):
                print(f"✓ Successfully processed repaired PCAP and generated CSV: {output_csv}")
            else:
                print("❌ Failed to generate flow CSV even after repair.")
                sys.exit(1)
        except Exception as retry_err:
            print(f"❌ Error during repair attempt: {retry_err}")
            sys.exit(1)
        finally:
            if os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except Exception:
                    pass
    finally:
        # Always clean up the PcapNg conversion temp file
        if temp_conv and os.path.exists(temp_conv):
            try:
                os.remove(temp_conv)
            except Exception:
                pass

if __name__ == "__main__":
    main()
