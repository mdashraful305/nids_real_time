#!/usr/bin/env bash
# scripts/pcap_to_flows_colab.sh
# ==============================================================================
# pcap -> CICFlowMeter CSV, built for Colab free tier (CPU-only, 12 GB RAM,
# ~100 GB local disk, sessions that die without warning).
#
# WHY NOT scripts/02_run_cicflowmeter.sh
# --------------------------------------
#   1. It runs `java -jar $JAR`. tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar has
#      Main-Class: cic.cs.unb.ca.ifm.App -- the SWING GUI. On a headless Colab
#      VM that throws HeadlessException and produces no CSV.
#      tools/CICFlowMeter.jar has Main-Class: cic.cs.unb.ca.ifm.Cmd (the CLI),
#      which is the one to use. This script picks the CLI class explicitly so
#      either jar works.
#   2. It feeds the whole 8.8 GB pcap to one JVM. CICFlowMeter holds flows in
#      memory; that OOMs well before the file ends, and an OOM 6 hours in loses
#      everything.
#   3. No resume. A dropped Colab session means starting over.
#
# This script splits the pcap, processes chunks one at a time, skips chunks
# already done, and merges at the end. Interrupt and re-run at will.
#
# GPU IS IRRELEVANT HERE. CICFlowMeter is single-threaded CPU + disk. Use a CPU
# runtime -- it has the same RAM and you stop burning your GPU quota.
#
# USAGE
#   bash scripts/pcap_to_flows_colab.sh /path/to/Friday-WorkingHours.pcap
#   bash scripts/pcap_to_flows_colab.sh <pcap> <out.csv> <seconds_per_chunk>
# ==============================================================================
set -uo pipefail

PCAP="${1:-}"
OUT_CSV="${2:-data/cicflow_csv/$(basename "${PCAP%.*}")_flows.csv}"
CHUNK_SECONDS="${3:-600}"          # 10 min per chunk; lower if you still OOM
JVM_HEAP="${JVM_HEAP:-6g}"         # leave headroom under Colab's ~12.7 GB
WORK="${WORK:-/content/cfm_work}"  # LOCAL disk, never Drive

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'
CYN=$'\033[0;36m'; NC=$'\033[0m'; BLD=$'\033[1m'

say()  { echo -e "${CYN}$*${NC}"; }
ok()   { echo -e "${GRN}  OK  $*${NC}"; }
warn() { echo -e "${YLW}  !   $*${NC}"; }
die()  { echo -e "${RED}  X   $*${NC}"; exit 1; }

echo -e "${BLD}================================================================${NC}"
echo -e "${BLD}  pcap -> CICFlowMeter CSV   (Colab free, CPU)${NC}"
echo -e "${BLD}================================================================${NC}"

[ -n "$PCAP" ] || die "usage: bash $0 <pcap> [out.csv] [chunk_seconds]"
[ -f "$PCAP" ] || die "pcap not found: $PCAP"

# ── 1. dependencies ───────────────────────────────────────────────────────────
say "\n[1/6] Dependencies"
if ! command -v java >/dev/null 2>&1; then
    say "  installing openjdk-11-jre-headless ..."
    apt-get -qq update >/dev/null 2>&1
    apt-get -qq install -y openjdk-11-jre-headless >/dev/null 2>&1
fi
command -v java >/dev/null 2>&1 || die "java install failed"
ok "java: $(java -version 2>&1 | head -1)"

if ! command -v editcap >/dev/null 2>&1; then
    say "  installing wireshark-common (editcap) ..."
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y wireshark-common >/dev/null 2>&1
fi
command -v editcap >/dev/null 2>&1 || die "editcap missing; apt install wireshark-common"
ok "editcap present"

# jnetpcap (CICFlowMeter's packet reader) is a JNI binding: the .class files
# ship inside the jar but libjnetpcap.so does NOT. Without libpcap present the
# JVM dies with UnsatisfiedLinkError and writes no CSV.
if ! ldconfig -p 2>/dev/null | grep -q libpcap; then
    say "  installing libpcap ..."
    apt-get -qq install -y libpcap0.8 libpcap-dev >/dev/null 2>&1
fi
ldconfig -p 2>/dev/null | grep -q libpcap && ok "libpcap present" || warn "libpcap not detected"

# ── 2. locate a jar that exposes the CLI ──────────────────────────────────────
say "\n[2/6] CICFlowMeter jar"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
JAR=""
for cand in "${CICFLOW_JAR:-}" "$HERE/tools/CICFlowMeter.jar" \
            "$HERE/tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"; do
    [ -n "$cand" ] && [ -f "$cand" ] || continue
    if unzip -l "$cand" 2>/dev/null | grep -q "cic/cs/unb/ca/ifm/Cmd.class"; then
        JAR="$cand"; break
    fi
done
[ -n "$JAR" ] || die "no jar containing cic/cs/unb/ca/ifm/Cmd.class under $HERE/tools/"
ok "jar: $JAR"

NATIVE_DIR="$HERE/tools/native"
mkdir -p "$NATIVE_DIR"
if ! ls "$NATIVE_DIR"/libjnetpcap*.so >/dev/null 2>&1; then
    warn "libjnetpcap.so not found in $NATIVE_DIR"
    warn "If the run below fails with UnsatisfiedLinkError, fetch jnetpcap"
    warn "1.4 (linux x86_64) and drop libjnetpcap.so into that directory."
    warn "Then re-run this script -- completed chunks are kept."
fi

# ── 3. stage the pcap on LOCAL disk ───────────────────────────────────────────
# Reading an 8.8 GB pcap straight off the Drive FUSE mount is many times slower
# than local disk and is a common cause of apparent hangs.
say "\n[3/6] Staging"
mkdir -p "$WORK/chunks" "$WORK/csv"
PCAP_SIZE=$(du -m "$PCAP" | cut -f1)
say "  pcap: $PCAP  (${PCAP_SIZE} MB)"

case "$PCAP" in
  /content/drive/*)
      LOCAL_PCAP="$WORK/$(basename "$PCAP")"
      if [ ! -f "$LOCAL_PCAP" ]; then
          AVAIL=$(df -m /content | awk 'NR==2{print $4}')
          [ "$AVAIL" -gt $((PCAP_SIZE * 2)) ] || \
              die "need ~$((PCAP_SIZE*2)) MB free on /content, have ${AVAIL} MB"
          say "  copying off Drive to local disk (much faster to read) ..."
          cp "$PCAP" "$LOCAL_PCAP"
      fi
      PCAP="$LOCAL_PCAP"; ok "staged locally"
      ;;
  *)  ok "already on local disk" ;;
esac

# ── 4. split ──────────────────────────────────────────────────────────────────
say "\n[4/6] Splitting into ${CHUNK_SECONDS}s chunks"
if [ -z "$(ls -A "$WORK/chunks" 2>/dev/null)" ]; then
    editcap -i "$CHUNK_SECONDS" "$PCAP" "$WORK/chunks/part.pcap" \
        || die "editcap failed"
else
    ok "chunks already present -- reusing (delete $WORK/chunks to redo)"
fi
mapfile -t CHUNKS < <(find "$WORK/chunks" -name "part*.pcap" | sort)
[ "${#CHUNKS[@]}" -gt 0 ] || die "no chunks produced"
ok "${#CHUNKS[@]} chunks"

# ── 5. process, resumably ─────────────────────────────────────────────────────
say "\n[5/6] Extracting flows  (heap ${JVM_HEAP}, one chunk at a time)"
DONE=0; FAILED=0; SKIPPED=0
for i in "${!CHUNKS[@]}"; do
    C="${CHUNKS[$i]}"; B="$(basename "$C" .pcap)"
    MARK="$WORK/csv/$B.done"
    if [ -f "$MARK" ]; then SKIPPED=$((SKIPPED+1)); continue; fi

    printf "  [%3d/%3d] %s ... " "$((i+1))" "${#CHUNKS[@]}" "$B"
    CDIR="$WORK/csv/$B"; mkdir -p "$CDIR"

    if java -Xmx"$JVM_HEAP" -Djava.awt.headless=true \
            -Djava.library.path="$NATIVE_DIR:/usr/lib/x86_64-linux-gnu" \
            -cp "$JAR" cic.cs.unb.ca.ifm.Cmd "$C" "$CDIR" \
            > "$CDIR/run.log" 2>&1; then
        N=$(find "$CDIR" -name "*.csv" | head -1)
        if [ -n "$N" ]; then
            ROWS=$(( $(wc -l < "$N") - 1 ))
            touch "$MARK"; DONE=$((DONE+1))
            echo -e "${GRN}${ROWS} flows${NC}"
        else
            FAILED=$((FAILED+1)); echo -e "${RED}no CSV${NC}"
            grep -iE "error|exception" "$CDIR/run.log" | head -2 | sed 's/^/          /'
        fi
    else
        FAILED=$((FAILED+1)); echo -e "${RED}java failed${NC}"
        grep -iE "error|exception|UnsatisfiedLink" "$CDIR/run.log" | head -3 | sed 's/^/          /'
    fi
done
say "  done=$DONE  skipped(already)=$SKIPPED  failed=$FAILED"
[ "$DONE" -gt 0 ] || [ "$SKIPPED" -gt 0 ] || die "no chunk produced a CSV -- see $WORK/csv/*/run.log"

# ── 6. merge ──────────────────────────────────────────────────────────────────
say "\n[6/6] Merging"
mkdir -p "$(dirname "$OUT_CSV")"
FIRST=1; TOTAL=0
: > "$OUT_CSV.tmp"
while IFS= read -r f; do
    if [ "$FIRST" -eq 1 ]; then cat "$f" >> "$OUT_CSV.tmp"; FIRST=0
    else tail -n +2 "$f" >> "$OUT_CSV.tmp"; fi
    TOTAL=$((TOTAL + $(wc -l < "$f") - 1))
done < <(find "$WORK/csv" -name "*.csv" | sort)
mv "$OUT_CSV.tmp" "$OUT_CSV"

echo -e "${BLD}================================================================${NC}"
ok "$OUT_CSV"
ok "$TOTAL flows, $(du -m "$OUT_CSV" | cut -f1) MB"
echo
echo "  NEXT -- verify the drift is actually gone before anything else:"
echo "    python scripts/diagnose_feature_drift.py \\"
echo "        --universal_pkl universal_nids_output.pkl \\"
echo "        --flow_csv $OUT_CSV --dataset CICIDS2017"
echo
echo "  Need: flow-level recall > 80%  (it was 0.00%)"
echo -e "${BLD}================================================================${NC}"
