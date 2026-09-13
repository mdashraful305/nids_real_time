#!/bin/bash
# Called by tcpdump -z with the pcap file as $1
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVA="/usr/lib/jvm/java-8-openjdk-amd64/bin/java"
JAR="$ROOT_DIR/tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
OUT="$ROOT_DIR/data/cicflow_csv/"

echo "[CICFlow] Processing: $1"
$JAVA -jar $JAR "$1" "$OUT"
echo "[CICFlow] Done: $1"
