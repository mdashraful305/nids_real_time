#!/bin/bash
# Called by tcpdump -z with the pcap file as $1
JAVA="/usr/lib/jvm/java-8-openjdk-amd64/bin/java"
JAR="/home/ashraf/nids_r1_2_3/tools/CICFlowMeterV3-0.0.4-SNAPSHOT.jar"
OUT="/home/ashraf/nids_r1_2_3/data/cicflow_csv/"

echo "[CICFlow] Processing: $1"
$JAVA -jar $JAR "$1" "$OUT"
echo "[CICFlow] Done: $1"
