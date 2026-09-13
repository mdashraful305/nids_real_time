#!/usr/bin/env bash
# scripts/03_check_ollama.sh
# ===========================
# Verify that Ollama server is running, the configured model is available,
# and send a test prompt to confirm the LLM produces valid JSON output.
#
# Usage:
#   bash scripts/03_check_ollama.sh
#   bash scripts/03_check_ollama.sh qwen2.5:7b

set -euo pipefail

# Read model from settings.yaml if yq is available, else use default or arg
MODEL="${1:-}"
if [ -z "$MODEL" ] && command -v python3 &>/dev/null; then
    MODEL=$(python3 -c "
import yaml, sys
try:
    with open('config/settings.yaml') as f:
        cfg = yaml.safe_load(f)
    print(cfg['ollama']['model'])
except Exception:
    print('qwen2.5:7b')
" 2>/dev/null || echo "qwen2.5:7b")
fi
MODEL="${MODEL:-qwen2.5:7b}"

OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  NIDS Role 3 — Setup Check                       ${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}\n"

PASS=0; FAIL=0

check() {
    local label="$1"; local result="$2"
    if [ "$result" = "ok" ]; then
        echo -e "  ${GREEN}✓${NC} $label"
        ((PASS++)) || true
    else
        echo -e "  ${RED}✗${NC} $label — $result"
        ((FAIL++)) || true
    fi
}

# ── Python ────────────────────────────────────────────────────────────────────
echo "  [1/6] Python environment"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version 2>&1)
    check "Python" "ok"
    echo "        $PY_VER"
else
    check "Python 3" "not found — install python3"
fi

# Check key packages
for PKG in pandas numpy requests yaml sklearn; do
    MODULE="$PKG"
    [ "$PKG" = "yaml" ] && MODULE="yaml"
    [ "$PKG" = "sklearn" ] && MODULE="sklearn"
    if python3 -c "import $MODULE" 2>/dev/null; then
        check "  python: $PKG" "ok"
    else
        check "  python: $PKG" "not installed — run: pip install -r requirements.txt"
    fi
done

# ── Suricata ──────────────────────────────────────────────────────────────────
echo ""
echo "  [2/6] Suricata"
if command -v suricata &>/dev/null; then
    SUR_VER=$(suricata --version 2>&1 | head -1)
    check "Suricata" "ok"
    echo "        $SUR_VER"
else
    check "Suricata" "not found — sudo apt install suricata"
fi

# ── Java (for CICFlowMeter) ───────────────────────────────────────────────────
echo ""
echo "  [3/6] Java (CICFlowMeter)"
if command -v java &>/dev/null; then
    JAVA_VER=$(java -version 2>&1 | head -1)
    check "Java" "ok"
    echo "        $JAVA_VER"
else
    check "Java" "not found — sudo apt install openjdk-11-jdk"
fi

# ── Ollama server ─────────────────────────────────────────────────────────────
echo ""
echo "  [4/6] Ollama server ($OLLAMA_URL)"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$OLLAMA_URL/api/tags" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    check "Ollama server reachable" "ok"
else
    check "Ollama server" "not reachable (HTTP $HTTP_CODE) — run: ollama serve"
    echo ""
    echo -e "  ${YELLOW}To start Ollama:${NC}"
    echo "    ollama serve &"
    echo "    ollama pull $MODEL"
    echo ""
    FAIL=$((FAIL + 1))
fi

# ── Model availability ────────────────────────────────────────────────────────
echo ""
echo "  [5/6] Model: $MODEL"
if [ "$HTTP_CODE" = "200" ]; then
    MODELS_JSON=$(curl -s "$OLLAMA_URL/api/tags" 2>/dev/null || echo "{}")
    MODEL_BASE="${MODEL%%:*}"
    if echo "$MODELS_JSON" | python3 -c "
import json,sys
data = json.load(sys.stdin)
models = [m['name'] for m in data.get('models',[])]
base = '${MODEL_BASE}'
found = any(base in m for m in models)
if found:
    matched = [m for m in models if base in m]
    print('FOUND: ' + ', '.join(matched))
    sys.exit(0)
else:
    print('NOT FOUND — available: ' + str(models))
    sys.exit(1)
" 2>/dev/null; then
        check "Model $MODEL" "ok"
    else
        check "Model $MODEL" "not pulled — run: ollama pull $MODEL"
        echo -e "    ${CYAN}Available models:${NC}"
        curl -s "$OLLAMA_URL/api/tags" 2>/dev/null | python3 -c "
import json,sys
data=json.load(sys.stdin)
for m in data.get('models',[]):
    print(f'      {m[\"name\"]}')
" 2>/dev/null || true
    fi
fi

# ── LLM JSON test ─────────────────────────────────────────────────────────────
echo ""
echo "  [6/6] LLM JSON output test"
if [ "$HTTP_CODE" = "200" ]; then
    TEST_PROMPT='Respond with ONLY this JSON, no other text: {"verdict":"benign","attack_type":"Normal","confidence":95,"key_indicators":["test"],"explanation":"Test OK.","recommended_action":"None"}'

    echo -e "  ${CYAN}Sending test prompt to $MODEL ...${NC}"
    RESPONSE=$(curl -s -X POST "$OLLAMA_URL/api/generate" \
        -H "Content-Type: application/json" \
        -d "{
            \"model\": \"$MODEL\",
            \"prompt\": \"$TEST_PROMPT\",
            \"stream\": false,
            \"options\": {\"temperature\": 0.0, \"num_predict\": 200}
        }" 2>/dev/null || echo "{}")

    RAW=$(echo "$RESPONSE" | python3 -c "import json,sys; print(json.load(sys.stdin).get('response',''))" 2>/dev/null || echo "")

    if echo "$RAW" | python3 -c "
import json, sys, re
text = sys.stdin.read()
m = re.search(r'\{[\s\S]*\}', text)
if not m: sys.exit(1)
obj = json.loads(m.group(0))
required = {'verdict','attack_type','confidence','key_indicators','explanation','recommended_action'}
if required.issubset(obj.keys()): sys.exit(0)
else: sys.exit(1)
" 2>/dev/null; then
        check "LLM returns valid JSON verdict" "ok"
        echo "    Raw: $(echo "$RAW" | head -c 120)..."
    else
        check "LLM JSON output" "invalid — model may need a larger context or different system prompt"
        echo "    Raw output: $(echo "$RAW" | head -c 200)"
    fi
fi

# ── data directories ──────────────────────────────────────────────────────────
echo ""
echo "  Data directories:"
for DIR in data/raw_pcap data/cicflow_csv data/eve_logs data/chunks data/results logs; do
    if [ -d "$DIR" ]; then
        N=$(find "$DIR" -maxdepth 1 -type f 2>/dev/null | wc -l)
        echo -e "    ${GREEN}✓${NC} $DIR/  ($N files)"
    else
        echo -e "    ${YELLOW}⚠${NC} $DIR/  (missing — will be created on first run)"
    fi
done

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
if [ $FAIL -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}✅ All checks passed! Ready to run.${NC}"
    echo ""
    echo "  Phase 1 (offline): python main_offline.py"
    echo "  Phase 2 (live):    python main_live.py"
else
    echo -e "  ${RED}${BOLD}❌ $FAIL check(s) failed.${NC} Fix the issues above, then re-run."
fi
echo -e "${BOLD}══════════════════════════════════════════════════${NC}\n"
