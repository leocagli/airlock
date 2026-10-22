#!/bin/bash
# End-to-end smoke test over real HTTP: mock upstream (echo) + Airlock proxy.
# Usage: bash scripts/smoke.sh        (from anywhere; uses the repo venv)
set -u
cd "$(dirname "$0")/.." || exit 1
PY=.venv/bin/python
TMP=$(mktemp -d)
UP=${UP:-18788}   # override with UP=... PX=... bash scripts/smoke.sh
PX=${PX:-18787}
PASS=0
FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# Never test somebody else's server: the ports must be free before we start ours.
for port in $UP $PX; do
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/"; then
    echo "port $port is already in use; set UP/PX to free ports"; exit 2
  fi
done

$PY -m uvicorn demo.mock_upstream:create_mock_app --factory --host 127.0.0.1 --port $UP \
  --log-level warning > "$TMP/upstream.log" 2>&1 &
UP_PID=$!
$PY -m airlock serve --host 127.0.0.1 --port $PX --upstream "http://127.0.0.1:$UP" \
  --audit-log "$TMP/audit.jsonl" --fingerprints "$TMP/fp.json" > "$TMP/proxy.log" 2>&1 &
PX_PID=$!
trap 'kill $UP_PID $PX_PID 2>/dev/null' EXIT

for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$PX/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
if ! kill -0 "$PX_PID" 2>/dev/null || ! kill -0 "$UP_PID" 2>/dev/null; then
  echo "the smoke test proxy or mock model did not start:"; tail -5 "$TMP/proxy.log" "$TMP/upstream.log"; exit 2
fi

post() {  # post <file> <out-prefix>
  curl -s -D "$TMP/$2.h" -o "$TMP/$2.b" -X POST "http://127.0.0.1:$PX/v1/messages" \
    -H "content-type: application/json" -H "x-api-key: smoke-test-not-a-key" \
    -H "anthropic-version: 2023-06-01" --data-binary @"$1"
}
hdr() { grep -i "^$2:" "$TMP/$1.h" | head -1 | cut -d' ' -f2- | tr -d '\r'; }

echo "== health"
check "healthz responds" "curl -sf http://127.0.0.1:$PX/healthz | grep -q true"

echo "== 01 web page with hidden instruction (tool_result)"
post demo/requests/01_web_injection.json r1
A1=$(hdr r1 x-airlock-action)
echo "     action=$A1 findings=$(hdr r1 x-airlock-findings)"
check "injection is stopped (REDACT or BLOCK)" "[ \"$A1\" = BLOCK ] || [ \"$A1\" = REDACT ]"
check "HTTP 200 with Anthropic message shape" "grep -q '\"type\": *\"message\"' $TMP/r1.b"
check "webhook URL never reaches the model" "! grep -q 'webhook.site' $TMP/r1.b || [ \"$A1\" = BLOCK ]"

echo "== 01 again with stream=true (SSE block path)"
$PY -c "import json,sys; b=json.load(open('demo/requests/01_web_injection.json')); b['stream']=True; json.dump(b, open('$TMP/r1s.json','w'))"
post "$TMP/r1s.json" r1s
check "SSE event order starts with message_start" "grep -m1 '^event:' $TMP/r1s.b | grep -q message_start"
check "SSE ends with message_stop" "grep '^event:' $TMP/r1s.b | tail -1 | grep -q message_stop"

echo "== 02 poisoned MCP tool"
post demo/requests/02_mcp_poisoning.json r2
A2=$(hdr r2 x-airlock-action)
echo "     action=$A2"
check "poisoned tool quarantined (REDACT)" "[ \"$A2\" = REDACT ] || [ \"$A2\" = BLOCK ]"

echo "== 03 secret pasted by the user (fake key built at runtime)"
FAKE="AKIA$(head -c 400 /dev/urandom | tr -dc 'A-Z2-7' | head -c 16)"
sed "s/{{FAKE_AWS_KEY}}/$FAKE/g" demo/requests/03_secret_paste.json > "$TMP/r3.json"
post "$TMP/r3.json" r3
A3=$(hdr r3 x-airlock-action)
echo "     action=$A3"
check "secret masked (REDACT)" "[ \"$A3\" = REDACT ]"
check "fake key never reaches upstream" "! grep -q '$FAKE' $TMP/r3.b"

echo "== 04 clean request"
post demo/requests/04_clean.json r4
A4=$(hdr r4 x-airlock-action)
echo "     action=$A4"
check "clean request allowed" "[ \"$A4\" = ALLOW ]"

echo "== rug pull (same proxy, two requests)"
post demo/rugpull_before.json rp1
post demo/rugpull_after.json rp2
echo "     first=$(hdr rp1 x-airlock-action) second=$(hdr rp2 x-airlock-action)"
check "changed tool definition is caught" "[ \"$(hdr rp2 x-airlock-action)\" != ALLOW ]"

echo "== passthrough + stats + audit"
CT=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PX/v1/messages/count_tokens" \
  -H "content-type: application/json" --data-binary @demo/requests/04_clean.json)
echo "     count_tokens via passthrough -> HTTP $CT"
check "stats endpoint" "curl -sf http://127.0.0.1:$PX/airlock/stats > /dev/null"
check "audit chain verifies over HTTP" "curl -sf http://127.0.0.1:$PX/airlock/audit/verify | grep -qi true"
check "audit chain verifies via CLI" "$PY -m airlock audit-verify $TMP/audit.jsonl > /dev/null"
check "audit log holds no raw secrets" "! grep -q '$FAKE' $TMP/audit.jsonl"
check "proxy log holds no API key" "! grep -q 'smoke-test-not-a-key' $TMP/proxy.log"
head -c 11000000 /dev/zero > "$TMP/big.bin"
C413=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PX/v1/messages" \
  -H 'content-type: application/json' --data-binary @"$TMP/big.bin")
check "oversized body rejected (413)" "[ \"$C413\" = 413 ]"

echo "== Snyk (security gate; runs when the Snyk CLI is installed and logged in)"
SKIP=0
snyk_gate() {  # snyk_gate <label> <command...>; exit 0 pass, 1 issues, other: skip
  local label=$1; shift
  "$@" > "$TMP/snyk.out" 2>&1
  case $? in
    0) ok "$label" ;;
    1) bad "$label"; grep -E "\[(HIGH|MEDIUM)\]|Open issues|Total security issues" "$TMP/snyk.out" | head -5 ;;
    *) echo "  SKIP  $label ($(grep -m1 -oE 'SNYK-[A-Z]+-[0-9]+[^)]*\)?|not enabled|Network[^.]*' "$TMP/snyk.out" || echo 'Snyk unavailable'))"
       SKIP=$((SKIP + 1)) ;;
  esac
}
if command -v snyk > /dev/null 2>&1; then
  snyk_gate "Snyk Code: no medium or high issues" \
    snyk code test --severity-threshold=medium
  snyk_gate "Snyk Open Source: no medium or high issues in proxy deps" \
    snyk test --file=requirements-proxy.txt --package-manager=pip --command="$PY" --severity-threshold=medium
else
  echo "  SKIP  Snyk CLI not installed (npm install -g snyk && snyk auth)"
  SKIP=$((SKIP + 1))
fi

echo
echo "SMOKE: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
