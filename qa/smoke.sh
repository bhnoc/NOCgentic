#!/usr/bin/env bash
# smoke.sh — fast reachability check of the NOCgentic app.
set -uo pipefail
BASE="${BASE:-https://aing.bhnoc.com}"
HOSTHDR="${HOSTHDR:-}"
CURL="curl -sk --max-time 15 $HOSTHDR"
pass=0; fail=0
chk(){ local n="$1" w="$2" g="$3"; if [ "$g" = "$w" ]; then echo "  ok   $n ($g)"; pass=$((pass+1)); else echo "  FAIL $n: want $w got $g"; fail=$((fail+1)); fi; }
echo "== SMOKE against $BASE =="
chk "/health"              200 "$($CURL -o /dev/null -w '%{http_code}' "$BASE/health")"
chk "/ (UI)"               200 "$($CURL -o /dev/null -w '%{http_code}' "$BASE/")"
chk "/api/v1/alerts/status" 200 "$($CURL -o /dev/null -w '%{http_code}' "$BASE/api/v1/alerts/status")"
chk "/api/v1/alerts/recent" 200 "$($CURL -o /dev/null -w '%{http_code}' "$BASE/api/v1/alerts/recent")"
chk "bogus path 404"       404 "$($CURL -o /dev/null -w '%{http_code}' "$BASE/api/v1/nope")"
echo "== smoke: $pass ok, $fail fail =="
[ "$fail" = 0 ]
