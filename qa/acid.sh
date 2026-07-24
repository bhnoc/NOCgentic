#!/usr/bin/env bash
# acid.sh — full E2E validation of NOCgentic against acceptance criteria.
set -uo pipefail
BASE="${BASE:-https://aing.bhnoc.com}"
HOSTHDR="${HOSTHDR:-}"
CT="-H Content-Type:application/json"
# Persist cookies across POST->poll: jobs are bound to the creator's bh_sid session
# cookie (IDOR fix, sweep 3), so a correct client carries the jar like a browser does.
CJAR="$(mktemp)"; trap 'rm -f "$CJAR"' EXIT
CURL="curl -sk --max-time 30 -c $CJAR -b $CJAR $HOSTHDR"
pass=0; fail=0
chk(){ local n="$1" ok="$2"; if [ "$ok" = 1 ]; then echo "  ok   $n"; pass=$((pass+1)); else echo "  FAIL $n"; fail=$((fail+1)); fi; }
echo "== ACID against $BASE =="
ST=$($CURL "$BASE/api/v1/alerts/status")
echo "$ST" | python3 -c "import sys,json;d=json.load(sys.stdin);assert 'queueLength' in d and 'emitted' in d" 2>/dev/null && chk "alerts/status schema" 1 || chk "alerts/status schema" 0
RC=$($CURL "$BASE/api/v1/alerts/recent")
echo "$RC" | python3 -c "import sys,json;d=json.load(sys.stdin);a=d.get('alerts',d);assert isinstance(a,list)" 2>/dev/null && chk "alerts/recent is list" 1 || chk "alerts/recent is list" 0
run_query(){
  local q="$1"; local jid
  jid=$($CURL $CT -X POST "$BASE/api/v1/chat" -d "{\"query\":\"$q\"}" | python3 -c "import sys,json;print(json.load(sys.stdin).get('jobId',''))" 2>/dev/null)
  [ -z "$jid" ] && { echo "0|no-jobid|"; return; }
  for i in $(seq 1 40); do
    local r st; r=$($CURL "$BASE/api/v1/chat/$jid")
    st=$(echo "$r" | python3 -c "import sys,json;print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
    if [ "$st" = "done" ] || [ "$st" = "error" ]; then
      echo "$r" | python3 -c "
import sys,json
d=json.loads(sys.stdin.read(),strict=False); ans=(d.get('answer') or ''); agent=d.get('agentUsed',''); conf=d.get('confidence',0)
ok = 1 if (d.get('status')=='done' and len(ans)>20 and 'error' not in ans.lower()[:60]) else 0
print(f'{ok}|{agent}|conf={conf}')"
      return
    fi
    sleep 3
  done
  echo "0|timeout|"
}
for pair in \
  "How many alerts in the last 24 hours by severity?::alert-triage" \
  "Top 5 source IPs by connection count in the last 24 hours?::athena-hunter" \
  "Are there any SSH brute force attempts today?::threat" ; do
  q="${pair%%::*}"; want="${pair##*::}"
  res=$(run_query "$q"); ok="${res%%|*}"; rest="${res#*|}"; agent="${rest%%|*}"; extra="${rest#*|}"
  echo "     [$want] agent=$agent $extra"
  chk "chat E2E: $want" "$ok"
done
echo "== acid: $pass ok, $fail fail =="
[ "$fail" = 0 ]
