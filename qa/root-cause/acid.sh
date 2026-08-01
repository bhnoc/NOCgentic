#!/usr/bin/env bash
# acid.sh — full end-to-end validation of the root-cause slice against every
# acceptance line in SLICE.md. Run when you think you're done. This is a RATCHET:
# it only grows. Needs the test Postgres (nocgentic-pgtest) up; uses the stub
# embedder + FixtureAnomalySource, so NO AWS creds or Gemini key required.
set -euo pipefail
IFS=$' \n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
PYVENV="tests/python/.venv"
PG_DSN="${PG_DSN:-postgresql://nocgentic:nocgentic@localhost:5432/nocgentic}"
export PG_DSN

# Ensure the test Postgres is reachable; start the throwaway container if not.
if ! "$PYVENV/bin/python" -c "import psycopg,os; psycopg.connect(os.environ['PG_DSN']).close()" 2>/dev/null; then
  echo "==> [acid] test Postgres unreachable; starting nocgentic-pgtest"
  docker start nocgentic-pgtest 2>/dev/null || docker run -d --name nocgentic-pgtest \
    -e POSTGRES_USER=nocgentic -e POSTGRES_PASSWORD=nocgentic -e POSTGRES_DB=nocgentic \
    -p 5432:5432 pgvector/pgvector:pg16 >/dev/null
  for i in $(seq 1 15); do
    "$PYVENV/bin/python" -c "import psycopg,os; psycopg.connect(os.environ['PG_DSN']).close()" 2>/dev/null && break
    sleep 2
  done
fi

echo "==> [acid] full level9000 suite (templating + embeddings + store + root_cause + investigator)"
"$PYVENV/bin/python" -m pytest \
  tests/python/test_templating.py \
  tests/python/test_embeddings.py \
  tests/python/test_store.py \
  tests/python/test_root_cause.py \
  tests/python/test_investigator.py \
  tests/python/test_triage.py \
  -q 2>&1 | tail -15

echo "==> [acid] green — all acceptance lines locked"
