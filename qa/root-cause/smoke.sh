#!/usr/bin/env bash
# smoke.sh — fast plumbing check for the root-cause slice. Run before every round.
# Confirms: the primitives import, their unit suites pass, and (if a service URL is
# given) the live service answers /health. Cheap, no AWS/Gemini needed (stub embedder).
set -euo pipefail
IFS=$' \n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT"
PYVENV="tests/python/.venv"
PG_DSN="${PG_DSN:-postgresql://nocgentic:nocgentic@localhost:5432/nocgentic}"
export PG_DSN

echo "==> [smoke] primitives import"
"$PYVENV/bin/python" - <<'PY'
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("agents/shared")))
import templating, embeddings, store  # noqa
print("    templating, embeddings, store import OK; embed_stub =", embeddings.is_stub())
PY

echo "==> [smoke] primitive unit suites (templating + embeddings)"
"$PYVENV/bin/python" -m pytest tests/python/test_templating.py tests/python/test_embeddings.py -q 2>&1 | tail -3

# Optional: live service health if ROOT_CAUSE_URL is set
if [ -n "${ROOT_CAUSE_URL:-}" ]; then
  echo "==> [smoke] GET ${ROOT_CAUSE_URL}/health"
  curl -fsS -m 5 "${ROOT_CAUSE_URL}/health" && echo
fi

echo "==> [smoke] green"
