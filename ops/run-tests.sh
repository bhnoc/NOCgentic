#!/usr/bin/env bash
# run-tests.sh; the regression suite that gates deploys (and is runnable by hand).
#
# Locks in the QA-sweep fixes: Python (pytest, agents + shared) and TypeScript
# (vitest, web-server). CI runs this before ops/deploy.sh; a red result blocks the
# deploy. Run it yourself before pushing:  bash ops/run-tests.sh
#
# Self-contained: builds the python venv + installs deps if missing, and npm-installs
# the web-server workspace if needed. Exits non-zero if either suite fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Python regression suite (pytest)"
PYVENV="tests/python/.venv"
if [ ! -x "$PYVENV/bin/python" ]; then
  echo "    building test venv"
  python3 -m venv "$PYVENV"
  "$PYVENV/bin/python" -m pip install --quiet --upgrade pip
fi
# Always sync deps: the self-hosted runner keeps this venv across checkouts, so a
# requirement added in a PR was never installed and its tests failed on import.
# pip is a no-op when everything is already satisfied.
"$PYVENV/bin/python" -m pip install --quiet -r tests/python/requirements-test.txt
"$PYVENV/bin/python" -m pytest tests/python -q

echo ""
echo "==> TypeScript regression suite (vitest)"
if [ ! -d node_modules ] || [ ! -d packages/web-server/node_modules ]; then
  echo "    npm install (workspaces)"
  npm install --no-audit --no-fund
fi
# @bhnoc/shared resolves through its package.json "main": dist/index.js, and dist/
# is gitignored -- so a fresh CI checkout has no built entry and vitest fails with
# "Failed to resolve entry for package @bhnoc/shared" before a single test runs.
# Build it first, exactly as packages/web-server/Dockerfile:17 already does for prod.
echo "    building @bhnoc/shared (provides dist/index.js for the import)"
npm run build --workspace=packages/shared

npm run test --workspace=packages/web-server

echo ""
echo "==> All regression suites passed."
