#!/usr/bin/env bash
# Compatibility wrapper — canonical deploy is ops/deploy.sh (used by CI).
#
# Historical callers used ./scripts/deploy-agents.sh; that script had an IFS bug
# and duplicated ops/deploy.sh. Prefer:
#   APP_DIR=/opt/nocgentic/app bash ops/deploy.sh
# Or push to main and let .github/workflows/deploy.yml run it on the box.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${ROOT}/ops/deploy.sh" "$@"
