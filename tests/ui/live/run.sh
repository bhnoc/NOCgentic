#!/usr/bin/env bash
# Drives the LIVE production UI (https://ng.bhnoc.com) in headless Chrome
# over CDP. Read-only: chat/alert clicks only, no destructive/admin actions.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
UI_DIR="${REPO_ROOT}/tests/ui/live"
WORK_DIR="${REPO_ROOT}/temp/ui-live-sweep"
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
CDP_PORT="${CDP_PORT:-9223}"

mkdir -p "${WORK_DIR}"

if [[ ! -x "${CHROME}" ]]; then
    echo "ERROR: Chrome not found at ${CHROME} (override with CHROME_BIN)" >&2
    exit 1
fi

chrome_pid=""
cleanup() { [[ -n "${chrome_pid}" ]] && kill "${chrome_pid}" 2>/dev/null || true; }
trap cleanup EXIT

wait_for() {
    local url="$1" name="$2" _i
    for _i in $(seq 1 40); do
        if curl -fs -o /dev/null -m 2 "${url}" 2>/dev/null; then return 0; fi
        sleep 0.25
    done
    echo "ERROR: ${name} never came up at ${url}" >&2
    return 1
}

"${CHROME}" --headless=new \
    --remote-debugging-port="${CDP_PORT}" \
    --user-data-dir="${WORK_DIR}/chrome-profile" \
    --no-first-run --disable-gpu \
    --window-size=1280,900 about:blank \
    > "${WORK_DIR}/chrome.log" 2>&1 &
chrome_pid=$!
wait_for "http://127.0.0.1:${CDP_PORT}/json/version" "headless chrome"

CDP_PORT="${CDP_PORT}" node "${UI_DIR}/golden-path.mjs"
