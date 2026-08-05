#!/usr/bin/env bash
# Headless UI gate for packages/web-server/static/index.html.
# Drives the real page in Chrome over CDP against a stub of /api/v1/chat.
# No npm deps: uses Node's global WebSocket (>=22) and the local Chrome install.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UI_DIR="${REPO_ROOT}/tests/ui"
WORK_DIR="${REPO_ROOT}/temp/ui-gate"
CHROME="${CHROME_BIN:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
STUB_PORT=8791
CDP_PORT=9222

mkdir -p "${WORK_DIR}"

if [[ ! -x "${CHROME}" ]]; then
    echo "ERROR: Chrome not found at ${CHROME} (override with CHROME_BIN)" >&2
    exit 1
fi

stub_pid=""
chrome_pid=""
cleanup() {
    [[ -n "${stub_pid}" ]] && kill "${stub_pid}" 2>/dev/null || true
    [[ -n "${chrome_pid}" ]] && kill "${chrome_pid}" 2>/dev/null || true
}
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

# Fresh stub per run: the gate asserts exact POST counts, so leftover state fails it.
node "${UI_DIR}/static-stub-server.mjs" > "${WORK_DIR}/stub.log" 2>&1 &
stub_pid=$!
wait_for "http://127.0.0.1:${STUB_PORT}/" "stub server"

"${CHROME}" --headless=new \
    --remote-debugging-port="${CDP_PORT}" \
    --user-data-dir="${WORK_DIR}/chrome-profile" \
    --no-first-run --disable-gpu \
    `# Pin the viewport. Headless defaults to 756x469, and the alert popup is 429`\
    `# tall, so the on-screen clamp leaves only 40px of vertical travel and any`\
    `# drag assertion larger than that measures the clamp instead of the drag.`\
    `# An operator's browser is not 469px tall, so the default made the gate`\
    `# test a geometry nobody has.`\
    --window-size=1280,900 about:blank \
    > "${WORK_DIR}/chrome.log" 2>&1 &
chrome_pid=$!
wait_for "http://127.0.0.1:${CDP_PORT}/json/version" "headless chrome"

node "${UI_DIR}/quick-pick-autosubmit.mjs"
node "${UI_DIR}/lane-swap.mjs"
node "${UI_DIR}/alert-popup.mjs"
