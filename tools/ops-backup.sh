#!/usr/bin/env bash
# ops-backup.sh — Capture operational state from the aing.bhnoc.com host
# that does NOT live in the S3 trace archive:
#   - Docker logs for every container (with timestamps)
#   - nginx access + error logs (they're symlinked to container stdout/stderr)
#   - docker ps + docker inspect snapshots
#   - .env.s3 with secrets redacted
#   - git state snapshot
#   - container image digests
#
# Output: backups/ops-<UTC-timestamp>/  (and a .tar.gz next to it)
#
# Usage:  bash tools/ops-backup.sh
#         SSH_KEY=~/.ssh/id_macmini EC2_HOST=ubuntu@aing.bhnoc.com bash tools/ops-backup.sh
set -euo pipefail

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_macmini}"
EC2_HOST="${EC2_HOST:-ubuntu@aing.bhnoc.com}"
REMOTE_APP_DIR="${REMOTE_APP_DIR:-/opt/bhasia/app}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${REPO_ROOT}/backups/ops-${TS}"
mkdir -p "${OUT_DIR}/logs" "${OUT_DIR}/inspect"

echo "[1/6] container logs (may take ~30s)..."
SSH="ssh -i ${SSH_KEY} -o StrictHostKeyChecking=no ${EC2_HOST}"
CONTAINERS="$($SSH 'docker ps --format "{{.Names}}"')"
for c in $CONTAINERS; do
    printf '        %s\n' "$c"
    $SSH "docker logs --timestamps $c 2>&1 | gzip" > "${OUT_DIR}/logs/${c}.log.gz"
done

echo "[2/6] docker ps + per-container inspect (secrets redacted)..."
$SSH 'docker ps -a'        > "${OUT_DIR}/docker-ps.txt"
$SSH 'docker images'       > "${OUT_DIR}/docker-images.txt"
for c in $CONTAINERS; do
    $SSH "docker inspect $c" > "${OUT_DIR}/inspect/${c}.json"
done
# `docker inspect` includes the full container env which exposes API keys,
# bearer tokens, HMAC secrets, etc. Redact anything that looks like a secret
# in place so this backup can be shared safely.
python3 - "${OUT_DIR}/inspect" <<'PY'
import glob, json, os, re, sys
leak_re = re.compile(r'(KEY|SECRET|TOKEN|PASSWORD|PASSWD)', re.IGNORECASE)
redacted = 0
for p in glob.glob(os.path.join(sys.argv[1], "*.json")):
    try:
        data = json.load(open(p))
    except Exception:
        continue
    for c in data:
        env = c.get("Config", {}).get("Env") or []
        new = []
        for e in env:
            if "=" in e:
                k, v = e.split("=", 1)
                if leak_re.search(k) and v and v != "<redacted>":
                    new.append(f"{k}=<redacted>")
                    redacted += 1
                    continue
            new.append(e)
        c.get("Config", {})["Env"] = new
    json.dump(data, open(p, "w"), indent=2)
print(f"        redacted {redacted} secret env vars from inspect/*.json")
PY

echo "[3/6] .env.s3 (secrets redacted)..."
# Redact any key containing KEY/SECRET/TOKEN/PASSWORD/PASSWD
$SSH "cat ${REMOTE_APP_DIR}/.env.s3" | \
    sed -E 's/^([A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z_]*=).*/\1<redacted>/' \
    > "${OUT_DIR}/env.s3.redacted"

echo "[4/6] remote git state..."
$SSH "cd ${REMOTE_APP_DIR} && git rev-parse HEAD 2>/dev/null ; git status --porcelain 2>/dev/null | head -50" \
    > "${OUT_DIR}/git-state.txt" 2>/dev/null || true

echo "[5/6] deployed config files (nginx, compose, Dockerfiles hashes)..."
$SSH "cd ${REMOTE_APP_DIR} && {
  echo '--- nginx/nginx-ssl.conf ---'
  cat nginx/nginx-ssl.conf
  echo
  echo '--- docker-compose.agents.yml ---'
  cat docker-compose.agents.yml
  echo
  echo '--- agent Dockerfile SHAs ---'
  for f in agents/*/Dockerfile packages/*/Dockerfile tools/*/Dockerfile; do
    [ -f \"\$f\" ] && echo \"\$(sha256sum \"\$f\" | awk '{print \$1}') \$f\"
  done
}" > "${OUT_DIR}/deployed-config.txt" 2>&1

echo "[6/6] manifest..."
cat > "${OUT_DIR}/MANIFEST.txt" <<EOF
BHNOCgentic operational backup
captured:   ${TS}
from host:  ${EC2_HOST}
remote dir: ${REMOTE_APP_DIR}
local dir:  ${OUT_DIR}

files:
  logs/<container>.log.gz  — docker logs --timestamps per container (stdout+stderr, gzipped)
                             nginx access + error are in app-nginx-1.log.gz
  inspect/<container>.json — docker inspect per container (env, volumes, network, IP)
  docker-ps.txt            — snapshot of running containers
  docker-images.txt        — snapshot of pulled images
  env.s3.redacted          — app env vars with secrets stripped
  git-state.txt            — remote HEAD commit + dirty-file list
  deployed-config.txt      — nginx conf, docker-compose.yml, Dockerfile sha256 digests

The S3 span archive ("prompts" data) is NOT in this bundle — that's
covered by:
  backups/aing-trace-*/                (rsync'd from s3://...aing-trace/)
  trace-export-*.csv                   (produced by tools/trace-export.py)
EOF

# Tarball the whole thing so it's one file to share / archive
TARBALL="${REPO_ROOT}/backups/ops-${TS}.tar.gz"
tar -C "${REPO_ROOT}/backups" -czf "${TARBALL}" "ops-${TS}"

echo
echo "done."
echo "  dir:     ${OUT_DIR}"
echo "  tarball: ${TARBALL}  ($(du -h "${TARBALL}" | awk '{print $1}'))"
