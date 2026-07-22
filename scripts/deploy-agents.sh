#!/usr/bin/env bash
# deploy-agents.sh — Sync agent code to EC2 and rebuild Docker services
#
# Usage:
#   ./scripts/deploy-agents.sh [--ssh-key PATH] [--ec2-ip IP] [--dry-run]
#
# Environment:
#   SSH_KEY   Path to SSH private key (default: ~/.ssh/blackhat)
#   EC2_IP    EC2 public IP (default: ${EC2_IP:?Set EC2_IP})
#
# The script:
#   1. Syncs agent code and configs to EC2
#   2. Rebuilds and restarts Docker services
#   3. Waits for health checks to pass
#   4. Prints service URLs on success

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# Defaults (override via env or flags)
# ---------------------------------------------------------------------------
EC2_IP="${EC2_IP:-${EC2_IP:?Set EC2_IP}}"
SSH_KEY="${SSH_KEY:-${HOME}/.ssh/blackhat}"
EC2_USER="ubuntu"
REMOTE_DIR="/opt/bhasia/app"
DRY_RUN=false

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ec2-ip)  EC2_IP="$2";  shift 2 ;;
        --dry-run) DRY_RUN=true; shift   ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
[[ -f "${SSH_KEY}" ]] || die "SSH key not found: ${SSH_KEY}. Set SSH_KEY env var or use --ssh-key."

if ${DRY_RUN}; then
    log "DRY RUN — no changes will be made."
fi

log "Deploying to ${EC2_USER}@${EC2_IP} (key: ${SSH_KEY})"

# Resolve repo root (script lives in scripts/, so go one level up)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------------------------------------------------------------------
# Step 1: Sync code to EC2
# ---------------------------------------------------------------------------
log "Syncing code to EC2..."

RSYNC_OPTS="-av --delete --exclude=.git --exclude=node_modules --exclude=dist --exclude=__pycache__ --exclude=*.pyc --exclude=.env --exclude=.env.s3 --exclude=venv"

if ${DRY_RUN}; then
    RSYNC_OPTS="${RSYNC_OPTS} --dry-run"
fi

# shellcheck disable=SC2086
rsync ${RSYNC_OPTS} \
    -e "ssh ${SSH_OPTS}" \
    "${REPO_ROOT}/" \
    "${EC2_USER}@${EC2_IP}:${REMOTE_DIR}/"

log "Code sync complete."

# ---------------------------------------------------------------------------
# Step 2: Rebuild and restart services on EC2
# ---------------------------------------------------------------------------
if ! ${DRY_RUN}; then
    log "Rebuilding and restarting Docker services on EC2..."

    # shellcheck disable=SC2029
    ssh ${SSH_OPTS} "${EC2_USER}@${EC2_IP}" bash -s <<'REMOTE'
set -euo pipefail
cd /opt/bhasia/app

# Use .env.s3 as the canonical env file (has OTEL + S3 + LLM keys)
if [[ ! -f .env.s3 ]]; then
    echo "WARNING: .env.s3 not found on EC2. Create it with LLM keys, S3, and OTEL settings."
fi

# Refresh AWS credentials from instance role for Docker containers
if [[ -f scripts/refresh-env-creds.sh ]]; then
    echo "Refreshing AWS credentials from instance role..."
    bash scripts/refresh-env-creds.sh .env.s3
fi

# Re-seed S3 data with fresh timestamps so time filters work
if [[ -f scripts/seed-s3.py ]]; then
    echo "Re-seeding S3 data with fresh timestamps..."
    python3 scripts/seed-s3.py || echo "WARNING: seed-s3.py failed (non-fatal)"
fi

# Bring up all services (base + agents), rebuild changed images
docker compose \
    -f docker-compose.agents.yml \
    --env-file .env.s3 \
    up -d --build --remove-orphans

echo "Services restarted."
REMOTE

    # ---------------------------------------------------------------------------
    # Step 3: Wait for health checks
    # ---------------------------------------------------------------------------
    log "Waiting for services to become healthy..."
    sleep 10

    HEALTH_URL="https://${EC2_IP}/health"
    MAX_RETRIES=12
    RETRY=0

    until curl -sk --fail "${HEALTH_URL}" > /dev/null 2>&1; do
        RETRY=$((RETRY + 1))
        if [[ ${RETRY} -ge ${MAX_RETRIES} ]]; then
            die "Health check failed after ${MAX_RETRIES} attempts. Check 'docker compose logs' on EC2."
        fi
        log "  Waiting... (attempt ${RETRY}/${MAX_RETRIES})"
        sleep 5
    done

    log "Health check passed."

    # ---------------------------------------------------------------------------
    # Step 4: Summary
    # ---------------------------------------------------------------------------
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║              Deployment Complete ✓                       ║"
    echo "╠══════════════════════════════════════════════════════════╣"
    echo "║  Chat UI:        https://${EC2_IP}/                      "
    echo "║  Chat API:       https://${EC2_IP}/api/v1/chat           "
    echo "║  Ingestion API:  https://${EC2_IP}/v1/health             "
    echo "╚══════════════════════════════════════════════════════════╝"
else
    log "DRY RUN complete — no changes applied."
fi
