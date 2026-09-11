#!/usr/bin/env bash
# NOCgentic deploy — run BY the self-hosted GitHub Actions runner on the nocgentic box.
#
# The runner checks main out into its own workspace ($GITHUB_WORKSPACE, == PWD here).
# This script mirrors that checkout into the live app dir, refreshes the AWS creds the
# containers need, then rebuilds/restarts the Docker Compose stack and health-checks it.
#
# It deliberately preserves the box-authoritative files that are NOT in git:
#   .env .env.s3  (LLM + S3 + OTEL secrets, injected AWS creds)   node_modules/ venv/
#   *.log *.pid  .git/   (and never touches /etc/letsencrypt, which nginx mounts)
#   nginx/nginx-ssl.conf  (rendered below from its .template with ORIGIN_SECRET)
#
# Safe to run by hand on the box too:  APP_DIR=/opt/nocgentic/app bash ops/deploy.sh
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/nocgentic/app}"
SRC="${GITHUB_WORKSPACE:-$(pwd)}"
COMPOSE_FILE="docker-compose.agents.yml"
ENV_FILE=".env.s3"

echo "==> Deploying from $SRC -> $APP_DIR"

# First deploy into an empty/new dir needs the tree to exist.
mkdir -p "$APP_DIR"

# Mirror source in. --delete keeps the live dir == git, but the excludes below are
# NEVER deleted, so the box's secrets / deps / logs / TLS survive untouched.
rsync -a --delete \
  --include='.env.example' \
  --exclude='.env' \
  --exclude='.env.*' \
  --exclude='node_modules/' \
  --exclude='venv/' \
  --exclude='.venv/' \
  --exclude='dist/' \
  --exclude='nginx/nginx-ssl.conf' \
  --exclude='*.log' \
  --exclude='*.log.*' \
  --exclude='*.pid' \
  --exclude='.git/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$SRC"/ "$APP_DIR"/

cd "$APP_DIR"

# .env.s3 is the box's source of truth (LLM keys + S3 + OTEL). It is NOT in git.
# Refuse to (re)build without it rather than bring up a broken stack.
if [ ! -f "$APP_DIR/$ENV_FILE" ]; then
  echo "!! $APP_DIR/$ENV_FILE is missing. Seed it once (see .env.example); refusing to deploy." >&2
  exit 1
fi

# Containers can't reach IMDS, so pull fresh temporary instance-role creds into .env.s3.
# (See scripts/refresh-env-creds.sh — these expire in a few hours; every deploy re-injects.)
if [ -f scripts/refresh-env-creds.sh ]; then
  echo "==> Refreshing AWS credentials from instance role"
  bash scripts/refresh-env-creds.sh "$ENV_FILE"
fi

# Render nginx-ssl.conf from its template, injecting ORIGIN_SECRET from .env.s3.
# The rendered file is gitignored and rsync-excluded, so the secret never lands in
# git and a deploy can't clobber it with a placeholder.
echo "==> Rendering nginx config"
ORIGIN_SECRET="$(grep -E '^ORIGIN_SECRET=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
if [ -z "$ORIGIN_SECRET" ]; then
  echo "!! ORIGIN_SECRET is not set in $APP_DIR/$ENV_FILE. Without it the CloudFront" >&2
  echo "   origin lock cannot be rendered, and the security group already admits the" >&2
  echo "   whole shared CloudFront IP range — refusing to deploy an unprotected origin." >&2
  exit 1
fi
ZEEK_TOKEN="$(grep -E '^ZEEK_DETECTOR_API_TOKEN=' "$ENV_FILE" | head -1 | cut -d= -f2-)"
if [ -z "$ZEEK_TOKEN" ]; then
  echo "    note: ZEEK_DETECTOR_API_TOKEN not set in $ENV_FILE — /zeek/ location will return 401 until set" >&2
fi
python3 - "$ORIGIN_SECRET" "$ZEEK_TOKEN" <<'PY'
import sys
secret, zeek_token = sys.argv[1], sys.argv[2]
src = 'nginx/nginx-ssl.conf.template'
dst = 'nginx/nginx-ssl.conf'
body = open(src).read()
if '__ORIGIN_SECRET__' not in body:
    sys.exit(f'{src} has no __ORIGIN_SECRET__ placeholder')
body = body.replace('__ORIGIN_SECRET__', secret)
body = body.replace('__ZEEK_DETECTOR_API_TOKEN__', zeek_token)
open(dst, 'w').write(body)
print(f'    rendered {dst}')
PY

# Rebuild changed images and restart. --remove-orphans cleans up any renamed services.
echo "==> Bringing up the compose stack"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build --remove-orphans --force-recreate nginx
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" exec -T nginx nginx -s reload || true

# Prune dangling build layers so the box doesn't fill up over many deploys.
docker image prune -f >/dev/null 2>&1 || true

# Give the stack a moment, then health-check via nginx (TLS) on the box itself.
echo "==> Post-deploy health"
docker compose -f "$COMPOSE_FILE" ps

HEALTHY=false
for i in $(seq 1 30); do
  if curl -sk --fail -H "Host: ng.bhnoc.com" -o /dev/null "https://127.0.0.1/health" || curl -sk --fail -o /dev/null "https://127.0.0.1/health" ; then
    HEALTHY=true
    break
  fi
  echo "  waiting for /health... ($i/30)"
  sleep 5
done

if $HEALTHY; then
  echo "==> OK: /health is up"
else
  echo "!! /health did not come up — dumping recent container logs:" >&2
  docker compose -f "$COMPOSE_FILE" logs --tail=40 >&2 || true
  exit 1
fi
