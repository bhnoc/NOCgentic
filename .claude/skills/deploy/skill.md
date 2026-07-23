---
name: deploy
description: Deploy the NOCgentic (bhnocgentic) Black Hat NOC platform from nothing to fully running on EC2 — provision the instance, install Docker, sync code, wire credentials, bring up the Docker Compose agent stack, and issue the TLS cert. Trigger on "deploy nocgentic", "stand up the NOC app", "redeploy the agents", "bring the blackhat app up from scratch", or fresh-instance provisioning.
---

# NOCgentic — Deploy Skill

Take the Black Hat Asia NOC platform (**bhnocgentic**, repo `bhnoc/NOCgentic`) from
nothing to fully running.

> `nocgentic` is the **project name**, not a hostname. The app is served at
> **`https://aing.bhnoc.com/`**. There is no `nocgentic.bhnoc.com`.

This skill is a living document — append what you learn each deploy. Its sibling is
[[../ops/skill.md]] (day-2 operations). **PostCog** (the Slack bot) is a separate app with
its own skills at `blackhat/PostCog/.claude/skills/`.

## What you're deploying

An agentic NOC/SOC dashboard. Docker Compose stack at `/opt/bhasia/app` on the EC2 box:

| Service | Port | Role |
|---------|------|------|
| `nginx` | 80/443 | TLS termination + reverse proxy (only public entry) |
| `web-server` | 3000 (internal) | Chat UI + alerts API (Node) |
| `orchestrator` | 8001 | Routes questions to the specialist agents |
| `threat-hunter` | 8002 | Threat hunting over logs |
| `alert-triage` | 8003 | Alert triage (Athena) |
| `thousandeyes-analyst` | 8004 | ThousandEyes network analysis |
| `athena-hunter` | 8005 | NL→SQL over the Corelight Athena tables |
| `audit-monitor` | 8787 (internal) | Token-gated trace viewer at `/bh/1337/thetraces/` |

Backend data: **Athena** (`blackhat_pope_logs` DB, `blackhat-pope-dev` workgroup, `us-west-2`)
over Corelight logs in S3 (`blackhat-pope-dev-logs`). LLM: **Gemini** by default
(`GEMINI_MODEL`, provider selectable via `LLM_PROVIDER`, OpenRouter as fallback).

## Current deployed instance (as of 2026-07-22)

| Property | Value |
|----------|-------|
| Instance ID | `i-0430224b1ac82701e` (nickname **AING**) |
| Type | g6e.4xlarge (GPU — **overspec'd**, the app is pure Athena/HTTP; see [[../ops/skill.md]]) |
| Region | `us-west-2` |
| Public IP | ephemeral — changes on every stop/start (currently `44.248.50.25`) |
| DNS | `aing.bhnoc.com` (Cloudflare zone) |
| IAM role | `blackhat-pope-dev-ec2-role` (has Athena/Glue/S3) |
| SSH | `ssh ubuntu@aing.bhnoc.com` (or the current IP) |
| Security group | `sg-022b87911ecf12539` — 443 restricted to allow-listed IPs |
| App dir | `/opt/bhasia/app` |

> Note: the box **also** hosts PostCog at `/home/ubuntu/PostCog` (systemd service). Different
> app; see its skills. Relevant here only because both have a process named `python app.py`
> — never `pkill -f app.py` on this host (see [[../ops/skill.md]]).

## ⚠️ Known stale artifacts in the repo

Fix or ignore these — they predate the current infra:

1. **`scripts/deploy-agents.sh` defaults `EC2_IP=54.179.83.209`** — an old Singapore IP.
   Always pass `--ec2-ip` / `EC2_IP` explicitly, or the deploy targets a dead host.
2. **`SETUP.md` and `.env.example` describe an OpenSearch architecture** that was
   abandoned. The live stack is Athena-based (`docker-compose.agents.yml`). Ignore the
   OpenSearch ingestion-API sections when deploying the current app.
3. **`.env.s3` is the canonical env file** on the box (LLM keys + S3 + OTEL), not `.env`.

---

## Source control & deploy flow

- **Repo:** `bhnoc/NOCgentic` (private, GitHub). Local clone: `blackhat/NOCgentic`.
- **CI auto-deploy is live** (as of 2026-07-22): every push to `main` triggers
  `.github/workflows/deploy.yml`, which runs on a **self-hosted runner** on the AING box
  (label `nocgentic`). The runner polls GitHub *outbound*, so no inbound ports are opened.
  This is a **separate runner** from PostCog's (`postcog` label, `bhnoc/PostCog`) — one
  runner binds to one repo — but both live on the same box.
- The deploy step runs `ops/deploy.sh`: it rsyncs the git checkout into `/opt/bhasia/app`
  **preserving** `.env`, `.env.s3`, `node_modules/`, `venv/`, `*.log`, `.git/`, then
  refreshes IMDS creds into `.env.s3` and runs `docker compose ... up -d --build
  --remove-orphans`, then health-checks `https://127.0.0.1/health`. It **refuses to deploy
  if `.env.s3` is absent** — the box's `.env.s3` is authoritative and not in git.
- **The normal deploy is now just `git push origin main`.** Watch it with
  `gh run watch <id>` or `gh run list --branch main`.
- **Test before pushing to `main`** — main is the deploy branch. For LLM/model changes you
  can test the real module in a version-matched venv without a container rebuild (see the
  Gemini section in [[../ops/skill.md]]).
- The box (`/opt/bhasia/app`) was originally an **untracked** copy that drifted from git.
  If you hand-edit on the box, mirror it back into the repo or it's lost on next deploy.

### Runner health
```bash
gh api /repos/bhnoc/NOCgentic/actions/runners --jq '.runners[]|{name,status,labels:[.labels[].name]}'
# on the box: sudo /home/ubuntu/actions-runner-nocgentic/svc.sh status
#   systemd unit: actions.runner.bhnoc-NOCgentic.aing-nocgentic.service (runs as ubuntu, enabled on boot)
```
If the runner is offline, deploys queue until it's back:
`ssh ubuntu@aing.bhnoc.com 'sudo systemctl restart actions.runner.bhnoc-NOCgentic.aing-nocgentic.service'`.
Re-register with a fresh token (they expire):
`gh api -X POST /repos/bhnoc/NOCgentic/actions/runners/registration-token --jq .token`.

---

## Path A — Redeploy code to the existing instance (manual fallback)

**Preferred: just `git push origin main`** and let the runner deploy (above). Use this only
when the runner is down or you need to deploy off-main. Run from your **local machine** in
the repo root (the code lives locally; the box is a target).

```bash
# Needs the SSH key and the current IP (NOT the script default).
EC2_IP=$(AWS_PROFILE=VirtualPOC-users aws ec2 describe-instances \
  --instance-ids i-0430224b1ac82701e --region us-west-2 \
  --query 'Reservations[].Instances[].PublicIpAddress' --output text)

./scripts/deploy-agents.sh --ssh-key ~/.ssh/blackhat --ec2-ip "$EC2_IP"
# add --dry-run first to preview the rsync
```

What `deploy-agents.sh` does:
1. `rsync` the repo to `ubuntu@EC2_IP:/opt/bhasia/app` (excludes `.env`, `.env.s3`, `.git`, `node_modules`, venvs)
2. On the box: `scripts/refresh-env-creds.sh .env.s3` (see below), re-seed S3, then
   `docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d --build --remove-orphans`
3. Poll `https://EC2_IP/health` up to 12×5s until healthy

If the instance is stopped, start it first — see [[../ops/skill.md]].

### The IMDS credentials gotcha

Docker containers **cannot reach the instance metadata service** (169.254.169.254) to
pick up the IAM role, so they can't talk to Athena/S3 on their own. `refresh-env-creds.sh`
pulls **temporary** role credentials from IMDS and writes `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` into `.env.s3`. These **expire (~hours)** —
if agents start failing S3/Athena calls with auth errors, re-run it and recreate:

```bash
# on the box, in /opt/bhasia/app
bash scripts/refresh-env-creds.sh .env.s3
docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d
```

> Contrast with PostCog, which runs as a host systemd service (not a container) and so uses
> the instance role via IMDS directly — no cred injection. Different pattern, same box.

---

## Path B — From nothing (fresh instance)

Only when there is no instance, or you're rebuilding. Prereqs: `AWS_PROFILE=VirtualPOC-users`
(or `-admins` for provisioning), the `~/.ssh/blackhat` key, a Cloudflare API token for
the `bhnoc.com` zone, and the repo locally.

### 1. Launch the EC2 instance

Place it per the account's TME conventions. **Recommendation:** the app needs no GPU —
a `m7i.xlarge` (or similar CPU instance) starts instantly, costs ~10× less, and never
hits the GPU capacity wall the g6e does. Only keep g6e if something else on the box needs it.

- Attach the IAM instance profile with Athena/Glue/S3 (`blackhat-pope-dev-ec2-role`).
- Security group: SSH (22) from your IP, HTTPS (443) from the allow-list, HTTP (80) open
  (needed for the ACME HTTP challenge fallback and the →HTTPS redirect).
- Ubuntu AMI.

### 2. Configure the instance

```bash
ssh ubuntu@<IP>
# Docker + compose plugin
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker ubuntu   # re-login for group to take effect
sudo mkdir -p /opt/bhasia/app && sudo chown ubuntu:ubuntu /opt/bhasia/app
```

### 3. Sync code + env

- `rsync`/`deploy-agents.sh` the repo to `/opt/bhasia/app`.
- Create `.env.s3` on the box (it is **not** synced) with: `GEMINI_API_KEY`,
  `OPENROUTER_API_KEY`, `LLM_PROVIDER`, `GEMINI_MODEL`, `S3_BUCKET`, `S3_REGION`,
  `S3_PREFIX`, `ATHENA_*`, OTEL settings, `THOUSANDEYES_BEARER_TOKEN`, `AUDIT_*`.
  Then `bash scripts/refresh-env-creds.sh .env.s3` to inject AWS creds.

### 4. DNS

Point `aing.bhnoc.com` (Cloudflare A record) at the instance's public IP. **Re-point it
after every stop/start** — the IP is ephemeral (no Elastic IP attached).

### 5. TLS certificate (first issuance)

The stack uses certbot with the **`dns-cloudflare`** authenticator (DNS-01 challenge, so
the box needn't be publicly reachable during issuance). Renewal config already exists at
`/etc/letsencrypt/renewal/aing.bhnoc.com.conf` once issued.

```bash
# on the box — creds at /etc/letsencrypt/cloudflare.ini (dns_cloudflare_api_token=...)
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  -d aing.bhnoc.com --key-type ecdsa \
  --server https://acme-v02.api.letsencrypt.org/directory
```

nginx mounts `/etc/letsencrypt` read-only, so the cert is available to the container
immediately. (Renewal after this is covered in [[../ops/skill.md]].)

### 6. Bring up the stack

```bash
cd /opt/bhasia/app
docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d --build --remove-orphans
```

### 7. Verify

```bash
# on the box
docker compose -f docker-compose.agents.yml ps
curl -sk -o /dev/null -w "HTTP %{http_code}\n" https://127.0.0.1/ -H 'Host: aing.bhnoc.com'
# from an allow-listed IP
curl -s -o /dev/null -w "HTTP %{http_code}\n" https://aing.bhnoc.com/health
```

Expect HTTP 200 and a valid cert for `aing.bhnoc.com`.

### 8. Seed a demo day (between conferences)

If you're standing this up outside a live event, the "last 24h" views will be empty
because the capture data is frozen in the past. Seed a re-dated slice so the app looks
live — full procedure (driver, sizing, verification) is in [[../ops/skill.md]] under
"Seeding a re-dated demo day". TL;DR:
```bash
cd /Users/landbeforetime/Documents/dev/blackhat/NOCgentic
AWS_PROFILE=VirtualPOC-users python3 scripts/redate_slice.py
```

## Public endpoints (once up)

Verified route names (the app does **not** expose a bare `/api/v1/alerts` — that 404s):

| URL | Serves |
|-----|--------|
| `https://aing.bhnoc.com/` | Chat UI |
| `POST /api/v1/chat` | Submit a query → returns `{jobId}` (async) |
| `GET /api/v1/chat/:id` | Poll job result (`status`, `answer`, `agentUsed`, …) |
| `GET /api/v1/alerts/recent` | Last-24h alert feed (dashboard) |
| `GET /api/v1/alerts/status` | Alert cache/queue telemetry |
| `GET /ws` | WebSocket (live updates) |
| `GET /health` | Health check |
| `/bh/1337/thetraces/` | Audit/trace viewer (token-gated) |

Chat request body field is **`query`** (not `message`). See [[../ops/skill.md]] for a
copy-paste smoke-test loop and good default queries.

## Deploy checklist

- [ ] Instance running, IP known
- [ ] `aing.bhnoc.com` DNS points at current IP (Cloudflare)
- [ ] Code synced to `/opt/bhasia/app` (runner on push, or `--ec2-ip` for manual)
- [ ] `.env.s3` present + `refresh-env-creds.sh` run (creds not expired)
- [ ] Valid TLS cert for `aing.bhnoc.com`
- [ ] Self-hosted runner `aing-nocgentic` shows `online` (`gh api …/actions/runners`)
- [ ] `docker compose ... up -d --build` succeeded, all services up
- [ ] `https://.../health` returns 200 from an allow-listed IP
- [ ] Cost note: if GPU instance, remember it bills ~$3+/hr — stop when idle

## CI auto-deploy — how it's wired (2026-07-22)
- `.github/workflows/deploy.yml`: `on: push [main]` + `workflow_dispatch`,
  `runs-on: [self-hosted, nocgentic]`, `concurrency: deploy-nocgentic` (no racing deploys).
- `ops/deploy.sh`: rsync `--delete` from the runner checkout → `/opt/bhasia/app`, excluding
  `.env .env.* node_modules/ venv/ .venv/ dist/ *.log *.pid .git/ __pycache__` (keeps
  `.env.example`). Then refresh IMDS creds into `.env.s3`, `docker compose -f
  docker-compose.agents.yml --env-file .env.s3 up -d --build --remove-orphans`, prune
  dangling images, and poll `https://127.0.0.1/health` (12×5s). Refuses to deploy if
  `.env.s3` is missing.
- Runner: `/home/ubuntu/actions-runner-nocgentic`, systemd unit
  `actions.runner.bhnoc-NOCgentic.aing-nocgentic.service`, runs as `ubuntu` (in the `docker`
  group + passwordless sudo). Registered with label `nocgentic`. **Distinct** from the
  `postcog` runner at `/home/ubuntu/actions-runner` — same box, different repo.
