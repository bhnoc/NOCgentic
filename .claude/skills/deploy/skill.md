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
| `orchestrator` | 8001 (internal) | Routes questions to the specialist agents |
| `alert-triage` | 8003 (internal) | Alert triage (Athena) |
| `thousandeyes-analyst` | 8004 (internal) | ThousandEyes network analysis |
| `athena-hunter` | 8005 (internal) | NL→SQL over the Corelight Athena tables |
| `audit-monitor` | 8787 (internal) | Token-gated trace viewer at `/bh/1337/thetraces/` |

Agent ports (8001-8005) are `expose:`-only, not published to the host; nginx (80/443) is the only public entry.

Backend data: **Athena** (`blackhat_pope_logs` DB, `blackhat-pope-dev` workgroup, `us-west-2`)
over Corelight logs in S3 (`blackhat-pope-dev-logs`). LLM: **Gemini** by default
(`GEMINI_MODEL`, provider selectable via `LLM_PROVIDER`, OpenRouter as fallback).

## Current deployed instance (as of 2026-07-22)

| Property | Value |
|----------|-------|
| Instance ID | `i-0430224b1ac82701e` (nickname **AING**) |
| Account | `552440750419` |
| VPC / Subnet | `vpc-06a6a29e7d0aecab3` / `subnet-076f03e8454c7bb70` (us-west-2a) |
| Type | g6e.4xlarge (GPU — **overspec'd**, the app is pure Athena/HTTP; see [[../ops/skill.md]]) |
| Region | `us-west-2` |
| Public IP | ephemeral — changes on every stop/start (currently `44.248.50.25`) |
| DNS | `aing.bhnoc.com` (Cloudflare zone) |
| IAM role | `blackhat-pope-dev-ec2-role` (has Athena/Glue/S3) |
| SSH | `ssh aing` (shorthand; = `ubuntu@aing.bhnoc.com` via the 1Password agent, biometric-gated) |
| Security groups | `sg-022b87911ecf12539` (`blackhat-asia-dev-sg`, the primary allow-list) + `sg-0a24a0bef5a92acca` (`aing-https-443-allowlist`, per-guest 443 rules) |
| App dir | `/opt/bhasia/app` |

### AWS access (read this before any `aws` command)

- **Profiles:** `VirtualPOC-users` for READS (describe/list), `VirtualPOC-admins` for
  WRITES to infra (security groups, `modify-instance-attribute`, launch/stop). Both SSO,
  both account `552440750419`. `bhasia-deploy` in the top-level CLAUDE.md is stale; it is
  not what this box uses.
- **If a token is expired:** `aws sso login --profile VirtualPOC-admins` (or `-users`).
  Just run it; it opens a browser and lands creds in-session.
- **PASS `--profile X --region us-west-2` AS FLAGS. Do NOT `export AWS_PROFILE`.** An
  exported var persists across shell calls in this harness and silently poisons later
  commands. A wrong/stale export makes correct by-ID lookups return
  `InvalidInstanceID.NotFound` / `InvalidVpcID.NotFound`, which reads as "the box moved
  accounts" when nothing moved. Every NotFound chase in this project has traced back to a
  stray export, not missing resources.
- **Ground truth when in doubt:** ask the box itself, not the API guesswork:
  `ssh aing 'TOK=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60"); curl -s -H "X-aws-ec2-metadata-token: $TOK" http://169.254.169.254/latest/dynamic/instance-identity/document'`
  returns the real account, region, instance ID, and AZ.

> Note: the box **also** hosts PostCog at `/home/ubuntu/PostCog` (systemd service). Different
> app; see its skills. Relevant here only because both have a process named `python app.py`
> — never `pkill -f app.py` on this host (see [[../ops/skill.md]]).

## Grant someone 443 access (per-guest allow-list)

Guest 443 rules live on their OWN SG (`sg-0a24a0bef5a92acca`, `aing-https-443-allowlist`),
attached alongside the primary `sg-022b87911ecf12539`, so adding/removing a guest never
touches the primary rules. To add a person, one command (WRITE → `-admins`, flags not
exports):

```bash
aws ec2 authorize-security-group-ingress --profile VirtualPOC-admins --region us-west-2 \
  --group-id sg-0a24a0bef5a92acca \
  --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=<IP>/32,Description="<name>"}]'
```

- **CIDR gotcha:** AWS does NOT reject a host-bit-set CIDR; it SILENTLY normalizes it to
  the network address. Send `66.205.200.65/29` and it stores `66.205.200.64/29` (the whole
  8-IP block `.64` to `.71`), not the single host. So confirm intent: a single host is
  `/32` (`.65/32`); a `/29` is always an 8-address range regardless of which host you
  typed. If someone hands you `x.x.x.65/29` and means one machine, they want `/32`.
- **Remove a guest:** same command with `revoke-security-group-ingress`.
- **List current guests:** `aws ec2 describe-security-groups --profile VirtualPOC-admins
  --region us-west-2 --group-ids sg-0a24a0bef5a92acca --query
  'SecurityGroups[].IpPermissions[].IpRanges[].[CidrIp,Description]' --output text`.
- This opens **443 only**. SSH (22) is a separate rule on the primary SG; don't assume it.
- **If the guest SG ever needs recreating** (fresh box): `create-security-group
  --group-name aing-https-443-allowlist --vpc-id vpc-06a6a29e7d0aecab3`, add the 443 rules,
  then `modify-instance-attribute --instance-id i-0430224b1ac82701e --groups
  sg-022b87911ecf12539 <new-sg>` (list BOTH, because `--groups` REPLACES the set: include
  the primary or you'll detach it).

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

## Local LLM on the GPU box (llama.cpp, optional; set up 2026-07-25)

The g6e.4xlarge has an **NVIDIA L40S (48GB, Ada)**. To run a local model instead of
the Gemini cloud baseline (air-gapped / no-cloud posture), set up the GPU + a local
OpenAI-compatible server and point the app at it with `LLM_PROVIDER=local`. The base
AMI ships with NO NVIDIA driver, so this is a one-time host setup:

```bash
ssh aing
# 1. NVIDIA driver + CUDA toolkit (kernel headers for the running -aws kernel are needed;
#    they were already present). The CUDA apt repo gives matched driver + toolkit.
cd /tmp && curl -fsSL -O https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb && sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nvidia-driver-610-open cuda-toolkit
sudo systemctl reboot        # REQUIRED: the module won't bind until a clean boot.
# After reboot (containers + runner auto-start, unless-stopped/enabled):
nvidia-smi                   # want: NVIDIA L40S, ~46GB, driver 610.x

# 2. Build llama.cpp with CUDA
sudo apt-get install -y cmake git libcurl4-openssl-dev
cd /home/ubuntu && git clone --depth 1 https://github.com/ggml-org/llama.cpp.git && cd llama.cpp
export PATH=/usr/local/cuda/bin:$PATH
cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=ON
cmake --build build --config Release -j"$(nproc)" --target llama-server llama-cli

# 3. Pull a model GGUF (llama.cpp's built-in -hf fetch; no python/HF-cli needed).
#    Shortlist (see docs/llm/local-model-research-2026-07-25.md): Qwen3-Coder-30B-A3B
#    (top), Qwen2.5-Coder-32B, Qwen3-32B. Apache 2.0, ~18-21GB at Q4_K_M/Q5, fit 48GB.
export LLAMA_CACHE=/home/ubuntu/models
# 4. Serve it (OpenAI-compatible on :8080), full GPU offload:
./build/bin/llama-server -hf unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF:Q4_K_M \
  -ngl 999 --host 0.0.0.0 --port 8080 --ctx-size 16384 &

# 5. Point the app at it (per-box env, NOT committed): in .env.s3 set
#    LLM_PROVIDER=local, LOCAL_LLM_BASE_URL=http://<host-or-docker-bridge>:8080/v1,
#    LOCAL_LLM_MODEL=<served name>. NOTE: agent containers reach the host via the
#    docker bridge, so use the bridge gateway IP or run llama-server in the compose
#    network, not localhost. Then recreate the stack.
```

- **Benchmark before switching:** `bench/` harness compares any provider/model vs the
  Gemini baseline on the 3 real tasks (NL->SQL, JSON classify, summarize). Capture the
  Gemini baseline first (`LLM_PROVIDER=gemini ... python bench/run_bench.py`), then the
  local model, then `bench/compare.py`. Expect a text-to-SQL accuracy trade vs cloud.
- **GBNF grammar** (llama.cpp) guarantees valid JSON for the classify path and single
  statement SQL: a bigger quality lever than model choice. Wire it once a model is picked.
- **Cost:** the GPU is the reason the box bills ~$3+/hr. Stop it when idle. `LLM_PROVIDER`
  is per-box, so a CPU host stays on `gemini`; only this GPU box uses `local`.

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

---

## level9000 services (branch `level9000`, added 2026-07-30)

The stack gained a `postgres` (pgvector/pgvector:pg16) container plus five internal FastAPI services
(`investigator` 8007, `triage` 8008, `memory` 8009, `hunter` 8010, `root-cause` 8006). They're all in
`docker-compose.agents.yml` and come up with the normal `docker compose ... up -d --build`. Extra deploy
notes:
- **Postgres has a named volume `pgdata`** — persistent across recreates. First deploy creates the DB;
  schema auto-migrates on service startup from `agents/shared/migrations/*.sql` (idempotent).
- Set `PG_PASSWORD` (and optionally `PG_USER`/`PG_DB`) in `.env.s3` for a non-default DB password;
  the service `PG_DSN` defaults line up with `postgres:5432/nocgentic`.
- `investigator`/`root-cause` use the existing `GEMINI_API_KEY`; no new secrets. `hunter`'s scheduler
  auto-runs (`HUNTER_AUTORUN=1` default) — set to `0` to keep it dormant until you want proactive hunts.
- Day-2 details (sweeps, traces, gotchas) live in [[../ops/skill.md]] under "level9000 services".

---

## Path C — Fresh show in a segmented tenant (Product Research, done 2026-07-30)

Standing up a NEW show (e.g. USA 2026) as an isolated, prod-tagged deployment in the
**Product Research** account (`104738328073`), fully segmented from the VirtualPOC AING box.
Because everything (bucket, catalog, box) lives in one account+region, the runtime is
**fully in-account** — no cross-account IAM, `refresh-env-creds.sh` works unchanged. This was
the "deploy nocgentic to product-research" migration. Bring the new box up 100% and validate
by raw IP BEFORE touching the old box or DNS.

### The USA 2026 deployment (reference values)

| Property | Value |
|----------|-------|
| Account | Product Research `104738328073`, profile `ProductResearch-admins`, SSO session `VirtualPOC` (role `104738328073_admins`) |
| Region | **us-east-2** (the `blackhatnoc` bucket is us-east-2 — Athena+Glue MUST match the data's region) |
| Instance | `i-0b278c0b3a38ebf69`, **g4dn.xlarge** (T4 16GB VRAM — AQLight needs only ~5GB, so T4 is right; NOT g6e) |
| Host tag / SSH | `Name=nocgentic`; `ssh nocgentic` (User `ubuntu`) via the **`product-research-key`** (1Password, Product-Research vault) — NOT the tme/blackhat key, NO AWS keypair |
| IP (raw-validation) | `3.142.124.50` (ephemeral; DNS not flipped yet) |
| VPC / Subnet | `vpc-0a618760a621ef4df` (`10.20.0.0/16`, isolated, no peering) / `subnet-07f30d798b0007635` (us-east-2a) |
| SG | `sg-0aed39f01f0526f85` (`nocgentic-sg`) — all-traffic from admin IPs only (James/Spicer/Spicer2), mirrors aing's model |
| IAM | role/profile `blackhatnoc-ec2-role` / `blackhatnoc-ec2-profile` (in-account S3+Athena+Glue+CW+SSM) |
| Data bucket | `s3://blackhatnoc/corelight/usa2026/` — layout `parquet/<table>/dt=…`, `raw/`, `traces/`, `athena-results/`, `models/` |
| Athena WG | `blackhatnoc-usa2026` (results → `…/athena-results/`) |
| **Glue DB** | **`blackhat_pope_logs`** — see the schema-name gotcha below; do NOT rename it |
| Tags (prod) | `Name`, `Project=blackhatnoc`, `User=james.pope@corelight.com`, `Purpose=siem`, `Environment=prod`, `Org=TME`, `Source=Claude`, `DestructionDate=permanent` on EVERY resource |

Bucket-prefix convention going forward: **`blackhatnoc/<partner>/<show>`** (this show =
`corelight/usa2026`). Each new show gets its own prefix + workgroup; the Glue DB name stays
`blackhat_pope_logs` (below).

### ⚠️ The #1 gotcha: keep the Glue DB named `blackhat_pope_logs`

AQLight (the fine-tuned NL→SQL model) and the app code (`agents/athena-hunter/main.py:141`
prompt, `agents/shared/athena_client.py` default) both emit/expect the schema name
**`blackhat_pope_logs`**. The model was fine-tuned on that schema, so it generates
`FROM blackhat_pope_logs.<table>` **regardless of the prompt or `ATHENA_DATABASE`** — a
differently-named DB yields `SCHEMA_NOT_FOUND` and every athena-hunter query returns 0 rows
with confidence 0. Fix: **name the new account's Glue database `blackhat_pope_logs`** (the DB
name is internal plumbing, NOT an Argus-tagged resource — segmentation is preserved by the
bucket/VPC/SG/IAM/workgroup/tags). A different account+region means no collision with the
source. (First attempt used `blackhatnoc_usa2026_logs` and hit exactly this; renaming the DB
fixed it with zero code/retrain.)

### ⚠️ The #2 gotcha: partition projection, not the table Location

These tables use **Athena partition projection** (`projection.enabled=true`) with a table
Parameter **`storage.location.template`** (e.g. `s3://blackhat-pope-parquet/notice/dt=${dt}`).
Athena resolves partitions from THAT template, overriding `StorageDescriptor.Location` AND
making `MSCK REPAIR` irrelevant. When replicating the catalog you MUST rewrite BOTH the
`Location` and the `storage.location.template` Parameter, or queries silently read the OLD
bucket (→ `s3:ListBucket` AccessDenied on the source). 68 tables have this.

### Catalog replication recipe (boto3, both profiles)

1. `get_tables` from source `blackhat_pope_logs` (VirtualPOC/us-west-2): 68 EXTERNAL_TABLE + 3
   VIRTUAL_VIEW (`alerts`, `uid_lookup`, `fuid_lookup`).
2. For each external table: deep-copy, **strip** these keys or `create_table` rejects them —
   `DatabaseName, CreateTime, UpdateTime, CreatedBy, IsRegisteredWithLakeFormation, CatalogId,
   VersionId, IsMultiDialectView, FederatedTable, IsMaterializedView`. Rewrite
   `StorageDescriptor.Location` AND `Parameters["storage.location.template"]` from
   `s3://blackhat-pope-parquet/<t>` → `s3://blackhatnoc/corelight/usa2026/parquet/<t>`.
   (`corelight_raw` is the exception: its data is in the dev-logs bucket under
   `bh-asia-26/corelight` → map to `…/usa2026/raw/corelight_raw`.)
3. **Views:** do NOT copy via `create_table` — the Glue view text is base64 in
   `ViewOriginalText`, so a `.replace()` on it doesn't take (you get `INVALID_VIEW: Schema
   'blackhat_pope_logs' does not exist` at query time, or with a renamed DB). Instead
   `SHOW CREATE VIEW <src>.<v>` on the SOURCE to get plain SQL, then `CREATE VIEW` in the new
   DB via Athena DDL. Watch for **unqualified** table refs (`uid_lookup`/`fuid_lookup` use
   `FROM conn` not `FROM db.conn`) → they resolve to `default` and fail; qualify them with the
   DB name. `alerts` is already fully qualified.
4. Athena `create-work-group --tags` wants **space-separated** `Key=..,Value=..` pairs
   (NOT comma-separated like other services) or it errors "Second instance of key Key".

### Moving the AQLight GGUF between boxes — use S3, not your laptop

The GGUF is 4.68GB. Routing aing→laptop→newbox via scp is bottlenecked by aing's uplink
(~13MB/min → hours). Instead: from aing, upload straight to the show bucket over the AWS
backbone, then the new box pulls it from S3 (in-region, seconds). aing has no PR creds, so
`aws configure export-credentials --profile ProductResearch-admins --format env-no-export`
locally, stream the blob into aing's shell over SSH (never write it to a transcript/file),
`aws s3 cp … s3://blackhatnoc/corelight/usa2026/models/athena-v3-q4_k_m.gguf`, then shred the
temp env file. New box (needs `aws` CLI — `sudo snap install aws-cli --classic`) pulls with
its instance role. Same trick works for a test-data slice, though a small slice is fine to
stage through the laptop.

### Test slice (prove the pipeline before real show data)

Copy ONE small `dt=` partition of `conn, dns, notice, suricata_corelight` (pick the smallest
day — `dt=2026-04-21` was ~2.5GB, conn is ~90% of it). notice+suricata feed the `alerts`
view. Partition projection means **no MSCK needed** — a `WHERE dt='2026-04-21'` query just
works once the parquet is in place. Validate: `SELECT severity, COUNT(*) FROM
blackhat_pope_logs.alerts WHERE dt='…' GROUP BY severity` (view lights up), and an
athena-hunter chat query ("Top 5 source IPs by connection count on 2026-04-21?") → should
route to athena-hunter, AQLight generates SQL, returns real top-talkers at conf ~0.95.
NOTE: **alert-triage queries a today+yesterday window**, so a slice dated in the past returns
0 rows there — that's expected, not a fault; use athena-hunter with an explicit date to
validate, or run the redate driver for the dashboard's 24h views.

### GPU box setup order (Ubuntu 24.04, g4dn)

1. **user-data caveat:** `docker-compose-plugin` is NOT in Ubuntu's repos — it's in Docker's
   repo. A `set -e` user-data that `apt-get install docker.io docker-compose-plugin` ABORTS
   the whole script (docker.io never installs) but key-injection already ran, so SSH works
   and it looks half-done. Install Docker from the official repo post-boot (docker-ce +
   docker-compose-plugin). Keep key-injection FIRST in user-data so SSH always survives.
2. NVIDIA driver: `ubuntu-drivers autoinstall` gives the driver but **not** the CUDA toolkit.
   For the llama.cpp CUDA build you also need `cuda-toolkit` from NVIDIA's apt repo
   (`cuda-keyring` → `cuda-toolkit-12-6`). Driver needs a **reboot** to bind (also a pending
   kernel bump on fresh AMIs — one reboot covers both).
3. Build llama.cpp with `-DGGML_CUDA=ON` BEFORE the reboot is fine — the `nvcc warning:
   Cannot find valid GPU for '-arch=native'` (no GPU bound yet) is HARMLESS; the binary still
   offloads to the T4 after reboot (verified: 6.4GB VRAM in use under load). The built
   `llama-server` being ~18KB is normal (impl is in the shared lib).
4. `aqlight.service`: same ExecStart as aing but model at
   `/home/ubuntu/slm-athena/training/gguf/athena-v3-q4_k_m.gguf`, `--host 0.0.0.0 --port 8080
   -ngl 99 -c 8192 --alias AQLight`. Health: `curl -sf http://127.0.0.1:8080/health`.
   Write the unit via scp, NOT an SSH heredoc right after a `pkill` (the pkill can kill the
   parent shell before the heredoc's `tee` runs).

### .env.s3 for the new tenant

scp aing's `.env.s3` (secrets stay off the wire/transcript) and rewrite ONLY:
`S3_BUCKET=blackhatnoc`, `S3_PREFIX=corelight/usa2026`, `S3_REGION=us-east-2`,
`ATHENA_DATABASE=blackhat_pope_logs` (keep this name!), `ATHENA_WORKGROUP=blackhatnoc-usa2026`,
`ATHENA_REGION=us-east-2`, `AUDIT_BUCKET=blackhatnoc`, `AUDIT_PREFIX=corelight/usa2026/traces`,
`AUDIT_REGION=us-east-2`. aing's `.env.s3` relied on compose defaults for `ATHENA_*`/`AUDIT_*`
(pointing at us-west-2), so you must set them EXPLICITLY here. Then `refresh-env-creds.sh
.env.s3` (uses THIS box's instance role — in-account, no cross-account hop). The stale
AWS_* creds copied from aing are overwritten by the refresh.

### nginx needs a cert to start (raw-IP validation)

`nginx-ssl.conf` hard-references `/etc/letsencrypt/live/aing.bhnoc.com/{fullchain,privkey}.pem`
and nginx-alpine crash-loops on 443 without it. For raw-IP validation before DNS/real cert,
drop a **self-signed** cert at that path (`openssl req -x509 -newkey rsa:2048 -nodes -keyout
privkey.pem -out fullchain.pem -subj /CN=aing.bhnoc.com`). Then `curl -sk` by IP works. Real
Let's Encrypt cert is a cutover step.

### Cutover (deferred — do NOT do during standup)

- **Cloudflare token CAN create a new subdomain via API** (verified 2026-07-30): the token in
  aing's `/etc/letsencrypt/cloudflare.ini` has `Zone.DNS:Edit` on the `bhnoc.com` zone (id
  `2756c9c41af2aa986e54a50382bdeba0`) — it's what certbot uses for DNS-01. So a new
  `nocgentic.bhnoc.com` A record (or CNAME) is one API POST; no UI needed. `aing.bhnoc.com` is
  a plain A record → the old box's IP. Issue the new host's cert via the same DNS-01 flow.
- **Chatbot/Slack paging is NOT wired in Product Research** — creating an AWS Chatbot config
  needs a console OAuth to the Slack workspace (can't be done headless). SNS topic
  `prod-monitoring-alerts` (us-east-2) + the 5 `prod-nocgentic-*` alarms exist and fire to
  SNS; they just need a Slack/email subscription added later.
- Final hostname is James's call (keep `aing.bhnoc.com`, or a new name). Only flip DNS + tear
  down the old AING box once the new box is fully validated and the real cert is issued.

### Cutover DONE for USA 2026 (2026-07-30): nocgentic.bhnoc.com

- **DNS:** `nocgentic.bhnoc.com` A → `3.142.124.50`, created via the Cloudflare API using
  aing's token (zone `bhnoc.com` = `2756c9c41af2aa986e54a50382bdeba0`), `proxied=false`.
  Create/read the record with a `POST`/`GET` to `…/zones/<zid>/dns_records`. **IP is
  ephemeral** (no EIP) — re-point after any stop/start, same as aing.
- **TLS:** real Let's Encrypt cert via certbot `dns-cloudflare` DNS-01 on the box (copied
  aing's `/etc/letsencrypt/cloudflare.ini` over, `apt-get install certbot
  python3-certbot-dns-cloudflare`, `certbot certonly --dns-cloudflare -d nocgentic.bhnoc.com
  --key-type ecdsa`). Then `sed` `aing.bhnoc.com`→`nocgentic.bhnoc.com` in `nginx/nginx-ssl.conf`
  (server_name + both cert paths) and **`up -d --force-recreate nginx`** (bind-mount inode
  gotcha — reload no-ops). Verified HTTPS-by-name 200 with a valid cert.
- **UI "not connected" / RECONNECT after rename (found 2026-07-30):** the dashboard's
  connection pill keys on the **WebSocket** (`ws.onopen`→LIVE, `ws.onclose`→RECONNECT), and
  the web-server's `/ws` handler **rejects any handshake whose `Origin` header ≠
  `ALLOWED_WS_ORIGIN`** (closes 1008). That var (`packages/web-server/src/index.ts:24`)
  defaults to **`https://aing.bhnoc.com`** via `process.env.ALLOWED_ORIGIN`. On a renamed
  host the browser sends `Origin: https://nocgentic.bhnoc.com`, doesn't match → socket
  closed → UI shows RECONNECT while "API ONLINE" (HTTP polling has no origin check). **A curl
  WS test PASSES (101) because curl sends no `Origin`** — you must test WITH an `Origin:
  https://<newhost>` header to reproduce. Fix: set `ALLOWED_ORIGIN=https://nocgentic.bhnoc.com`
  in `.env.s3`, add `- ALLOWED_ORIGIN=${ALLOWED_ORIGIN:-https://aing.bhnoc.com}` to the
  web-server env block in compose (default keeps aing working), `up -d --force-recreate
  web-server`. This is the ONLY hardcoded `aing.bhnoc.com` default left in source — nginx
  server_name/cert paths (conf) and the trace bucket (`TRACE_S3_*`) are the other two rename
  points, both covered above.

## Path D — the auto-Glue-table ingestion Lambda (+ a dev dataset)

**"The Lambda that auto-builds Glue tables"** = **`blackhat-pope-athena-refresh`** (in VPOC;
in Product Research it's `blackhatnoc-athena-refresh[-dev]`). There are NO Glue crawlers/jobs
— this one Lambda IS the ingestion engine. EventBridge (`*-athena-hourly`) invokes it hourly.

What it does (handler `athena_refresh_lambda_v6.handler`, 370 lines, py3.12, 900s):
1. Lists log types present under the raw prefix for a date (files named
   `<logtype>_<YYYYMMDD>_<HH:MM...>+0800-<n>.log.gz`).
2. For each new type: `get_schema_from_raw` reads the `#fields` header line from the
   `corelight_raw` table, then `create_new_table` runs `CREATE EXTERNAL TABLE IF NOT EXISTS`
   with **partition projection** (all columns `string` except `ts DOUBLE`, plus a synthesized
   `ts_datetime`). **This is the auto-build.**
3. `incremental_load` does `INSERT INTO <table> SELECT <split(line, tab)…> FROM corelight_raw
   WHERE dt=… AND ts > watermark` → parquet. Per-log-type/day **watermark** JSON in S3 makes
   it idempotent + resumable. Dispatcher self-invokes one worker per log type (fan-out, never
   times out).

Event shapes: `{}` = today; `{"date":"2026-04-23"}` = one day; `{"start_date","end_date"}` =
range; `{"log_type","date"}` = single worker. **`corelight_raw` is the INPUT** and is NOT
auto-created — you must create it (single `line` string col, `TEXTFILE`, projection on `dt`,
pointing at the raw prefix). The dispatcher runs long (creates all ~60 tables synchronously
before fanning out) — a synchronous `lambda invoke` from the CLI will hit the 2-min tool
timeout, but the Lambda keeps running server-side; watch `aws logs tail` and the Glue table
count instead.

### It is ONE-DATASET-PER-DEPLOYMENT

Each deployment hardcodes (now via env) one raw prefix → one parquet location → one Glue DB,
separating data only by `dt` partition. So **dev and the show CANNOT share a Glue DB** (each
table has exactly one S3 location). Give them separate DBs + separate Lambda instances.

### Parameterized (pope-free) version — env vars

The original hardcodes VPOC names. The Product Research copy is env-driven (same code, no
"pope"): `REGION, S3_LOG_BUCKET, S3_LOG_PREFIX, S3_PARQUET_BUCKET, S3_PARQUET_PREFIX` (new —
prefix under the parquet bucket, empty = bucket-root like the original), `WATERMARK_PREFIX,
GLUE_DATABASE, ATHENA_WORKGROUP`. Two code spots also fixed: the table `s3_location` now uses
`S3_PARQUET_PREFIX`, and `get_existing_tables` filters on `loc.startswith(_PARQUET_BASE)`
(the original's `'dev-parquet' not in loc` hack was VPOC-specific). IAM role needs S3
(rw+list on the bucket), Athena (start/get), Glue (get/create table+partition),
`lambda:InvokeFunction` on ITSELF (fan-out), and logs.

### The DEV dataset (built 2026-07-30, for testing "all the things")

Fully self-contained test env, parallel to the show, in Product Research/us-east-2:
- **Data:** `s3://blackhatnoc/corelight/dev/` — `raw/<dt>/` (raw logs), `parquet/<table>/<dt>/`
  (Lambda output), `_watermarks/v6/`, `athena-results/`, `traces/`.
- **Catalog:** Glue DB **`blackhatnoc_dev_glue`**, workgroup **`blackhatnoc-dev`**.
- **Lambda:** `blackhatnoc-athena-refresh-dev` + EventBridge `blackhatnoc-athena-hourly-dev`
  (rate(1 hour), ENABLED). Role `blackhatnoc-athena-refresh-role`.
- **Slice:** a contiguous **14:00–17:00 (+0800) window of 2026-04-21** = ~1.32GB raw, 8,514
  files — a contiguous time window keeps ALL log types present (each window has every type).
  Loaded via aing (download w/ aing's VPOC role → upload w/ PR creds; a cross-account
  `s3 cp --recursive` with PR creds FAILS because it can't `ListBucket` the VPOC source).
- **Result:** Lambda auto-built **56 tables** and ingested — conn 4.2M rows, dns 2.7M. Then
  created the 3 views (`SHOW CREATE VIEW` from source, rewrite DB name + qualify bare
  `FROM conn` refs). **`uid_lookup` references `rdp`** which had no traffic in the window, so
  the Lambda never made that table → view creation fails with "Table rdp does not exist";
  fix = create an empty projected `rdp` table (it'll fill when RDP traffic appears).

### Glue DB naming per tenant (supersedes the earlier "keep blackhat_pope_logs" gotcha)

The AQLight schema-name problem is now fixed **in code**, so you can name the DB per-tenant
(`blackhatnoc_dev_glue`, `blackhatnoc_glue`, …) — no "pope" needed. `agents/athena-hunter/
main.py` `_sub_tokens()` rewrites AQLight's baked-in `blackhat_pope_logs.` prefix →
`ATHENA_DATABASE` (no-op when they're equal, so aing is unaffected). Also made the SQL-gen
prompt DB name and the two telemetry `db_name=` args use `ATHENA_DATABASE`. Set
`ATHENA_DATABASE`/`ATHENA_WORKGROUP`/`ATHENA_REGION` explicitly in `.env.s3`. Rebuild
athena-hunter after changing. (The earlier USA 2026 test used `blackhat_pope_logs` as a
workaround BEFORE this fix existed; those temp DBs were dropped.)

### Trace-exporter bucket bug (found + fixed 2026-07-30)

`agents/shared/s3_span_exporter.py` reads **`TRACE_S3_BUCKET`/`TRACE_S3_PREFIX`/`TRACE_S3_REGION`**
(separate from `AUDIT_*`!), defaulting to `blackhat-pope-dev-logs/bh-asia-26/aing-trace`. These
were NOT passed through `docker-compose.agents.yml`, so on any non-VPOC box every agent tried
to write traces to the VPOC bucket → `s3:PutObject AccessDenied` (non-fatal, but noisy). Fix:
added `TRACE_S3_*` passthrough (with old-bucket defaults, so aing is unaffected) to all 9
LLM/agent service env blocks in compose, and set them in `.env.s3` to the tenant bucket
(`blackhatnoc` / `corelight/dev/traces` / `us-east-2`). Traces now land correctly.

## Path E — Corelight log delivery endpoint + the real-show pipeline (built 2026-07-30)

### How Corelight delivers logs (this is "the endpoint")

There is **no HTTP ingest** — `docs/API_INSTRUCTIONS.md` describes the ABANDONED OpenSearch
design. Corelight delivers via **`aws s3 sync` with scoped IAM credentials** (per
`docs/NEWDIRECTION_PROGRESS.md`). In April they synced to
`s3://blackhat-pope-dev-logs/bh-asia-26/corelight/<date>/<logtype>_<date>_<time>.log.gz` —
**flat `.log.gz` files directly under a `<date>/` dir, no `raw/` subdir**. Their exporter is
given a BASE path and appends `<date>/<files>` itself; **we cannot change that**, so we match
it: base = `corelight/<partner>/<show>/`.

**What to hand Corelight** (stored in 1Password → **TME** vault →
`Corelight -> blackhatnoc USA2026 S3 uploader`):
- S3 destination: `s3://blackhatnoc/corelight/usa2026/` (their tool creates `<date>/` under it)
- Region `us-east-2`, IAM user `blackhatnoc-corelight-uploader`, access key + secret
- Command: `aws s3 sync /var/log/corelight/ s3://blackhatnoc/corelight/usa2026/ --region us-east-2`

**The uploader IAM user** (`blackhatnoc-corelight-uploader`, long-lived access key): inline
policy scoped to `corelight/*` ONLY — `s3:PutObject` on `arn:aws:s3:::blackhatnoc/corelight/*`,
`s3:ListBucket` on the bucket with `Condition StringLike s3:prefix corelight/*`, plus
`GetBucketLocation`. Verified live: write to `corelight/usa2026/` OK, write to `slackcapture/`
DENIED, list root DENIED. Rotate the key after the show. (Requested scope was the whole
`corelight/*` prefix even though we tell them `usa2026` — so nothing breaks if they land
elsewhere under corelight/.)

### The real-show ingestion pipeline (blackhatnoc_glue / usa2026)

Same engine as dev, adapted to Corelight's forced layout (raw at `corelight/usa2026/<date>/`,
NOT `raw/<date>/`):
- **DB** `blackhatnoc_glue`, **workgroup** `blackhatnoc-usa2026`.
- **`corelight_raw`**: location `s3://blackhatnoc/corelight/usa2026/`, projection template
  `.../usa2026/${dt}/`. Projection only expands `YYYY-MM-DD` dirs, so it never scans the
  sibling `parquet/` subdir — safe to co-locate raw and parquet under one prefix.
- **Lambda** `blackhatnoc-athena-refresh` (no `-dev`), env: `S3_LOG_PREFIX=corelight/usa2026`,
  `S3_PARQUET_PREFIX=corelight/usa2026/parquet` (parquet lands at
  `corelight/usa2026/parquet/<table>/dt=…`, distinct from the `<date>/` raw dirs),
  `WATERMARK_PREFIX=corelight/usa2026/_watermarks/v6`, `GLUE_DATABASE=blackhatnoc_glue`,
  `ATHENA_WORKGROUP=blackhatnoc-usa2026`. EventBridge `blackhatnoc-athena-hourly` (ENABLED).
- **Role** `blackhatnoc-athena-refresh-role` — its `InvokeSelf` policy lists BOTH the `-dev`
  and show function ARNs (fan-out self-invoke).
- **Smoke-tested** end-to-end 2026-07-30: staged a few dev raw files into
  `corelight/usa2026/2026-04-21/`, invoked the Lambda → it auto-built conn/dns/notice, wrote
  parquet to `corelight/usa2026/parquet/`, conn query returned 9.6M rows. Then **removed the
  smoke-test tables + parquet + raw + watermarks** so the show DB is pristine (`corelight_raw`
  only) for real data.

### Views wait for real data — do NOT pre-create stub tables

The Lambda's `CREATE TABLE IF NOT EXISTS` builds base tables from the `#fields` header only
when that log type's data arrives. The 3 derived views (`alerts`, `uid_lookup`, `fuid_lookup`)
reference base tables (`uid_lookup` needs conn/dns/http/ssl/files/notice/suricata_corelight/
ssh/**rdp**), so they can't exist until those tables do. **Do NOT create stub tables to make
the views resolve early** — the Lambda would skip your empty/wrong-schema stub (IF NOT EXISTS)
and the real `#fields` schema would never apply, silently breaking that table for the show.
Instead: after real data lands and the Lambda has built the base tables, run
**`/opt/bhasia/app/create_show_views.sh`** (staged on the box) to create the 3 views. If a
view's table (e.g. `rdp`) has no traffic yet, either wait for it or create a real projected
`rdp` table matching the Lambda's schema pattern (see dev notes above).

### Show cutover (when data is flowing)

The app currently points at the **DEV** dataset. To flip to the show: in `.env.s3` set
`ATHENA_DATABASE=blackhatnoc_glue`, `ATHENA_WORKGROUP=blackhatnoc-usa2026`,
`S3_PREFIX=corelight/usa2026`, `TRACE_S3_PREFIX=corelight/usa2026/traces`,
`AUDIT_PREFIX=corelight/usa2026/traces`, then rebuild athena-hunter/alert-triage/orchestrator
and run `create_show_views.sh`. The dashboard's 24h views need data dated ~today (redate, or
wait for live show traffic).
