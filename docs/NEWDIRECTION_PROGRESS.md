# New Direction Progress — S3-Based Architecture

**Date:** 2026-04-21
**Target:** Black Hat Asia 2026 NOC
**Status:** DEPLOYED — Full stack running on EC2 with Gemini 2.5 Flash + S3 instance-role access

---

## Architecture Pivot Summary

Migrated from OpenSearch-based data layer to **S3-direct** architecture. Agents now query NDJSON files in S3 instead of OpenSearch indices. This simplifies infrastructure (no OpenSearch cluster to manage) and aligns with the event pipeline where data is pushed directly to S3.

### Before (OpenSearch)
```
Data Sources → Ingestion API → OpenSearch → Agents query via DSL
```

### After (S3-Direct)
```
Data Sources → S3 bucket (NDJSON) → Agents query via boto3
```

---

## Infrastructure

### EC2 Instances

| Instance | IP | Region | Role | Status |
|----------|-----|--------|------|--------|
| Primary (new) | <EC2-PUBLIC-IP> | us-west-2 | Full stack deployment | Active |
| Singapore (backburner) | <EC2-PUBLIC-IP-SGP> | ap-southeast-1 | Potential alternate | Standby |

**SSH Access:** `ssh -i ~/.ssh/id_macmini ubuntu@<EC2-PUBLIC-IP>`

### S3 Buckets

| Bucket | Region | Purpose | Access |
|--------|--------|---------|--------|
| `bhasia-noc-data` | us-east-1 | Seeded synthetic data (170 events) | IAM user `bhasia-noc-s3-readonly` |
| `blackhatnoc` | (TBD) | EC2 direct access — no credentials needed | EC2 instance role |

> **ACTION NEEDED:** Reconcile which bucket to use as primary. The EC2 at <EC2-PUBLIC-IP> has direct instance-role access to `blackhatnoc` (no IAM keys required). Consider switching `S3_BUCKET` to `blackhatnoc` and seeding data there instead, which would eliminate the need for AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY in .env.

**EC2 Direct S3 Usage (no credentials):**
```bash
# Upload logs
aws s3 cp /var/log/myapp.log s3://blackhatnoc/

# Sync a directory
aws s3 sync /var/log/corelight/ s3://blackhatnoc/corelight/

# List bucket contents
aws s3 ls s3://blackhatnoc/
```

---

## LLM Configuration

### OpenRouter (Current)
- **API Key:** Set in `.env.s3` as `OPENROUTER_API_KEY`
- **Models:**
  - Orchestrator: `anthropic/claude-3.5-sonnet` (routing/classification)
  - Threat Hunter: `anthropic/claude-3-haiku` (fast analysis)
  - Alert Triage: `anthropic/claude-3-haiku` (fast triage)

### Gemini (Primary — ACTIVE)
- **API Key:** Set in `.env` as `GEMINI_API_KEY`
- **Model:** `gemini-2.5-flash` (gemini-2.0-flash was deprecated for new users)
- **Status:** DEPLOYED and working as primary LLM backend
- **Fallback:** Auto-falls back to OpenRouter if Gemini key missing, and vice versa

---

## Services (Docker Compose)

5 containers defined in `docker-compose.agents.yml`:

| Service | Port | Description |
|---------|------|-------------|
| orchestrator | 8001 | Routes queries to specialist agents |
| threat-hunter | 8002 | Threat analysis via S3 data + LLM |
| alert-triage | 8003 | Alert severity triage via S3 data + LLM |
| web-server | 3000 (internal) | Fastify server, REST API, WebSocket |
| nginx | 80 (public) | Reverse proxy, security headers |

> Update 2026-07-24 (QA sweep 2): `threat-hunter` (8002) removed as orphaned. The stack later grew to add `athena-hunter`, `thousandeyes-analyst`, and `audit-monitor`; agent ports are now internal-only (`expose:`), with only nginx public. See `README.md` for the current service list.

---

## Files Changed (from OpenSearch baseline)

### New Files
- `agents/shared/s3_tools.py` — Drop-in replacement for opensearch_tools.py, reads NDJSON from S3 via boto3
- `agents/shared/llm_client.py` — **Unified LLM client** supporting Gemini and OpenRouter with auto-fallback
- `nginx/nginx-s3.conf` — HTTP reverse proxy config for the S3 architecture stack
- `scripts/seed-s3.py` — Generates and uploads 170 synthetic security events to S3
- `.env.s3` — Environment file for S3-based deployment
- `packages/web-server/static/index.html` — **Fully rewritten** with hacker conference theme

### Modified Files
- `agents/threat-hunter/main.py` — Import switched from opensearch_tools to s3_tools
- `agents/alert-triage/main.py` — Import switched from opensearch_tools to s3_tools
- `agents/shared/requirements.txt` — Added boto3>=1.34.0
- `docker-compose.agents.yml` — Removed OpenSearch, added S3/AWS env vars, added nginx

### Superseded (still exist, not used)
- `agents/shared/opensearch_tools.py` — Original OpenSearch query layer

---

## UI Theme

**Design:** Black void + ice blue, retro techno vibes for hacker conference

- **Fonts:** Orbitron (display), Share Tech Mono (mono/body)
- **Colors:** Pure black (#000000), ice blue palette (#1e90ff, #00d4ff, #60c8ff)
- **Effects:** CRT scanlines, vignette overlay, glitch animation on title hover, neon glow
- **Style:** Sharp 2px border-radius, all-caps labels, `//` separators, `>` prompt prefix
- **Alert cards:** Severity-colored left borders (critical=red, high=orange, medium=yellow, low=cyan, info=gray)

**Status:** Rewritten locally in `packages/web-server/static/index.html`. **NOT YET DEPLOYED** to EC2.

---

## Verified E2E Flow

Successfully tested the full pipeline:
1. Query submitted to orchestrator (port 8001)
2. Orchestrator classifies query and routes to specialist agent
3. Specialist agent loads relevant events from S3 (boto3)
4. Specialist builds prompt with telemetry context + user query
5. LLM (OpenRouter) generates analysis
6. Response returned with confidence score

Alert triage test returned 0.82 confidence with proper severity breakdown. S3 data loading confirmed (100 corelight + 50 paloalto events).

---

## Seeded Data in S3

Bucket `bhasia-noc-data` (us-east-1):

| Prefix | Events | Types |
|--------|--------|-------|
| corelight/ | 100 | 70 conn flows, 20 DNS, 10 notices |
| paloalto/ | 50 | Threat alerts with severity/category |
| partner/ | 20 | Auth, access, anomaly events |

Format: NDJSON files at `{prefix}/events-{timestamp}.ndjson`

---

## Completed (2026-04-21)

1. ~~Deploy updated UI to EC2~~ — DONE, hacker-themed UI live at http://<EC2-PUBLIC-IP>
2. ~~Resolve S3 bucket~~ — DONE, switched to `blackhatnoc` with instance-role access (no IAM keys)
3. ~~Integrate Gemini API~~ — DONE, unified `llm_client.py` supports Gemini + OpenRouter with auto-fallback
4. ~~Seed data to production bucket~~ — DONE, 170 events seeded to `blackhatnoc`
5. ~~Test full stack on EC2~~ — DONE, all 5 containers healthy, E2E query returns Gemini-powered triage report
6. ~~SSL/TLS~~ — DONE, Let's Encrypt cert issued via Cloudflare DNS-01, HTTPS live at https://aing.bhnoc.com (cert expires 2026-07-20, auto-renewal enabled)

## Remaining

1. **Additional agents** — Expand beyond threat-hunter and alert-triage (log-investigator, incident-responder per CLAUDE.md spec)
2. **Real data ingestion** — Connect actual Corelight/Palo Alto feeds to `blackhatnoc` bucket
3. **WebSocket streaming** — Wire up real-time streaming of LLM responses via WebSocket

---

## Environment Variables (.env)

```
OPENROUTER_API_KEY=<set>
GEMINI_API_KEY=<set>
LLM_PROVIDER=gemini
S3_BUCKET=blackhatnoc
S3_REGION=us-west-2
S3_PREFIX=
PORT=3000
NODE_ENV=production
```

> No AWS credentials needed — EC2 instance role provides S3 access.

---

*Last updated: 2026-04-21*
