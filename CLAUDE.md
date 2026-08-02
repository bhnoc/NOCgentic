# CLAUDE.md - AI-Powered SOC Platform Development Guide

## Project Overview

**Project Name:** NOCgentic - AI-Powered Security Operations Center Platform
**Target:** Black Hat NOC
**Live:** `https://ng.bhnoc.com`
**Architecture:** Multi-agent LLM SOC — thin Fastify BFF + four Python FastAPI agents + Athena data lake
**Languages:** TypeScript (web server / UI), Python 3.11 (agents), Bash (ops/deploy)
**Infrastructure:** Docker Compose on EC2, nginx TLS edge, AWS Athena/S3, Gemini via OpenRouter alternate

Canonical human overview: [`README.md`](README.md). This file is the day-to-day development guide for agents and contributors — keep it aligned with the live tree.

### Current AWS Environment

**AWS CLI Profile:** `nocgentic-deploy`

The `nocgentic-deploy` IAM user is configured for deployment-related AWS operations (org/IAM scripts under `infrastructure/scripts/`). Runtime Athena/S3 access on the box uses the **EC2 instance role** (do not freeze long-lived keys into container env — see Operational Gotchas).

```bash
aws sts get-caller-identity --profile nocgentic-deploy
```

> **Note:** Root credentials should ONLY be used for account-level operations that
> cannot be performed by IAM users (e.g., closing accounts, changing support plans).

---

## Security-First Development Principles

### CRITICAL: Security Requirements

1. **Never commit secrets** - All API keys, credentials, and sensitive data go in environment variables or AWS Secrets Manager
2. **Input validation everywhere** - All user input, API responses, and LLM outputs must be sanitized
3. **Principle of least privilege** - Every component gets minimum required permissions
4. **Defense in depth** - Multiple security layers, assume any layer can fail
5. **Audit everything** - All actions logged with timestamps and actor identification
6. **No secrets/PII to external LLMs** - Sanitize via `agents/shared/llm_sanitize.py` / `credscrub.py` before Gemini/OpenRouter

### Sensitive File Patterns (NEVER COMMIT)
```
.env*
*.pem
*.key
*credentials*
*secret*
config/local.*
nginx/nginx-ssl.conf   # rendered on-box from .template with ORIGIN_SECRET
```

---

## Project Structure (live)

```
NOCgentic/
├── CLAUDE.md                      # This file
├── README.md                      # Architecture + operator overview
├── package.json                   # npm workspaces: packages/*
├── docker-compose.agents.yml      # Full stack (agents + web + nginx + audit-monitor)
├── .env.example                   # Template → runtime `.env.s3` on the box
│
├── packages/
│   ├── shared/                    # @bhnoc/shared — Zod types (ChatQuery, AgentResponse, Alert)
│   └── web-server/                # Fastify BFF + static UI (index.html, app.css, app.js)
│
├── agents/
│   ├── orchestrator/              # :8001 — classify, guardrails, route, output sanitiser
│   ├── alert-triage/              # :8003 — Athena alerts triage
│   ├── thousandeyes-analyst/      # :8004 — ThousandEyes network quality
│   ├── athena-hunter/             # :8005 — NL→SQL hunt (primary data-lake agent)
│   └── shared/                    # llm_client, athena_client, telemetry, scrubbers
│
├── nginx/                         # TLS + reverse proxy (template → nginx-ssl.conf on box)
├── ops/                           # Canonical deploy + test runner (CI uses these)
│   ├── deploy.sh
│   └── run-tests.sh
├── lambda/                        # Athena refresh / materialized views (data pipeline)
├── tools/
│   └── audit-monitor/             # FastAPI swim-lane trace UI
├── scripts/                       # Helpers; deploy-agents.sh wraps ops/deploy.sh
├── infrastructure/scripts/        # Org/IAM setup only (no CloudFormation tree)
├── tests/                         # pytest + UI smoke helpers
├── docs/                          # SETUP, design history, security sweeps, Athena guides
└── .github/workflows/deploy.yml   # Deploy pipeline → ops/run-tests.sh → ops/deploy.sh
```

There is **no** `packages/agent-sdk`, no CloudFormation under `infrastructure/`, and no `threat-analyzer` / `log-investigator` / `incident-responder` agents. A former `threat-hunter` agent was removed (QA sweep 2); intent `threat_hunter` remaps to `athena_hunter`.

---

## Technology Stack

### TypeScript / Node.js (web server)
- **Runtime:** Node.js 20 LTS
- **Framework:** Fastify
- **Validation:** Zod (`@bhnoc/shared` + route-local schemas)
- **UI:** Static `packages/web-server/static/` (`index.html` + `app.css` + `app.js`)
- **Testing:** Vitest
- **Role:** Thin BFF — chat jobs, alert cache, WebSocket alert feed, static assets

### Python (agents)
- **Version:** Python 3.11+
- **Framework:** FastAPI + uvicorn
- **LLM:** `agents/shared/llm_client.py` (Gemini default; OpenRouter / local AQLight alternate)
- **Data:** `agents/shared/athena_client.py` (SELECT-only Athena)
- **Telemetry:** OpenTelemetry → Manifold + S3 span archive
- **Testing:** pytest (+ `ops/run-tests.sh` / `tests/`)

### Ops
- **Compose:** `docker-compose.agents.yml`
- **Deploy:** `ops/deploy.sh` (CI and on-box). `scripts/deploy-agents.sh` is a thin wrapper.
- **Shell:** Bash strict mode; ShellCheck where practical

---

## Coding Standards

### TypeScript Standards

```typescript
// ALWAYS use strict TypeScript
// Prefer Zod at API boundaries — use ChatQuerySchema from @bhnoc/shared for chat bodies
import { ChatQuerySchema } from '@bhnoc/shared';

function handleRequest(raw: unknown) {
  return ChatQuerySchema.parse(raw);
}
```

### Python Standards

```python
# ALWAYS use type hints + Pydantic for request/response models
from pydantic import BaseModel, Field

class AnalyzeRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)

# Sanitize before any LLM call
from llm_sanitize import sanitize_for_llm
```

### Bash Standards

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
# Quote variables; prefer ops/ scripts for deploy
```

---

## Security Implementation Guidelines

### 1. LLM Security (live path is Python)

LLM calls go through `agents/shared/llm_client.py`. Before calling the model, run
`sanitize_for_llm` (`agents/shared/llm_sanitize.py` → `credscrub` / `ipscope`).

Do not reintroduce a TypeScript LLM client — the removed `@bhnoc/agent-sdk` was unused scaffolding.

### 2. Input Validation

- Web: Zod on `/api/v1/chat` (`ChatQuerySchema`), rate limits, CSP headers in `httpSecurity.ts`
- Agents: Pydantic request models; Athena SQL sanitizer allows SELECT only
- Orchestrator: restricted-subnet / zone cover filters + guardrail intent (silent cover responses)

### 3. Audit / Telemetry

Spans via `agents/shared/telemetry.py` → Manifold OTLP + `s3_span_exporter.py`.
Admin UI: `tools/audit-monitor` (bearer + cookie auth behind nginx path).

---

## Agent Architecture

```
Browser
  ├─ HTTPS → nginx → web-server (:3000)
  │                    ├─ POST /api/v1/chat → orchestrator :8001/query
  │                    ├─ GET  /api/v1/alerts/* → athena-hunter (alert feed)
  │                    └─ WS   /ws (alert push; jobs also polled over HTTP)
  └─ nginx → audit-monitor (:8787) at /bh/1337/thetraces/

Orchestrator routes by intent:
  alert_triage          → alert-triage :8003/triage
  thousandeyes_analyst  → thousandeyes-analyst :8004/analyze
  athena_hunter         → athena-hunter :8005/analyze   (default)
  refused               → silent cover + hints
```

Agent ports are **internal-only** (`expose:` in compose). Only nginx 80/443 is public.

---

## Development Workflow

### Local / box development

```bash
# 1. Install Node workspaces
npm install

# 2. Env (never commit)
cp .env.example .env.s3   # or follow README for on-box secrets

# 3. Full stack
docker compose -f docker-compose.agents.yml up -d --build

# 4. Web-server only (dev)
npm run dev

# 5. Tests
npm test
bash ops/run-tests.sh     # fuller suite used by CI
```

Agent `main.py` files import shared code via Docker layout (`/app/shared`). For local Python without Compose, set `PYTHONPATH` to include `agents/` (or run inside the container).

### Git Workflow

```bash
git checkout -b feature/athena-hunter-sql-timeout
git checkout -b fix/chat-poll-race
git checkout -b security/rate-limiting

# <type>(<scope>): <description>
# Types: feat, fix, security, docs, refactor, test, chore
```

---

## API Design (live)

```
POST   /api/v1/chat              # Create chat job → orchestrator
GET    /api/v1/chat/:id          # Poll job status / result
GET    /api/v1/alerts/recent     # Alert sidebar feed
GET    /api/v1/alerts/status     # Alert cache / kill-switch status
GET    /api/v1/config            # Public UI config (event label, etc.)
GET    /health                   # Health check
GET    /ws                       # WebSocket (alerts + job_update)
```

Orchestrator (internal): `POST /query`, `GET /hints/:id`, `GET /admin/killswitch` (bearer).

---

## Testing Strategy

1. **Unit** — web-server Vitest (`packages/web-server/test/`), Python tests under `tests/`
2. **Ops suite** — `ops/run-tests.sh` before deploy in CI
3. **Security** — documented in `docs/security/`; guardrail + restricted-range covers must stay silent (no leak strings)

---

## Deployment

Canonical path (CI and on-box):

```bash
# On the nocgentic box / via GitHub Actions deploy.yml
APP_DIR=/opt/nocgentic/app bash ops/deploy.sh

# Compatibility wrapper (same thing):
./scripts/deploy-agents.sh
```

`ops/deploy.sh` rsyncs the checkout into `APP_DIR`, preserves `.env` / `.env.s3` / rendered `nginx-ssl.conf`, rebuilds compose, health-checks.

### Pre-deploy checks (practical)

- [ ] Secrets only in on-box `.env.s3` (not committed)
- [ ] `nginx/nginx-ssl.conf.template` changes understood (rendered at deploy)
- [ ] Rate limiting + Zod validation intact on chat
- [ ] LLM sanitization path unchanged for new agent code
- [ ] Agent ports remain unpublished

---

## Monitoring & Alerting

| Signal | Where |
|--------|--------|
| Distributed traces | Manifold + S3 NDJSON under `nocgentic/traces/` |
| Admin swim lanes | audit-monitor UI |
| API / agent health | compose healthchecks + `/health` |

Key thresholds from ops practice: API error rate, agent latency, LLM token/cost metrics on spans (`bhnoc.tokens`, `bhnoc.cost.usd`).

---

## Operational Gotchas (learned the hard way)

### 1. Nginx upstream caching after container recreate → 502 Bad Gateway

**Symptom:** A single path suddenly returns 502 ("connect() failed (111: Connection refused)" in nginx error log, pointing at a stale Docker bridge IP like `172.18.0.X`), while other paths still work.

**Cause:** `upstream name { server service:port; }` blocks resolve the service hostname to an IP *once* at nginx config-load time and cache it forever. When Docker Compose recreates that container it gets a new IP and nginx keeps hitting the old one.

**Permanent fix (already in nginx SSL config):** use Docker embedded DNS + variable `proxy_pass` (no sticky `upstream {}` blocks). Trailing-slash rewrite with variables needs an explicit `rewrite` — see audit-monitor location.

**Emergency recovery:** `docker restart` the nginx container flushes the cache; fix the config if it still uses `upstream {}`.

### 2. AWS credentials expiring mid-run on EC2 instance-role agents

**Symptom:** After ~6 hours, Athena/S3 calls return `ExpiredToken` / `InvalidToken`.

**Cause:** Env-var AWS keys frozen at container start, and/or a module-level cached `boto3.client()`.

**Permanent fix:**
- Do **not** set `AWS_ACCESS_KEY_ID` etc. in `docker-compose.agents.yml` for instance-role containers.
- Never cache the boto3 client at module level — create a fresh `boto3.Session().client(...)` per call.
- Canonical pattern: `agents/shared/athena_client.py::_get_athena()`.

### 3. Race between WebSocket `job_update` and HTTP poll → UI stuck on "Processing query"

**Symptom:** Fast cover/guardrail answers leave the UI on "Processing query…" forever.

**Cause:** WS `job_update` arrived before the first poll tick; older handlers cancelled the poll without rendering.

**Permanent fix (in `packages/web-server/static/app.js`):**
- `handleJobUpdate` renders when `status === 'done' | 'error'`.
- Both WS and poll paths use a `renderedJobs` Set — first wins, the other no-ops.

### 4. Deploy path

Use `ops/deploy.sh` (or `./scripts/deploy-agents.sh`, which execs it). Do not reintroduce a parallel rsync/compose script with custom `IFS` / `RSYNC_OPTS` word-splitting.

---

## Quick Reference Commands

```bash
# TypeScript
npm run dev              # Web-server watch
npm run build            # Build workspaces
npm run test             # Workspace tests

# Python / ops
bash ops/run-tests.sh
pytest                   # from tests/ or agent context

# Docker
docker compose -f docker-compose.agents.yml up -d --build
docker compose -f docker-compose.agents.yml logs -f
docker compose -f docker-compose.agents.yml down

# Deploy
APP_DIR=/opt/nocgentic/app bash ops/deploy.sh
```

---

## Contact & Resources

- **Live UI:** https://ng.bhnoc.com
- **AWS Console:** https://console.aws.amazon.com
- **OpenRouter Docs:** https://openrouter.ai/docs
- **Architecture detail:** [`README.md`](README.md)

---

*This document is the source of truth for development practices. Keep it updated with the live tree.*
*Last updated: 2026-08-02*
