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
│   └── web-server/                # Fastify BFF + static UI (index.html, app.css, app.js, alertHints.js, huntCatalog.js)
│
├── threathunt-catalog/            # Hunt playbooks/skills (APE-743, reviewed APE-750) — Playbooks tab; see docs/hunt-catalog.md
│
├── agents/
│   ├── orchestrator/              # :8001 — classify, guardrails, route, output sanitiser
│   ├── alert-triage/              # :8003 — Athena alerts triage
│   ├── thousandeyes-analyst/      # :8004 — ThousandEyes network quality
│   ├── athena-hunter/             # :8005 — NL→SQL hunt (primary data-lake agent)
│   ├── deter/                     # :8006 — contained sessions; safe_pool.py is its whole data surface
│   └── shared/                    # llm_client, athena_client, response_cache, local_models, telemetry, scrubbers
│
├── nginx/                         # TLS + reverse proxy (template → nginx-ssl.conf on box)
├── ops/                           # Canonical deploy + test runner (CI uses these)
│   ├── deploy.sh
│   ├── run-tests.sh
│   └── model-supervisor/          # HOST-side llama-server start/stop (NOT a container)
├── lambda/                        # Athena refresh / materialized views (data pipeline)
├── tools/
│   └── audit-monitor/             # FastAPI swim-lane trace UI
├── scripts/                       # Helpers; deploy-agents.sh wraps ops/deploy.sh
├── infrastructure/scripts/        # Org/IAM setup only (no CloudFormation tree)
├── tests/                         # pytest + UI smoke helpers
├── docs/                          # SETUP, design history, security sweeps, Athena guides
└── .github/workflows/
    ├── test.yml                   # CI test coverage on PRs to main → ops/run-tests.sh
    └── deploy.yml                 # Deploy pipeline → ops/run-tests.sh → ops/deploy.sh
```

There is **no** `packages/agent-sdk` and no CloudFormation under `infrastructure/`.
`threat-hunter` was retired from routing in QA sweep 2 (intent `threat_hunter` remaps
to `athena_hunter`), but `agents/threat-hunter/` still exists on disk.

### Not every principal in the Manifold tenant comes from this compose file

Verified against the live inventory 2026-08-04. The tenant carries agent principals
this repo does not build, and anything reasoning about "the fleet" has to account
for them:

| Principal | What it is |
|---|---|
| `bhnocgentic-investigator` | Ours, but **not** in this repo or in compose. Runs out of `bench-lab` (`/home/ubuntu/bench-lab` on the box) and reaches Athena through an **MCP tool named `query_athena`** — its spans carry the full MCP envelope `{"name":"query_athena","arguments":{…}}`. |
| `bhnocgentic-threat-hunter` | Retired from routing, still emitting telemetry. |
| `bhnocgentic-deter` | In `agents/` and in compose, **not yet deployed** — the box runs 8 containers and deter is not among them. |

Two consequences worth internalising:

* **`agents/` is not the whole fleet.** A detection policy, a principal allow-list,
  or a "which agents exist" answer derived only from this directory will be wrong.
  `.MANIFOLD/gen_principals.py` reads the live inventory *as well as* `agents/`
  precisely because of this.
* **Manifold mints one tool entity per distinct `tool.name` string.** Because the
  investigator puts a whole JSON envelope in that field, 45 of the tenant's 51 tool
  entities are individual SQL payloads rather than one `query_athena` tool. If you
  add an MCP-fronted agent, stamp `tool.name` with the *tool name only*.

`agents/thousandeyes-analyst/requirements.txt` pins `mcp>=1.0.0` and the container
has `mcp 2.0.0` installed, but **nothing imports it** — the ThousandEyes path is
plain REST (`httpx` → `api.thousandeyes.com/v7`, stamped `thousandeyes.api`).
Unused dependency; do not infer an MCP transport from it.

---

## Technology Stack

### TypeScript / Node.js (web server)
- **Runtime:** Node.js 20 LTS
- **Framework:** Fastify
- **Validation:** Zod (`@bhnoc/shared` + route-local schemas)
- **UI:** Static `packages/web-server/static/` (`index.html` + `app.css` + `app.js` + `alertHints.js`)
- **Testing:** Vitest
- **Role:** Thin BFF — chat jobs, alert cache, WebSocket alert feed, static assets

### Python (agents)
- **Version:** Python 3.11+
- **Framework:** FastAPI + uvicorn
- **LLM:** `agents/shared/llm_client.py` (Gemini default; OpenRouter / local AQLight alternate)
- **Data:** `agents/shared/athena_client.py` (SELECT-only Athena)
- **Cache:** `agents/shared/response_cache.py` (Redis; finished answers, guardrails first)
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

Guardrails run first, then the Redis response cache, then the agent:
  quarantine (Manifold)  → deter :8006/deter (live pool reads OK), cover on failure
  kill-switch (admin)    → deter :8006/deter with live_ok=false, cover on failure
  restricted / refused   → cover (never cached)
  cache hit  → stored answer, paced to a random 2-5s total, no lane metadata
  cache miss → agent call → sanitise → cache write
```

**The kill-switch is the plug, not an agent toggle.** `live_data_killed()` is
checked once in `handle_query`, before classification — so ahead of every agent
branch AND every cache lookup. It was an athena-only check inside the athena
branch, which meant a killed platform still answered from alert-triage (Athena)
and thousandeyes-analyst (live TE API), and still served live-derived cache
hits. Killed traffic is answered by deter with `live_ok=false`, which forbids
live pool reads regardless of the agent's own `DETER_ATHENA_ENABLED` — "answer
from deter" and "no live data" are only compatible if the ban travels on the
request. Deter down, disabled, slow or screening its own answer away all degrade
to the canned cover, which matters most here: a kill switch that errors instead
of answering announces that it was thrown.

The web-server half of the plug (`services/alertCache.ts`) freezes the alert
feed, **drops the queued and already-emitted buffers** (they are live venue data
held in that process), serves `[]` from `/api/v1/alerts/recent`, and stops
refreshing from Athena. Its kill poll is sticky: only a *successful* check may
change the state, so an unreachable orchestrator can no longer un-pull the plug.
The flag is still wired as `athena_hunter` on `/admin/killswitch` — one name, so
the audit-monitor button and the feed freeze cannot drift apart. Covered by
`tests/python/test_killswitch.py` and `packages/web-server/test/alertCache.test.ts`.

`deter` is NOT a routable intent — no classification reaches it and it answers
only sessions Manifold has quarantined. It replaces refusal-shaped containment
with a real, on-topic answer built solely from `agents/deter/safe_pool.py`:
author-written, aggregate-only, parameterless statements over an allowlisted set
of tables. The caller's text picks *which* facet is read and never becomes part
of one. Every failure path — agent down, timeout, or its own output screen
rejecting the model's text — degrades silently to the same canned cover the
other guardrails serve, so `_COVER_RESPONSES` stays the single copy of that
prose. The admin kill-switch is its second caller (with live reads forbidden);
quarantine keeps them, because "this caller is hostile" and "the venue data is
off limits" are different events. See
[`docs/security/deter-agent.md`](docs/security/deter-agent.md).

Lane mode decides which lanes run at all: `hybrid` (race), `cloud`, or `local`.
`LANE_MODE` overrides `LANE_RACE`; empty derives from it. `LANE_SIDE_BY_SIDE=false`
keeps the race but cancels the loser and reports no lane surface. Both are changeable
at runtime from the ⚙ gear in the audit monitor, which is process state and reverts on
restart. Local mode **never** falls back to the cloud. See
[`docs/llm/lane-mode.md`](docs/llm/lane-mode.md).

Agent ports are **internal-only** (`expose:` in compose). Only nginx 80/443 is public.
Redis is `expose: 6379`, reachable only from the compose network.

`ops/model-supervisor/` runs on the **host**, not in compose, and is the only thing
that can start or stop a llama-server unit. The orchestrator names an allowlist key;
the host file decides the command. Never give a container the docker socket, host PID
namespace or an SSH key to do this instead.

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

> **CRITICAL RULE:** Always create a feature branch (`git checkout -b <branch-name>`) for any development work. **Never** work out of `main` directly or commit directly to `main`.

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
GET    /api/v1/config            # Public UI config (event label; starter-hint draw)
GET    /api/v1/catalog           # Hunt catalog index (+ /search, /match, /:id) — Playbooks tab
GET    /health                   # Health check
GET    /ws                       # WebSocket (alerts + job_update)
```

`/api/v1/config` also carries the welcome-banner chips: a fresh five-chip draw
from the 100-question pool in
`packages/web-server/src/services/starterHints.ts` on every request, always with
at least two network-quality questions (`MIN_NETWORK_QUALITY`) and spread across
sub-groups so five chips are five different angles. The chips in
`static/index.html` are the fallback for a failed fetch, not the live set — edit
the pool, not the markup. These are opening questions only; post-answer "Next
Steps" hints are still generated by the orchestrator.

Every chip in the pool has been clicked against the live app and its answer
read. Re-vet after any edit with `python bench/starter_hints_smoke.py` (add
`--queries-file` to try candidates before committing them). It flags cover
responses, refusals, thin/no-data answers, low confidence and lane mismatch;
`--judge-file` re-scores stored answers without re-querying the show network.
A chip is only good if the ANSWER is good — three of the original hundred were
silently guardrailed and ten got boilerplate that ignored the question.

**A chip that trips a guardrail is worse than no chip** — it renders, gets
clicked, and answers with a silent cover. So the pool may not contain the
restricted-zone words `_ZONE_RE` matches (`Registration`, `Tools` — "AI tools"
is the trap), the refusal patterns, or the off-topic phrases, and it names none
of our own vendors (monitored public destinations like AWS/Azure/Google are
fine). `packages/web-server/test/starterHints.test.ts` enforces all of that
against copies of the orchestrator's regexes; if you loosen a guardrail there,
loosen it here too.

The same rule reaches the alert feed: clicking a card opens a draggable detail
popup whose "Hunt From Here" chips are built at runtime from that alert's own
fields by `static/alertHints.js`. Because those chips are assembled from live
data rather than authored, the guardrail check runs per hint instead of once in
a test — `alertHintIsSafe()` drops any candidate carrying a restricted-subnet
address, a zone name, a refusal/off-topic phrase, or one of our vendor names, so
a hostile-looking alert yields fewer chips rather than chips that answer with a
cover. The alert *description* is never pasted into a chip for the same reason:
it is vendor prose. Covered by `test/alertHints.test.ts` (hint text) and
`tests/ui/alert-popup.mjs` (the popup itself, needs Chrome).

`/api/v1/catalog` serves `threathunt-catalog/` to the **Playbooks** tab and
the alert popup's Playbooks row. It is reference material for a person and is
**never forwarded to an agent or model** — the APE-750 review cleared the files
for distribution, not for a model's context, and this feature does not cross
that line. Detection output links to playbooks through one shared file,
`threathunt-catalog/finding-playbook-map.json`, read by both the web-server and
zeek-detector (its `playbooks` field). Each playbook's "Hunt this live" question
lives in that map and is guardrail-checked in `test/huntCatalog.test.ts` like
the starter pool. See [`docs/hunt-catalog.md`](docs/hunt-catalog.md).

Orchestrator (internal): `POST /query`, `GET /hints/:id`, `GET /lanes/:id`,
`GET /admin/killswitch`, `GET|DELETE /admin/cache`, `GET|POST /admin/lanemode`,
`GET /admin/models`, `POST /admin/models/{start,stop}` (all `/admin/*` behind bearer).

`/lanes/:id` serves the losing lane of the dual-provider race (cloud Gemini vs
local AQLight) so the UI can offer a swap. See
[`docs/llm/lane-race.md`](docs/llm/lane-race.md).

`/admin/cache` reports and purges the Redis response cache. The lookup lives after
every guardrail in `handle_query` on purpose, because the key is the query text
alone and entries are shared between callers. Do not move it earlier. See
[`docs/cache/response-cache.md`](docs/cache/response-cache.md).

`/admin/lanemode` and `/admin/models` back the ⚙ settings gear in the audit monitor.
Reading the panel takes the audit cookie; changing anything takes the admin bearer.
The model routes proxy to the host supervisor, which owns the allowlist. See
[`docs/llm/lane-mode.md`](docs/llm/lane-mode.md).

---

## Testing Strategy

1. **Unit** — web-server Vitest (`packages/web-server/test/`), Python tests under `tests/`
2. **Ops suite** — `ops/run-tests.sh` before deploy in CI
3. **Security** — documented in `docs/security/`; guardrail + restricted-range covers must stay silent (no leak strings)
4. **Detection policies** — `.MANIFOLD/` (gitignored, local). Five gates, all offline:

```bash
python3 .MANIFOLD/gen_principals.py --check           # principals.yaml matches agents/ + live inventory
python3 .MANIFOLD/sync_principals.py --check          # every policy matches principals.yaml
python3 .MANIFOLD/validate_policies.py                # Cedar parses; enums; fail-open lint
python3 .MANIFOLD/run_test_prompts.py --check-coverage # every policy has a live-fire case
python3 .MANIFOLD/test_policy_logic.py --strict-overlap
```

The last one is the real suite: per-clause fire/quiet cases plus fleet-wide sweeps
for fail-open reads, cross-policy overlap, a benign corpus built from the app's own
SQL, principal realism, per-principal anchoring, non-Agent principals, and
post-redaction reachability. `cedarpy` is required — there is a venv at
`.MANIFOLD/.venv`. Run it before any `upload_policies.py --apply`; the uploader
runs `validate_policies.py` only.

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
| Distributed traces | Manifold + S3 NDJSON under `corelight/dev/traces/` on prod (`TRACE_S3_PREFIX`; the code default is `nocgentic/traces`) |
| Admin swim lanes | audit-monitor UI |
| API / agent health | compose healthchecks + `/health` |
| Response cache | `bhnoc.orchestrator.cache_hits` / `cache_misses`; `GET /admin/cache` |
| Detection findings | Manifold `/api/management/v1/threats`; policies in `.MANIFOLD/policies/` |

**Manifold event analysis is LIVE as of 2026-08-04.** It produced 0 findings for
this tenant through July — that caveat is now obsolete and should not be repeated.
Findings accrue continuously, so a policy change lands immediately; existing
findings are *not* retroactively withdrawn when you fix the rule that raised them,
so judge a fix by whether `last_seen_at` stops advancing, not by the total count.
The two CANARY profiles (CUST-20/21) existed only to detect this activation. They
have done their job and now contribute ~2,800 findings of pure noise — disable them
via `PATCH mode=disabled` (a profile `DELETE` returns 403).

Key thresholds from ops practice: API error rate, agent latency, LLM token/cost metrics on spans (`bhnoc.tokens`, `bhnoc.cost.usd`).

Cache hit rate is the only cache signal that means anything: a hit is paced to look like a live answer, so latency graphs will not show it.

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

### 5. Manifold principal identity — the two bugs that shipped

**Symptom:** a detection policy either never fires, or fires on the entire
legitimate fleet. Both happened, a week apart, from the same root: guessing what
Manifold puts in `principal` instead of reading it off a real event.

1. **Identifier format.** Manifold identifies an agent as
   `<otel_service_name>/<span_name>`, e.g.
   `Agent::"bhnocgentic-athena-hunter/athena_hunter.generate_sql"` — **not** the
   bare service name. Policies anchored on the bare uid matched nothing; the three
   that *negate* on principal inverted and flagged the whole fleet.
2. **Principal type.** Principals are not all Agents. An `llm.request` carries a
   **Model** principal (`model://google/gemini-3.5-flash-lite`), an `api.request` a
   **Resource**. `!(principal in [Agent::"…"])` is trivially TRUE for a Model, so
   every negating rule fired on the fleet's own Gemini calls — 3,984 findings from
   policy 16 alone, ~40% of the tenant's entire threat volume, plus 2,507 more from
   the trace-escalation rule cascading off them.

**Fix, both baked into the tooling:** principal lists are generated
(`gen_principals.py`) and written into policies (`sync_principals.py --apply`) —
never hand-edited; and every negating rule carries a `principal is Agent &&` head
guard.

**Why the tests missed both:** the vectors used the same bare uid as the policies,
and the harness hardcoded `Agent::` principals. 259 cases were green against a world
model that did not exist. A test that shares the code's assumptions cannot falsify
them — pin to an external source of truth (the live inventory) and make the harness
able to build the events production actually emits. Both gates are mutation-tested.

### 6. Manifold API: security-profiles moved off the management base

**Symptom:** `list_existing()` returns empty, so every policy looks new and an
`--apply` would create a full set of duplicates alongside the real ones.

**Cause:** security-profiles are no longer under `/api/management/v1` — that gateway
404s them and its `openapi.json` no longer lists the route. They are served from
`/api/v1`. The list is also offset/limit paginated with the array under `profiles`,
not the cursor+`data` shape the other endpoints use.

**Fix:** `MANIFOLD_PROFILES_BASE` defaults to `/api/v1`; `list_existing()` treats a
missing `profiles` key as fatal rather than as "no profiles". Keep
`.MANIFOLD/management-api.yaml` in mind as a Jul-27 snapshot, not current truth.

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
*Last updated: 2026-08-04*
