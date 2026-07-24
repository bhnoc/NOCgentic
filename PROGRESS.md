# BH Asia 2026 NOC - Progress Log

This file tracks periodic progress summaries for the AI-Powered SOC Platform project targeting Black Hat Asia 2026 NOC.

---

## 2026-05-18 — After-Action Report & Documentation Review

### Accomplished

1. **After-Action Report Written**
   - Created `After-Action.md` — comprehensive debrief addressed to Manifold Security
   - Covers: platform architecture, OTel integration depth (high-level to trace-level), LangSmith OTEL bridge, S3 dual-export design, swim-lane dashboard, kill switch, and all challenges encountered
   - Documents the 72-hour proof-of-concept pivot after the project was nearly cancelled
   - Lays out four key requirements from Manifold for Black Hat Vegas:
     1. Seamless custom agent integration with full LLM/agent visibility
     2. Alert triggering and kill switch control via Manifold rulesets
     3. Administrative dashboard with real-time monitoring (reference: our custom swim-lane)
     4. Technical debrief on data Manifold observed from BH Asia telemetry
   - Describes the "Remote NOC" vision for Vegas — vendor floor, attendee-facing threat hunting

2. **Full Documentation Review**
   - Verified PROGRESS.md, MANIFOLD_INTEGRATION.md, README.md, CLAUDE.md, and docs/ are consistent with current codebase state
   - All existing docs remain accurate as of the 2026-04-23 deployment snapshot

### Current Project Status

**Platform:** Live at `https://aing.bhnoc.com/` (user) + `https://aing.bhnoc.com/bh/1337/thetraces/` (admin)

**Next milestone:** Black Hat USA 2026 (Vegas) — "Remote NOC" on vendor floor targeting attendee-facing interactive threat hunting

**Key open items for Vegas:**
- Manifold technical debrief on Asia telemetry data
- Manifold ruleset-driven kill switch integration (automated response)
- Scale testing for concurrent attendee load
- Red-team testing of guardrails for adversarial conference audience
- Decision on infrastructure scaling (multi-instance vs. container orchestration)

---

## 2026-04-23 — Live, hardened, and audited

**Live at:** `https://aing.bhnoc.com/` (user) + `https://aing.bhnoc.com/bh/1337/thetraces/` (admin audit, bearer-gated)

### Major shifts today

#### 1. Data plane: S3 raw Zeek → AWS Athena (Parquet)
- New `athena-hunter` agent (port 8005) — LLM-generated SQL against `blackhat_pope_logs` workgroup `blackhat-pope-dev`.
- `alert-triage` fully migrated off S3 raw-TSV onto Athena for sub-second triage queries.
- Shared `agents/shared/athena_client.py` — SELECT-only wrapper with date-partition helpers (fixed to cover every day in a multi-day range; previously only emitted first+last dates).
- SQL generation prompt now carries **verified column schema**:
  - Raw Zeek tables (`conn`, `dns`, `http`, `ssl`, `ssh`, `files`, `notice`, `suricata_corelight`, `weird`) → `id_orig_h`, `id_resp_h`, `id_orig_network_name`, etc.
  - Derived tables (`alerts`, `uid_lookup`, `fuid_lookup`) → `orig_h`, `resp_h`, `orig_network_name` (no `resp_network_name` on `alerts`).
  - `alerts.severity` is VARCHAR (`critical|high|medium|low|informational`) — never use `<`/`<=`; `suricata_corelight.alert_severity` is INT.
  - `suricata_corelight.service` replaces removed `suricata` table.
- **Common hunt patterns** embedded in SQL prompt: brute-force LIKE matrix, lateral movement zone-diff, beaconing/C2, file-org JOIN pattern, org-keyword triple-query (alerts + SSL SNI + GeoIP).
- Orchestrator → agent payload **no longer sanitizes internal IPs** — they're the investigation target in a SOC. Agent LLM boundary still strips secrets/passwords. Fixed: `WHERE id_orig_h = '[INTERNAL-IP]'` literal bug that was returning 0 rows for every internal-IP query.
- `athena_client.query_by_ip`, `query_dns`, `query_ssl`, `query_top_talkers` updated to use `id_orig_h`/`id_resp_h` (they were querying `orig_h` which only exists on derived tables).

#### 2. Routing overhaul + guardrails
- **LLM-first classifier** (Gemini Flash-Lite, `thinking_budget=0`, ~500 ms) replaces heuristic. Heuristic remains as fallback on classifier error.
- 4 intents instead of 3:
  - `alert_triage` — alerts / alarms / IDS / severity
  - `thousandeyes_analyst` — BGP / packet loss / latency / outages
  - `athena_hunter` — **default** for everything else (was `threat_hunter`, now renamed & broadened)
  - `refused` — guardrail for off-topic / prompt-injection / attack-facilitation / jailbreak
- Guardrail prompt + heuristic cover examples like: "write me a phishing email", "ignore previous instructions", "what is the capital of France", "how do I hack into a server".
- **Silent guardrail**: refused queries now receive the *exact same* generic "nothing actionable on that range" cover response as restricted-range queries, `agent_used=athena-hunter`, with 5 hunt hints. No words like `refused`/`guardrail`/`rephrase`/`off-topic` appear in output. Prevents fuzzing for what's filtered. Admin span still tagged `filter.guardrail=true`.
- 15/15 routing tests passing; 5/5 guardrail-leak probes produce zero leak strings.

#### 3. Restricted-range filter
- Input short-circuit: any query mentioning IP in `10.220.{12,13,14,15,150,152,153,154,199}.X` (the `12.0/22` + four /24s + `199.0/24`) or the zone names `Registration` / `Tools` skips all agents and returns a cover response in <10 ms, plus 5 hunt hints.
- Output sanitizer at orchestrator final stage: rewrites any leaked restricted IPs → `10.220.69.X` (preserves last octet so reports still link), `Registration`/`Tools` → `internal`. Applied recursively to `answer`, `data`, `hints`.
- Alert-feed sidebar scrubs the same patterns before WebSocket broadcast (`packages/web-server/src/services/alertCache.ts`).
- **Admin side is unfiltered** — span `query.text` stores the raw query; audit monitor shows real IPs + zone names so SOC ops retain full visibility.

#### 4. Model + latency
- Default swapped to **`gemini-3.1-flash-lite-preview`** (all agents + orchestrator) via `GEMINI_MODEL` env, cost-tracked at `(0.05, 0.20)` per 1 M in/out tokens.
- `thinking_budget=0` on Flash-Lite paths (Pro requires thinking, Flash-Lite tolerates 0 — was the cause of the earlier "Budget 0 is invalid" 500s).
- `max_tokens=4096` on analyst agents (up from 2000 — bumped after the Flash truncation incident).
- Typical latency: **5–15 s** for `athena-hunter` / `alert-triage`, **2–4 s** for `thousandeyes-analyst`, **<1 s** for cover / guardrail paths.

#### 5. User-facing web UI
- 6 curated starter prompts on landing, split between threat hunting + network quality (vendor names scrubbed).
- **Collapsible answer sections** — `Key Entities`, `Next Steps`, `Evidence`, `Recommended Actions` render as `<details>` with ▸/▾ chevrons.
- **Mobile (≤480 px / iPhone 12)**:
  - Grid shrinks to `50 / 1fr / 120 px` (header / chat / alert sidebar).
  - Alerts sidebar becomes **single rotating card** swapping every 3–5 s with slide-in animation. Stats row hidden.
  - Example chips, message bubbles, input, and code blocks all scaled + `overflow-wrap: anywhere`.
- **Vendor names in responses stripped** — agent system prompts forbid mentioning ThousandEyes / Corelight / Palo Alto / Suricata / etc.; hints regex-filter on output as belt & suspenders.
- **Silent vendor scrub on alert feed** — `ET INFO` / `ETPRO INFO` signature prefixes dropped, alert names deduped by `(signature, src_ip)` so the feed shows variety instead of 200 rows of the same ET INFO.
- **6 active alerts** now trickled every ~9 s from real Athena data (30-min refresh window, shuffled queue so consecutive alerts aren't all from the same IP).
- **Race-condition fix**: WS `job_update` and HTTP poll now coordinate via `renderedJobs` Set — whichever arrives first renders, the other no-ops. Previously the WS was cancelling the poll timer without rendering, leaving the UI stuck on "Processing query…" for sub-second cover responses.

#### 6. Session + client attribution
- Web server: `trustProxy: true` so `request.ip` honours nginx `X-Forwarded-For`.
- `bh_sid` HttpOnly cookie (30-day maxAge) set on first request by Fastify `onRequest` hook.
- Browser-side: localStorage-backed `bhnoc.client_id` sent as `X-Client-Session` header — survives cookie-only wipe; cookie survives localStorage-only wipe.
- Forwarded to orchestrator in request body as `client: {ip, user_agent, session_id, referer}` → set on the `orchestrator.query` span → flows to every downstream span and the S3 audit archive.

#### 7. Observability: Manifold OTel + S3 span archive
- Every agent runs `init_telemetry()` at startup — traces/metrics/logs exported to Manifold (`blackcap.app.manifoldsecurity.io:4318`) via OTLP-HTTP with bearer auth.
- **LangSmith OTEL bridge** (set `LANGSMITH_TRACING=true` + `LANGSMITH_OTEL_ENABLED=true` BEFORE LangChain import) → every `ChatGoogleGenerativeAI.ainvoke()` auto-emits GenAI spans with prompt, completion, token counts, finish reason.
- **S3SpanExporter** (new `agents/shared/s3_span_exporter.py`) — BatchSpanProcessor writes gzipped NDJSON batches to `s3://blackhat-pope-dev-logs/bh-asia-26/aing-trace/service=<svc>/dt=YYYY-MM-DD/hour=HH/…jsonl.gz`. Hive-partitioned for Athena queryability later. Running in parallel to Manifold exporter, zero impact on latency.
- Custom metrics: `bhnoc.tokens`, `bhnoc.cost.usd`, `bhnoc.llm.duration_ms` with `gen_ai.system` / `gen_ai.request.model` attrs.
- Every query now carries `client.ip` / `client.user_agent` / `client.session_id` attrs on the root span through to S3.

#### 8. Audit monitor (admin only)
- New service `tools/audit-monitor/` (FastAPI + SSE, Docker-deployed alongside the main stack).
- **Swim-lane dashboard** at `https://aing.bhnoc.com/bh/1337/thetraces/`:
  - 5 columns (orchestrator, threat-hunter, alert-triage, athena-hunter, thousandeyes-analyst)
  - Cards color-coded by kind: **LLM** (yellow), **athena** (purple), **agent** (cyan), **tool** (orange), **http** (green, off by default)
  - Each card shows a ≤300-char preview pulled from (priority order): LangSmith `gen_ai.prompt.N.content`, `sql.query`, custom `query.text`, or httpx `method + URL path`
  - Click-to-expand drawer with full attributes, including LLM prompt/completion, all GenAI fields, resource tags, events, raw JSON.
- **Bearer + cookie auth**: `POST /login` with shared token → HMAC-signed `bh_audit` HttpOnly cookie (24 h default). API calls accept `Authorization: Bearer <token>` header as well for scripts.
- **Data source**: polls S3 trace prefix every 2 s, parses gzipped NDJSON, broadcasts new spans over SSE. Preload on startup pulls last 5 min of spans so lanes are populated immediately on first connection.
- Admin side sees **unfiltered** queries, IPs, zone names (by design — SOC has full visibility even when users see scrubbed output).

#### 9. UI polish
- Cover responses include hunt hints so blocked queries still feel productive ("Show the highest-severity threats right now", "Top talkers by outbound bytes today", etc.).
- Defensive try/catch around `appendAgentMessage` — if any formatter throws, a `RENDER ERROR` bubble surfaces the exception instead of the UI hanging silently.
- Consecutive-fail counter on `pollJob` — aborts after 5 consecutive network errors with a "Lost contact with server" bubble instead of silent infinite loop.
- 30 s `AbortController` on outbound `POST /api/v1/chat` to prevent hung tabs.

### Stack at a glance
8 Docker containers on EC2 `aing.bhnoc.com`:
`orchestrator, athena-hunter, alert-triage, threat-hunter, thousandeyes-analyst, web-server, audit-monitor, nginx`.

> Update 2026-07-24 (QA sweep 2): `threat-hunter` removed (orphaned; the orchestrator never routed to it, and the `threat_hunter` intent maps to `athena_hunter`). Stack is now 7 containers. Agent ports 8001-8005 are internal-only (`expose:`); only nginx 80/443 is public.

### Known limitations
- `thousandeyes-analyst` has no live tests configured — returns honest "no active anomalies" for all probes.
- `threat-hunter` (S3) runs as parallel secondary on `athena_hunter` intent but Athena is always primary.
- `2026-04-23` partition has `remote_organization` populated with country codes (US/SG/FR) instead of org names — compensated by triple-query pattern (SSL SNI + alerts + GeoIP) so org queries still return results.
- The deploy script `scripts/deploy-agents.sh` has an IFS word-splitting bug that mangles `RSYNC_OPTS` — workaround is to rsync/compose directly.

### Verification (run today)
- 15/15 routing tests pass — including 5 guardrail probes (no leak words detected in any response)
- 6/6 starter-prompt smoke tests return actionable answers (NetSupport RAT C2 found, Registration Web→DB lateral detected, 27 Zoho TLS connections identified, etc.)
- `10.220.199.0/24` cover path returns in ~500 ms with hunt hints and no indication of filter
- S3 span archive verified populating every ~5 s at `s3://blackhat-pope-dev-logs/bh-asia-26/aing-trace/`
- Audit monitor serves live swim-lane view with real prompts/SQL visible

---

## 2026-04-20 (Update 8) - Gap Analysis: Code Complete, Deployment Pending

### Current Status: All Code Built — Not Yet Live on EC2

All four phases of planned software work are complete locally. The critical remaining work is **deploying to EC2** and resolving the **OpenClaw network access** issue.

---

### What Is Done ✅

| Area | Detail |
|------|--------|
| **AWS Infrastructure** | EC2 (<EC2-PUBLIC-IP>, ap-southeast-1), OpenSearch, Ingestion API, Nginx TLS, S3 backup, IAM, CloudWatch alarms |
| **Ingestion Endpoints** | `/v1/ingest/corelight`, `/v1/ingest/paloalto`, `/v1/ingest/partner-default` — all live and tested |
| **LLM Agents (local)** | Orchestrator (port 8001), Threat Hunter (8002), Alert Triage (8003) — Python + OpenRouter |
| **Web Server (local)** | TypeScript/Fastify chat UI on port 3000, proxied via Nginx at `/` |
| **Dockerfiles** | All 4 services Dockerized (orchestrator, threat-hunter, alert-triage, web-server) |
| **docker-compose.agents.yml** | All agent services wired with correct env vars and inter-service URLs |
| **Nginx routing** | `/v1/*` → ingestion-api; `/api/v1/chat`, `/api/v1/alerts`, `/ws`, `/` → web-server |
| **deploy-agents.sh** | rsync + remote `docker compose up -d --build` with health-check loop — ready to run |
| **OPENROUTER_API_KEY** | Set in `.env` — agents can call LLMs ✅ |
| **API Keys** | Corelight, PaloAlto, Partner keys generated (in PRIVATE_NOTES.md) |

---

### What Is NOT Done ❌

| Priority | Gap | Blocker / Owner |
|----------|-----|-----------------|
| **CRITICAL** | Agents not deployed to EC2 | Need to run `./scripts/deploy-agents.sh` — ready to go |
| **CRITICAL** | `OPENSEARCH_API_KEY` missing in `.env` | Need to set the OpenSearch internal auth key so agents can query data |
| **HIGH** | No real NOC data in OpenSearch | NOC data feed format/credentials not confirmed by board |
| **HIGH** | API keys not distributed | Corelight, PaloAlto, Partner teams not yet given their keys |
| **HIGH** | OpenClaw Security Analyst agent | Board can't reach `localhost:3100` from OpenClaw — need network decision (local vs. exposed) |
| **MEDIUM** | SNS email subscription unconfirmed | Board needs to click confirmation link in <BILLING-EMAIL> |
| **MEDIUM** | No DNS / friendly URL for attendees | Raw IP <EC2-PUBLIC-IP> — no domain name |
| **MEDIUM** | E2E test not run | Full attendee flow (chat query → orchestrator → OpenSearch → response) not validated |
| **LOW** | CI/CD pipeline | Planned (GitHub Actions) but not built |
| **LOW** | Security review | Planned but not done |

---

### Discussed But Not In Original Plan

| Item | Status |
|------|--------|
| OpenClaw Security Analyst agent | Requested by board — invite mechanism works, blocked on localhost:3100 network access |
| Synthetic data seed script | Built (`scripts/seed-opensearch.py`) — can populate OpenSearch for demos without real NOC data |

---

### Immediate Next Actions (Priority Order)

1. **Board decision needed:** How to access Paperclip from OpenClaw (local install vs. Tailscale vs. expose via ngrok)
2. **Board: provide OPENSEARCH_API_KEY** (or confirm OpenSearch is running without auth)
3. **Board: confirm SNS subscription** (check email for CloudWatch alert confirmation)
4. **Run deploy:** `./scripts/deploy-agents.sh` — deploys agents to EC2 (unblocked once OPENSEARCH_API_KEY is set)
5. **Distribute API keys** to Corelight, PaloAlto, Partners
6. **Confirm NOC feed** — format and credentials for live data ingestion

---

## 2026-04-19 (Update 7) - Full Infrastructure Complete

### Accomplished

1. **S3 Backup Bucket Created**
   - Bucket: `bhasia-data-backup-<ACCOUNT-ID-PRODUCTION>`
   - Region: `ap-southeast-1`
   - Encryption: AES256 (server-side)
   - Public access: fully blocked
   - Lifecycle policy: auto-delete all objects after 8 days

2. **IAM Role for EC2**
   - Role: `bhasia-data-server-role`
   - Instance profile: `bhasia-data-server-profile` (attached to EC2)
   - Permissions: S3 read/write to backup bucket, CloudWatch metrics/logs

3. **CloudWatch Alarms Created**
   - `bhasia-instance-status` — EC2 status check failure → SNS alert
   - `bhasia-cpu-high` — CPU > 80% for 15 min → SNS alert
   - `bhasia-network-in-high` — Network ingestion > 100MB/5min → SNS alert
   - SNS topic: `arn:aws:sns:ap-southeast-1:<ACCOUNT-ID-PRODUCTION>:bhasia-alerts`
   - Alert email: `<BILLING-EMAIL>` (pending subscription confirmation)

4. **Backup Automation Deployed**
   - Script: `/opt/bhasia/backup-to-s3.sh` (exports OpenSearch → S3 daily)
   - Cron: `0 2 * * *` (2 AM UTC daily)
   - Verified S3 access from EC2 instance: ✅

5. **Data Deletion Script Deployed**
   - Script: `/opt/bhasia/delete-all-data.sh`
   - Stops services, deletes OpenSearch volume, wipes S3 backup
   - 10-second countdown before execution

6. **Admin SSH Keys Added**
   - `<ADMIN-SSH-KEY>` key added to instance
   - `blackhat` key added to instance
   - Both keys documented in SETUP.md for future instances

### Current Infrastructure State (COMPLETE)

| Component | Status | Details |
|-----------|--------|---------|
| EC2 Instance | ✅ Running | `<INSTANCE-ID>`, `<EC2-PUBLIC-IP>` |
| OpenSearch | ✅ Healthy (green) | Docker, port 9200 (internal) |
| Ingestion API | ✅ Running | FastAPI, port 8000 (internal) |
| Nginx TLS | ✅ Running | Port 443 (public) |
| S3 Backup | ✅ Configured | `bhasia-data-backup-<ACCOUNT-ID-PRODUCTION>` |
| IAM Role | ✅ Attached | `bhasia-data-server-role` |
| CloudWatch Alarms | ✅ Active | 3 alarms, SNS alerts |
| Backup Cron | ✅ Running | Daily at 2 AM UTC |
| SSH Keys | ✅ Added | 2 admin keys on instance |

### Pre-Event Checklist

- [x] EC2 instance launched in ap-southeast-1
- [x] Docker and Docker Compose installed
- [x] OpenSearch container running
- [x] Ingestion API container running
- [x] Nginx with TLS configured
- [x] API keys generated (distribute to sources)
- [x] Health check verified
- [x] CloudWatch alarms configured
- [x] S3 backup bucket created

### Next Steps (Remaining)

1. **Distribute API keys** to data sources (Corelight, PaloAlto, Partners) — keys in `/tmp/bhasia-api-keys.txt`
2. **Confirm SNS email subscription** — check <BILLING-EMAIL> for confirmation link
3. **Build LLM agent layer** — query interface on top of OpenSearch (next major phase)

---

## 2026-04-19 (Update 6) - Data Platform Deployed & Operational

### Accomplished

1. **EC2 Data Server Launched (bhasia-production account)**
   - Instance: `<INSTANCE-ID>` (t3.large)
   - Public IP: `<EC2-PUBLIC-IP>`
   - Region: `ap-southeast-1`
   - Storage: 100GB gp3 EBS (encrypted)
   - AMI: Amazon Linux 2023

2. **Security Group Configured**
   - `<SG-ID>` (bhasia-data-sg)
   - Port 443/tcp from 0.0.0.0/0 (HTTPS ingestion)
   - Port 22/tcp from admin IP only

3. **Docker Stack Deployed**
   - **OpenSearch 2.11.0** - running healthy at localhost:9200
   - **Ingestion API (FastAPI)** - running at localhost:8000
   - **Nginx** - TLS termination at 0.0.0.0:443

4. **API Keys Generated** (stored in `/run/secrets/api_keys.json` on instance)
   - Corelight: `bhasia-cl-...`
   - PaloAlto: `bhasia-pa-...`
   - Partner (default): `bhasia-ptr-...`
   - ⚠️ Keys stored in `/tmp/bhasia-api-keys.txt` on local machine - distribute to sources

5. **Ingestion Verified**
   - Health endpoint: `https://<EC2-PUBLIC-IP>/v1/health` → ✅ `{"status":"healthy","opensearch":"green"}`
   - Corelight ingestion tested: ✅ 1 document ingested
   - PaloAlto ingestion tested: ✅ 1 document ingested
   - Stats endpoint working: ✅ Shows 2 docs across 2 indices
   - Auth rejection tested: ✅ Returns 401 on invalid key

### Ingestion Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://<EC2-PUBLIC-IP>/v1/health` | GET | Health check (public) |
| `https://<EC2-PUBLIC-IP>/v1/ingest/corelight` | POST | Corelight/Zeek events |
| `https://<EC2-PUBLIC-IP>/v1/ingest/paloalto` | POST | Palo Alto events |
| `https://<EC2-PUBLIC-IP>/v1/ingest/partner-default` | POST | Partner events |
| `https://<EC2-PUBLIC-IP>/v1/stats` | GET | Ingestion stats (auth required) |

All POST endpoints require `X-API-Key` header.

### Current State

- Data platform fully operational
- EC2 instance running in ap-southeast-1
- All Docker services healthy
- Ready to receive production data from sources

### Next Steps

1. Distribute API keys to data sources (Corelight, PaloAlto, Partners)
2. Configure CloudWatch monitoring/alarms on the instance
3. Begin building LLM agent layer (query interface on top of OpenSearch)
4. Set up S3 backup for raw event data
5. Create data deletion automation for post-event cleanup

---

## 2026-04-17 (Update 5) - IAM Admin User Configured & Portable

### Accomplished

1. **IAM Admin User Created**
   - User: `bhasia-deploy` (redacted)
   - Group: `BHAsiaAdmins`
   - Access Key: `<REDACTED-ACCESS-KEY>`

2. **IAM Policies Attached**
   - `BHAsia-AssumeRoleInMemberAccounts` - Assume OrganizationAccountAccessRole in member accounts
   - `BHAsia-OrganizationManagement` - Read organization structure
   - `BHAsia-CloudTrailS3Access` - Read CloudTrail logs

3. **AWS CLI Profile Configured**
   - Profile `bhasia-deploy` configured with new credentials
   - Default region: `ap-southeast-1`
   - Verified credentials work with `aws sts get-caller-identity`
   - Tested assume role into production account: SUCCESS

4. **Documentation Updated**
   - Updated CLAUDE.md to reflect new IAM user (removed root warning)
   - Added assume role instructions for deployment

5. **Portable Setup Command Created**
   - One-liner to configure AWS CLI on any new machine:
   ```bash
   # Credentials redacted — rotate key in IAM console and run: aws configure --profile bhasia-deploy
   ```

### Security Improvements

- **No longer using root credentials** for day-to-day operations
- IAM user follows least-privilege principle
- Credentials file deleted after CLI configuration
- Root credentials reserved only for account-level operations

### Current State

- IAM admin user operational
- AWS CLI configured with `bhasia-deploy` profile
- Ready to deploy infrastructure to member accounts
- Credentials portable to other development machines

### Next Steps

1. Deploy data server EC2 in bhasia-production account
2. Set up Docker containers (OpenSearch, Ingestion API)
3. Generate and distribute API keys to data sources
4. Test ingestion with sample Corelight/Palo Alto data

---

## 2026-04-17 (Update 4) - Data Platform Architecture Finalized

### Accomplished

1. **Data Platform Architecture Decision**
   - Selected **Option B: EC2 + OpenSearch Docker** for cost efficiency
   - Rejected OpenSearch Serverless (~$160/7 days) in favor of EC2 (~$25-35/7 days)
   - Single t3.large instance with 100GB gp3 EBS

2. **Data Requirements Documented**
   - Volume: ~50GB total (~10GB/day for 5 days)
   - Retention: 7 days, then complete deletion
   - Sources: Corelight (Zeek JSON), Palo Alto, Partners
   - Format: JSON (pre-sanitized by sources)

3. **Ingestion API Design**
   - Secure REST endpoint: `POST /v1/ingest/{source_type}`
   - API Key authentication per source
   - Optional IP allowlisting
   - Rate limiting per source
   - Nginx TLS termination

4. **SETUP.md Completely Rewritten**
   - Documented AWS Organization structure (completed)
   - Full data platform architecture diagram
   - Docker Compose configuration (OpenSearch, Ingestion API, Nginx)
   - Complete Python FastAPI ingestion implementation
   - OpenSearch index templates for security data
   - Sample queries for LLM agents
   - Deployment steps with actual commands
   - Security controls and network diagram
   - Post-event deletion checklist

### Architecture Summary

```
Sources (Corelight/PaloAlto/Partners)
         │
         ▼
    [Nginx TLS]
         │
         ▼
  [FastAPI Ingestion]
         │
    ┌────┴────┐
    ▼         ▼
[S3 Backup] [OpenSearch]
              │
              ▼
         [LLM Agents]
```

### Cost Estimate (7-Day Event)

| Resource | Cost |
|----------|------|
| EC2 t3.large | $13.30 |
| EBS 100GB gp3 | $2.03 |
| S3 Backup | $0.28 |
| Contingency | ~$10 |
| **Total** | **~$25-35** |

### Current State

- AWS Organization fully configured and operational
- Data platform architecture documented
- Ready to deploy data server infrastructure

### Next Steps

1. Create IAM admin user (stop using root)
2. Deploy data server EC2 in bhasia-production account
3. Set up Docker containers (OpenSearch, Ingestion API)
4. Generate and distribute API keys to data sources
5. Test ingestion with sample Corelight/Palo Alto data

---

## 2026-04-17 (Update 3) - AWS Organization Deployed

### Accomplished

1. **AWS Organization Setup Script Executed Successfully**
   - Organization: `<ORG-ID>`
   - Root: `<ROOT-ID>`

2. **Member Accounts Created**
   | Account | ID | OU |
   |---------|----|----|
   | bhasia-security | <ACCOUNT-ID-SECURITY> | Security |
   | bhasia-production | <ACCOUNT-ID-PRODUCTION> | Production |
   | bhasia-development | <ACCOUNT-ID-DEVELOPMENT> | Development |

3. **Organizational Units Created**
   - Security (<OU-SECURITY>)
   - Production (<OU-PRODUCTION>)
   - Development (<OU-DEVELOPMENT>)
   - Sandbox (<OU-SANDBOX>)

4. **Service Control Policies Active**
   - BHAsia-DenyRootUsage (<SCP-ID>)
   - BHAsia-RequireMFAForSensitive (<SCP-ID>)
   - BHAsia-DenyLeaveOrg (<SCP-ID>)
   - BHAsia-RegionRestriction (<SCP-ID>)

5. **Organization CloudTrail Deployed**
   - Trail: `bhasia-org-trail`
   - S3 Bucket: `bhasia-cloudtrail-<ACCOUNT-ID-MANAGEMENT>`
   - Multi-region, organization-wide

### Current State

- AWS Organization fully operational
- All member accounts created and in correct OUs
- SCPs enforcing security policies
- CloudTrail logging all API activity

---

## 2026-04-17 (Update 2) - Organization Script Refinement

### Accomplished

1. **Renamed project prefix from `bhnoc` to `bhasia`**
   - All resource names now use `bhasia-` prefix
   - Consistent naming for Singapore-based deployment

2. **Configured Singapore Region (ap-southeast-1)**
   - Primary region set to `ap-southeast-1`
   - Added region restriction SCP allowing only `ap-southeast-1` and `us-east-1` (for global services)

3. **Integrated Existing Accounts**
   - Script now references pre-created accounts:
     - `bhasia-security` → Security OU
     - `bhasia-production` → Production OU
     - `bhasia-development` → Development OU
   - Added `organize_existing_accounts()` function to move accounts to correct OUs

4. **Configured Alternate Contacts**
   - Billing: <BILLING-EMAIL>
   - Security: <SECURITY-EMAIL>
   - Operations: <OPS-EMAIL>

5. **Enhanced Security SCPs**
   - Added `BHAsia-RegionRestriction` SCP to enforce Singapore region
   - Allows global services (IAM, Organizations, Route53, CloudFront, etc.)
   - Prevents resource creation in unapproved regions

6. **CloudTrail Setup Now Active**
   - Organization-wide CloudTrail enabled (not commented out)
   - Logs stored in `bhasia-cloudtrail-{account-id}` bucket
   - Multi-region trail with log file validation

### Current State

- Accounts already created in AWS
- Script ready to configure organization structure, SCPs, and CloudTrail
- Alternate contacts configured

### Next Steps

1. Run `./setup-organization.sh --dry-run` to verify configuration
2. Execute script to apply organization settings
3. Create IAM admin user and stop using root credentials
4. Begin VPC and infrastructure setup in ap-southeast-1

---

## 2026-04-17 - Project Initialization

### Accomplished

1. **Project Documentation Setup**
   - Created comprehensive `CLAUDE.md` development guide covering:
     - Security-first development principles
     - Project structure definition
     - Technology stack (TypeScript, Python, Bash)
     - Coding standards with examples
     - Agent architecture design
     - API design specifications
     - Testing strategy
     - Deployment checklist

2. **AWS Organization Setup Script**
   - Created `infrastructure/scripts/setup-organization.sh`
   - Features:
     - Strict bash mode with comprehensive error handling
     - Dry-run mode for safe testing (`--dry-run`)
     - Root account safety warnings and confirmation prompts
     - Creates AWS Organization with all features enabled
     - Enables Service Control Policies (SCPs)
     - Creates Organizational Units: Security, Production, Development, Sandbox
     - Security SCPs included:
       - Deny root account usage in member accounts
       - Require MFA for sensitive operations (CloudTrail changes)
       - Prevent accounts from leaving organization
     - Organization-wide CloudTrail setup (commented out for safety)
     - Detailed logging to timestamped log files
     - Summary report with next steps

3. **Infrastructure Foundation**
   - Created `infrastructure/scripts/` directory structure
   - AWS CLI already configured (using root account temporarily)

### Current State

- Root account AWS CLI access configured (temporary, for org setup only)
- Organization setup script ready for review and execution
- No AWS resources created yet (script not executed)

### Next Steps

1. Review and customize email addresses in setup script
2. Run `./setup-organization.sh --dry-run` to preview changes
3. Execute organization setup
4. Create IAM admin user and stop using root credentials
5. Set up isolated development environment
6. Begin implementing core infrastructure (VPC, EC2, Docker)

### Security Notes

- Currently using root account credentials - TEMPORARY
- Must transition to IAM user/role after org setup
- All sensitive operations require explicit confirmation
- No secrets committed to repository

---

*Add new progress entries above this line, newest first*
