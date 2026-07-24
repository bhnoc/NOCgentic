# BHNOCgentic — System Design

**Black Hat Asia 2026 — AI-Powered SOC for Attendees**
**Region:** ap-southeast-1 (Singapore)
**Last updated:** 2026-04-20

> **Stale: historical design snapshot.** This describes the original OpenSearch-backed,
> three-agent design (orchestrator + threat-hunter + alert-triage) in ap-southeast-1. The
> platform has since moved to AWS Athena over S3 Parquet, added `athena-hunter` and
> `thousandeyes-analyst`, and **removed `threat-hunter`** (2026-07-24 QA sweep 2: it was
> orphaned; the orchestrator never routed to it). Agent ports are now internal-only; only
> nginx (80/443) is public. For current reality see `README.md`. Kept for design history.

---

## 1. Purpose

Give Black Hat Asia 2026 attendees a window into the NOC. Instead of watching traffic dashboards from behind glass, attendees can ask natural-language questions — "What are the top threat actors right now?", "Show me suspicious DNS activity in the last hour", "What's causing the most alerts?" — and get real answers drawn from live NOC data.

The system is self-contained on AWS. No login required. No local infrastructure dependencies. Attendees walk up, type a question, get an answer.

---

## 2. Design Principles

- **Standalone AWS-only.** No dependencies on local machines, or any external control plane. The entire system runs on AWS in ap-southeast-1.
- **Open kiosk.** No authentication. Any attendee can query the system without an account.
- **500 concurrent users.** Single t3.large EC2 is the current deployment target; can scale horizontally if needed.
- **$200/month budget.** Actual cost ~$25–35 for the 7-day event window.
- **LLM via OpenRouter.** Cost-optimized model routing. High-complexity agents use Claude Sonnet; simpler tasks use Haiku. Keys managed via `.env` on EC2.
- **No PII to external LLMs.** Internal IPs, credentials, and raw packet data are stripped before any LLM call.
- **Synthetic data fallback.** Until NOC feed credentials are confirmed, `scripts/seed-opensearch.py` populates realistic test data (Corelight flows, Palo Alto alerts, DNS events).

---

## 3. Architecture

### 3.1 High-Level

```
Attendee Browser
      │
      │  HTTPS (port 443)
      ▼
 ┌─────────────────────────────────────────────┐
 │              Nginx (TLS termination)         │
 │                                             │
 │  /v1/*        → Ingestion API (port 8000)   │
 │  /api/v1/chat → Web Server (port 3000)      │
 │  /            → Web Server (port 3000)      │
 └─────────────────────────────────────────────┘
      │
      ▼
 Web Server (Node.js / Fastify — port 3000)
      │  POST /query
      ▼
 Orchestrator Agent (Python / FastAPI — port 8001)
      │
      ├── threat_hunter intent ──► Threat Hunter (port 8002)
      │                                └── OpenSearch
      │
      ├── alert_triage intent  ──► Alert Triage  (port 8003)
      │                                └── OpenSearch
      │
      └── direct intent ─────────► OpenRouter (no live data)
             │
             ▼
         OpenRouter API
         (anthropic/claude-3-5-sonnet for orchestration,
          anthropic/claude-3-haiku for specialists)


NOC Data Sources
      │
      │  HTTPS + X-API-Key
      ▼
 Ingestion API (FastAPI — port 8000)
      ├── /v1/ingest/corelight     → corelight-events index
      ├── /v1/ingest/paloalto      → paloalto-events index
      └── /v1/ingest/partner-default → partner-events index
            │
            ▼
       OpenSearch (port 9200, internal)
            │
            ▼
       S3 (daily backup at 2 AM UTC)
```

### 3.2 EC2 Instance

| Field | Value |
|-------|-------|
| Instance ID | <INSTANCE-ID> |
| Type | t3.large |
| Public IP | <EC2-PUBLIC-IP> |
| Region | ap-southeast-1 |
| OS | Amazon Linux 2023 |
| Storage | 100GB gp3 EBS (encrypted) |
| IAM Role | bhasia-data-server-role |

All services run as Docker containers managed by two compose files:
- `docker-compose.yml` — OpenSearch + Ingestion API + Nginx (original infra layer)
- `docker-compose.agents.yml` — Orchestrator + Threat Hunter + Alert Triage + Web Server

### 3.3 AWS Organization Structure

```
Management Account (root)
└── bhasia-security   (<ACCOUNT-ID-SECURITY>)  — Security OU
└── bhasia-production (<ACCOUNT-ID-PRODUCTION>)  — Production OU  ← EC2 lives here
└── bhasia-development (<ACCOUNT-ID-DEVELOPMENT>) — Development OU
```

SCPs enforce: no root usage in member accounts, MFA required for sensitive ops, region restriction to ap-southeast-1 + us-east-1, deny leaving org. CloudTrail org-wide.

---

## 4. Agent Pipeline

### 4.1 Query Flow

1. Attendee types a question in the chat UI.
2. Web server forwards to Orchestrator via `POST /query`.
3. Orchestrator uses `claude-3-5-sonnet` to classify intent:
   - `threat_hunter` — IOC lookups, suspicious IPs/domains/hashes, threat intel
   - `alert_triage` — alert summaries, severity scoring, firewall events
   - `direct` — general SOC questions answered without live data
4. For threat_hunter / alert_triage, Orchestrator calls the relevant specialist.
5. Specialist queries OpenSearch, sends results to its LLM (`claude-3-haiku`), returns analysis.
6. Response streams back to the browser.

### 4.2 Agents

| Agent | Port | Model | Role |
|-------|------|-------|------|
| Orchestrator | 8001 | claude-3-5-sonnet | Intent classification + routing + direct fallback |
| Threat Hunter | 8002 | claude-3-haiku | IOC search, suspicious pattern detection |
| Alert Triage | 8003 | claude-3-haiku | IDS/IPS alert scoring, response suggestions |

**Deferred (not yet built):**

| Agent | Role | LLM Tier |
|-------|------|----------|
| Traffic Analyst | Flow patterns, anomaly detection, top talkers | GPT-4o-mini |
| Intel Lookup | IP/domain/hash enrichment (VT, Shodan, AbuseIPDB) | Llama 3 8B |
| Explainer | Attendee-friendly educational summaries | Llama 3 8B |

### 4.3 OpenSearch Tools (agents/shared/opensearch_tools.py)

Six async query functions available to all agents:

| Function | Index | Purpose |
|----------|-------|---------|
| `query_alerts` | paloalto-events | Recent IDS/IPS alerts by severity |
| `query_flows` | corelight-events | Network flow records |
| `query_dns` | corelight-events | DNS query/response activity |
| `enrich_ip` | all | All events involving a specific IP |
| `get_top_talkers` | corelight-events | Highest-traffic src/dst pairs |
| `search_events` | all | Full-text search across all indices |

When `OPENSEARCH_INTERNAL_URL` is set (EC2 deployment), agents query OpenSearch directly on port 9200 over the internal Docker network — no auth token required. The `OPENSEARCH_API_KEY` env var is optional and only used if present.

---

## 5. Data Layer

### 5.1 Ingestion Endpoints

All require `X-API-Key` header.

| Endpoint | Source | Index |
|----------|--------|-------|
| `POST /v1/ingest/corelight` | Zeek/Corelight JSON | corelight-events |
| `POST /v1/ingest/paloalto` | Palo Alto NGFW | paloalto-events |
| `POST /v1/ingest/partner-default` | Partner feeds | partner-events |
| `GET /v1/health` | — | Health check (no auth) |
| `GET /v1/stats` | — | Ingestion stats (auth required) |

### 5.2 API Keys (in PRIVATE_NOTES.md)

| Source | Key prefix |
|--------|------------|
| Corelight | bhasia-cl-... |
| Palo Alto | bhasia-pa-... |
| Partner (default) | bhasia-ptr-... |

Keys have not yet been distributed to those teams.

### 5.3 OpenSearch Indices

Event schema (common fields across all indices):

```json
{
  "timestamp": "ISO 8601",
  "src_ip": "string",
  "dst_ip": "string",
  "proto": "string",
  "event_type": "string",
  "severity": "low|medium|high|critical",
  "source": "corelight|paloalto|partner-default",
  "raw": "original event object"
}
```

### 5.4 NOC Data Feed (not yet connected)

The NOC data format and credentials have not been confirmed. Until they are, the synthetic data seed script provides realistic test data:

```bash
python scripts/seed-opensearch.py
# Seeds 170 synthetic events: Corelight flows, Palo Alto alerts, DNS events
```

### 5.5 Backup

- Script: `/opt/bhasia/backup-to-s3.sh` — exports OpenSearch to S3 daily
- Bucket: `bhasia-data-backup-<ACCOUNT-ID-PRODUCTION>`
- Schedule: 2 AM UTC
- Retention: 8 days (auto-delete lifecycle)

---

## 6. Web Interface

### 6.1 Chat UI

Single-page app served from `packages/web-server/static/index.html`. Dark theme, SOC aesthetic.

- Text input for natural language queries
- Response panel with streaming output
- Live alert feed (WebSocket connection to `/api/v1/alerts`)

### 6.2 API Routes (Web Server)

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Serve chat UI |
| POST | `/api/v1/chat` | Submit query to Orchestrator |
| GET | `/api/v1/alerts` | Recent alerts from OpenSearch |
| GET | `/health` | Service health check |
| WS | `/ws` | WebSocket for live updates |

---

## 7. Security Model

**Ingestion API:** API key per source. Nginx enforces TLS. Keys rotate post-event.

**LLM prompt safety:** Before any query goes to OpenRouter:
- Internal IPs (RFC 1918) are redacted
- Credentials and secrets are stripped
- Max query length enforced (5000 chars)
- No raw packet capture data forwarded

**Infrastructure:**
- SCPs block root usage in production account
- CloudTrail logging all API calls
- CloudWatch alarms: CPU > 80%, network > 100MB/5min, instance status failure
- SNS alerts → <BILLING-EMAIL> (pending subscription confirmation)
- EBS encrypted at rest
- Security group: only 443 public; 22 from admin IP only

**Post-event:** `/opt/bhasia/delete-all-data.sh` — stops services, deletes OpenSearch volume, wipes S3. 10-second countdown before execution.

---

## 8. Deployment

### 8.1 Environment Variables (.env on EC2)

```
OPENROUTER_API_KEY=sk-or-v1-...         # Set ✅
OPENSEARCH_INTERNAL_URL=http://opensearch:9200  # Docker internal
OPENSEARCH_API_URL=https://<EC2-PUBLIC-IP>
OPENSEARCH_API_KEY=                      # Optional (OpenSearch runs without auth internally)
PORT=3000
NODE_ENV=production
ORCHESTRATOR_URL=http://orchestrator:8001
THREAT_HUNTER_URL=http://threat-hunter:8002
ALERT_TRIAGE_URL=http://alert-triage:8003
```

### 8.2 Deploy Agents to EC2

Run from a machine with SSH access (requires `~/.ssh/blackhat` key):

```bash
cd BHNOCgentic
./scripts/deploy-agents.sh
# or with explicit key:
./scripts/deploy-agents.sh --ssh-key ~/.ssh/blackhat --ec2-ip <EC2-PUBLIC-IP>
```

The script: rsync code → EC2, `docker compose up -d --build`, health-check loop, summary.

### 8.3 Seed Test Data

```bash
# On EC2 or locally with OPENSEARCH_API_URL set:
python scripts/seed-opensearch.py
```

---

## 9. Cost Model

| Resource | Cost (7-day event) |
|----------|-------------------|
| EC2 t3.large | ~$13.30 |
| EBS 100GB gp3 | ~$2.03 |
| S3 backup | ~$0.28 |
| OpenRouter LLM | ~$5–10 (est. for event volume) |
| Misc (CloudWatch, data transfer) | ~$5 |
| **Total** | **~$25–35** |

Well within the $200/month budget.

---

## 10. Open Items

| Priority | Item | Owner |
|----------|------|-------|
| CRITICAL | Deploy agents to EC2 — run `deploy-agents.sh` | Board (needs SSH key) |
| HIGH | Confirm NOC data feed format + credentials | Board / Black Hat NOC team |
| HIGH | Distribute API keys to Corelight, Palo Alto, Partners | Board |
| MEDIUM | Confirm SNS subscription (check <BILLING-EMAIL>) | Board |
| MEDIUM | Domain name for attendees (optional but better UX) | Board |
| MEDIUM | E2E test — full query flow with live data | After deploy |
| LOW | Traffic Analyst + Intel Lookup + Explainer agents (Phase 3) | After core is live |
| LOW | CI/CD pipeline | Post-event |

---

## 11. File Map

```
BHNOCgentic/
├── design.md                        # This file
├── PROGRESS.md                      # Chronological build log
├── SETUP.md                         # AWS infrastructure setup guide
├── CLAUDE.md                        # Development guide and coding standards
├── PRIVATE_NOTES.md                 # API keys (never commit)
├── .env                             # Runtime secrets (never commit)
├── docker-compose.yml               # OpenSearch + Ingestion API + Nginx
├── docker-compose.agents.yml        # Orchestrator + Agents + Web Server
├── nginx/nginx.conf                 # TLS termination + routing
│
├── agents/
│   ├── shared/
│   │   └── opensearch_tools.py      # 6 async OpenSearch query functions
│   ├── orchestrator/                # Intent classifier + router (claude-3-5-sonnet)
│   ├── threat-hunter/               # IOC + threat detection (claude-3-haiku)
│   └── alert-triage/                # Alert scoring (claude-3-haiku)
│
├── packages/
│   ├── shared/                      # TypeScript types + Zod schemas
│   ├── agent-sdk/                   # LLM client + prompt sanitization
│   └── web-server/                  # Fastify HTTP + WebSocket + chat UI
│
├── infrastructure/
│   └── scripts/
│       └── setup-organization.sh    # AWS Org setup (already run)
│
└── scripts/
    ├── deploy-agents.sh             # rsync + remote docker compose
    └── seed-opensearch.py           # Synthetic test data generator
```
