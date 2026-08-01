# NOCgentic — AI-Powered Security Operations Center

Multi-agent LLM platform deployed at the **Black Hat NOC**.
Live at **`https://ng.bhnoc.com`**.

A Python/TypeScript SOC assistant that routes analyst questions to the
right specialist (alerts / network-quality / data-lake hunt), queries
Corelight/Zeek telemetry in AWS Athena, and synthesises concise active-voice
answers with next-step hints.

---

## Current architecture

```
Browser (static/index.html) ──HTTPS──┐
                                     ▼
                        ┌── nginx (443 + 80) ──┐
                        │                      │
                        ▼                      ▼
         Web server (Fastify, 3000)     Audit monitor (FastAPI, 8787)
              │                               (behind bearer+cookie auth at
              │ POST /query                    /bh/1337/thetraces/)
              ▼
         Orchestrator (FastAPI, 8001)
              │  ┌─ classify (Gemini Flash-Lite, ~500ms)
              │  ├─ restricted-range filter (silent cover)
              │  ├─ guardrail filter (silent cover)
              │  └─ 4-intent router
              │
   ┌──────────┼──────────────┐
   ▼          ▼              ▼
alert-triage  thousandeyes   athena-hunter
   :8003      :8004           :8005 (primary)
     │         │                │
     │         │                ▼
     │         │           AWS Athena
     │         │           (Parquet logs)
     └─────────┴────────────┐
                            ▼
                  Gemini 3.1 Flash Lite Preview
                  (LangChain + LangSmith OTEL bridge)
```

### Stack
- **TypeScript** (Fastify web server + audit monitor UI)
- **Python 3.11** (all four agents, FastAPI)
- **LangChain** + **LangSmith OTEL bridge** for LLM spans
- **OpenTelemetry** → Manifold (`blackcap.app.manifoldsecurity.io`) for monitoring
- **S3 span archive** at `s3://blackhat-pope-dev-logs/nocgentic/traces/` (NDJSON.gz, Hive partitions)
- **AWS Athena** — `blackhat_pope_logs.{conn,dns,http,ssl,files,alerts,suricata_corelight,uid_lookup,fuid_lookup,…}`
- **Docker Compose** stack on EC2 `ng.bhnoc.com`
- **Gemini 3.1 Flash-Lite-Preview** (swappable via `GEMINI_MODEL`); OpenRouter available as alternate provider

---

## Data flow for a chat query

1. **Browser** POSTs `/api/v1/chat` with the query text, `X-Client-Session` header (stable localStorage UUID), and the `bh_sid` cookie.
2. **Web server** extracts `clientIp` / `user_agent` / `session_id`, creates a job, dispatches to orchestrator.
3. **Orchestrator**:
   - Tags span with `client.ip`, `client.user_agent`, `client.session_id`, `query.text` (raw).
   - **Restricted-range check** — if query mentions `10.220.{12,13,14,15,150,152,153,154,199}.X` or "Registration"/"Tools", returns a generic cover response (+ 5 hunt hints) in <10 ms. Admin audit span still tagged `filter.restricted=true`.
   - **LLM classifier** (Gemini Flash-Lite, `thinking_budget=0`, ~500 ms) → one of four intents:
     - `alert_triage` → triage Athena alerts table
     - `thousandeyes_analyst` → ThousandEyes API
     - `athena_hunter` → **default** data-lake hunt (SQL generation via LLM)
     - `refused` → guardrail (silent; returns same cover response + hints)
4. Specialist agent runs, returns structured answer + data.
5. **Orchestrator output sanitiser**: restricted IPs masked → `10.220.69.X`, "Registration"/"Tools" → "internal". Runs on every non-cover response.
6. Web server writes `status=done` to job store + sends WS `job_update`.
7. Browser receives WS push OR polls `/api/v1/chat/:id` every 2 s — whichever wins renders the answer; the other path no-ops.
8. Hints generated async (non-blocking) and delivered via `/hints/:id`.

---

## Security / guardrails (all silent)

| Filter | What it blocks | What the user sees |
|---|---|---|
| Restricted subnets | `10.220.{12-15,150,152,153,154,199}.X` | Generic "nothing actionable on that range" + 5 hunt hints |
| Restricted zone names | `Registration` / `Tools` | Same generic cover |
| Output sanitiser | IPs in restricted ranges, zone names anywhere in output | Rewritten to `10.220.69.X` / `internal` |
| Guardrail classifier | Off-topic, prompt-injection, attack-facilitation, jailbreak | Same generic cover + hints |
| SQL sanitizer | DROP/DELETE/INSERT/UPDATE/ALTER/CREATE/TRUNCATE/MERGE | Raises `ValueError` (only SELECT allowed) |
| Agent-side LLM sanitiser | Credential patterns (`password`, `api_key`, `Bearer`) | Redacted before Gemini call |

Internal `10.x`/`172.16/12`/`192.168` IPs are **not** stripped at the orchestrator→agent boundary any more — they're the investigation subject. They flow into SQL; only secret/credential patterns are stripped at the LLM boundary.

---

## Agents

| Agent | Port | Data source | Role |
|---|---|---|---|
| **orchestrator** | 8001 | — | Routing brain, guardrails, output sanitiser, trace headers |
| **athena-hunter** | 8005 | AWS Athena (SQL) | Default: generates SQL from NL, explains results |
| **alert-triage** | 8003 | AWS Athena `alerts` | Prioritises active alerts, IDS feed |
| **thousandeyes-analyst** | 8004 | ThousandEyes v7 API | BGP / latency / uplink health |

Agent ports (8001-8005) are internal to the Docker network (`expose:`, not published to the host). Only nginx (80/443) is public.

Each agent:
- Initialises OTel at startup → Manifold traces, metrics, logs + S3 NDJSON span archive
- Runs LangSmith OTEL bridge so every LLM call emits GenAI spans (prompt, completion, tokens)
- Exposes `/health`
- Returns `{answer, confidence, agent_used, data}` JSON

---

## Web UI

`packages/web-server/static/index.html` — single-page, retro techno Black Hat theme (black void + ice blue).

- **Chat** with streaming `job_update` over WebSocket and 2 s HTTP polling (either path renders; race-safe).
- **Collapsible answer sections** (`Key Entities`, `Next Steps`, `Evidence`, `Recommended Actions`).
- **Alert feed sidebar** — backed by `athena-hunter/alerts/recent` every 30 min, trickled one card every 9 s with fresh timestamps.
- **Mobile (iPhone 12)** layout: single rotating alert card swapping every 3–5 s, stats hidden, full-width bubbles.
- **Session tracking** — `bh_sid` HttpOnly cookie (30 days) + `X-Client-Session` header backed by localStorage. Either survives a cookie clear; both must be cleared to reset identity.
- **6 starter prompts** on landing page covering threat hunting + network quality.

---

## Audit monitor (admin only)

`tools/audit-monitor/` — FastAPI + SSE live view of every agent span.

- **URL**: `https://ng.bhnoc.com/bh/1337/thetraces/`
- **Auth**: bearer token → HTTPOnly signed cookie (HMAC(expiry))
- **Data source**: polls `s3://blackhat-pope-dev-logs/nocgentic/traces/` every 2 s
- **UI**: one swim-lane per service, color-coded card kinds (LLM, athena, agent, tool, http). Cards show query/prompt/SQL preview (≤300 chars). Click-to-expand for full attributes including LLM prompt/completion.
- **Startup preload**: pulls last 5 min of spans so lanes are populated immediately.
- **Raw admin view**: spans show **unredacted** queries, IPs, zone names — the restricted-range filter only touches end-user responses.

---

## Deployment

- **Target**: `ng.bhnoc.com` (EC2 `<INSTANCE-ID>`, us-west-2)
- **Creds**: instance role `blackhat-pope-dev-ec2-role` (S3 + Athena + Glue read; S3 write scoped to `blackhat-pope-dev-logs`)
- **Refresh STS**: `bash scripts/refresh-env-creds.sh .env.s3` on the host before `docker compose up`
- **SSH**: `ssh -i ~/.ssh/id_macmini ubuntu@ng.bhnoc.com`, app at `/opt/nocgentic/app`

### Deploy cycle
```bash
# From repo root, after changes:
rsync -av -e "ssh -i ~/.ssh/id_macmini" \
  agents/ packages/ tools/ docker-compose.agents.yml nginx/ \
  ubuntu@ng.bhnoc.com:/opt/nocgentic/app/

ssh -i ~/.ssh/id_macmini ubuntu@ng.bhnoc.com \
  'cd /opt/nocgentic/app && docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d --build'
```

### Local dev
```bash
npm install
npm run build               # builds shared + web-server
docker compose -f docker-compose.agents.yml up -d --build
# then open http://localhost (nginx) or http://localhost:3000 (direct)
```

---

## Environment variables (key)

| Var | Default | Meaning |
|---|---|---|
| `GEMINI_API_KEY` | — | required |
| `GEMINI_MODEL` | `gemini-3.1-flash-lite-preview` | LLM model (swap via env, no code change) |
| `LLM_PROVIDER` | `gemini` | or `openrouter` |
| `OPENROUTER_API_KEY` | — | alternate provider |
| `ATHENA_DATABASE` | `blackhat_pope_logs` | |
| `ATHENA_WORKGROUP` | `blackhat-pope-dev` | |
| `ATHENA_REGION` | `us-west-2` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Manifold | trace export |
| `OTEL_EXPORTER_OTLP_API_KEY` | — | Manifold bearer |
| `TRACE_S3_BUCKET` | `blackhat-pope-dev-logs` | span archive bucket |
| `TRACE_S3_PREFIX` | `nocgentic/traces` | |
| `AUDIT_BEARER_TOKEN` | — | required for audit monitor |
| `AUDIT_COOKIE_SECRET` | — | HMAC key for admin cookie |
| `ADMIN_BEARER_TOKEN` | n/a | bearer token guarding the orchestrator `/admin/*` routes; audit monitor forwards it |
| `ALERT_REFRESH_MS` | `1800000` | alert cache refresh cadence (30 min) |
| `ALERT_LOOKBACK_HOURS` | `24` | initial Athena window for alert feed |
| `THOUSANDEYES_BEARER_TOKEN` | — | optional; only needed for TE intent |

---

## Repo layout

```
agents/
  orchestrator/       routing, classify, guardrails, output sanitiser
  alert-triage/       Athena-backed triage (Flash-Lite)
  athena-hunter/      SQL generation + analysis (primary hunt agent)
  thousandeyes-analyst/  TE REST API
  shared/
    llm_client.py     Gemini/OpenRouter unified client + metrics
    athena_client.py  SELECT-only SQL wrapper with date partitioning
    telemetry.py      OTel → Manifold + S3 span exporter
    s3_span_exporter.py  gzipped NDJSON span archive

packages/
  shared/             TS types / validation (Zod)
  web-server/         Fastify + Zod + WebSocket; static/index.html

tools/
  audit-monitor/      FastAPI + SSE swim-lane dashboard (Docker)

infrastructure/
  cloudformation/     IaC for VPC/EC2/CloudWatch
  scripts/            deploy-agents.sh, refresh-env-creds.sh, seed-s3.py

nginx/                TLS + reverse proxy config
docker-compose.agents.yml   full stack (7 containers)
docs/
  Athenaguide.md.md   schema / SQL reference
  DATA-SCHEMA.md      Corelight field reference
```

---

## Observability

Every query emits a distributed trace from `POST /api/v1/chat` through orchestrator → specialist agent → Gemini API. Spans carry:

- `client.ip`, `client.user_agent`, `client.session_id` (attribution)
- `query.text` (raw, admin-visible in audit monitor)
- `routing.intent`, `classification.reasoning`, `filter.restricted`, `filter.guardrail`
- `sql.query`, `sql.row_count`, `athena.execution_time_ms`, `athena.data_scanned_mb`
- `gen_ai.request.model`, `gen_ai.usage.{input,output}_tokens`, `thinking_tokens`
- `bhnoc.tokens`, `bhnoc.cost.usd`, `bhnoc.llm.duration_ms` (metrics)

All exported to Manifold + the S3 NDJSON archive. The audit monitor reads S3 live.

---

## Current user-facing state (2026-04-23)

- Six starter prompts on landing, covering threat hunting + network quality
- Mobile layout verified for iPhone 12; single rotating alert, no horizontal overflow
- Classifier routes correctly (15/15 tests passing across all 4 intents + guardrail)
- Restricted-range filter verified silent against IP-in-range / zone-name / jailbreak / off-topic / attack-facilitation probes — no leak strings (`guardrail`, `refuse`, `rephrase`, etc.) appear in responses
- Cover path and guardrail path both complete in <1 s and include hunt hints
- Normal query latency 5–15 s (alert-triage / athena-hunter), 2–4 s (thousandeyes)
- Admin audit monitor receives every span; raw queries + IPs visible, restricted-range cover still tagged for audit

---

## License

Internal — Black Hat NOC project.
