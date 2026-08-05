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
              │  ┌─ Manifold quarantine → deter (safe-pool answer)
              │  ├─ classify (Gemini Flash-Lite, ~500ms)
              │  ├─ restricted-range filter (silent cover)
              │  ├─ guardrail filter (silent cover)
              │  └─ 4-intent router
              │
   ┌──────────┼──────────────┬──────────────┐
   ▼          ▼              ▼              ▼
alert-triage  thousandeyes   athena-hunter  deter
   :8003      :8004           :8005 (primary)  :8006
     │         │                │              │
     │         │                ▼              ▼
     │         │           AWS Athena     safe_pool.py
     │         │           (Parquet logs) (vetted aggregates)
     └─────────┴────────────┬──────────────┘
                            ▼
                  Gemini 3.1 Flash Lite Preview
                  (LangChain + LangSmith OTEL bridge)
```

### Stack
- **TypeScript** (Fastify web server + audit monitor UI)
- **Python 3.11** (all four agents, FastAPI)
- **LangChain** + **LangSmith OTEL bridge** for LLM spans
- **OpenTelemetry** → Manifold (`blackcap.app.manifoldsecurity.io`) for monitoring
- **S3 span archive** at `s3://blackhatnoc/corelight/dev/traces/` (NDJSON.gz, Hive partitions)
- **AWS Athena** — `blackhatnoc_glue.{conn,dns,http,ssl,files,alerts,suricata_corelight,uid_lookup,fuid_lookup,…}`
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
| **deter** | 8006 | `agents/deter/safe_pool.py` | Answers sessions Manifold has quarantined, from vetted aggregates only |

Agent ports (8001-8006) are internal to the Docker network (`expose:`, not published to the host). Only nginx (80/443) is public.

`deter` is the one agent no intent routes to. When a Manifold threat quarantines
a session, its later queries go there instead of getting a canned refusal-shaped
cover: it answers what was actually asked, using only author-written,
aggregate-only roll-ups over an allowlisted set of tables. The caller's text
selects which roll-up is read and never becomes part of one, and any failure —
agent down, timeout, or its own output screen rejecting the model's text —
degrades silently to the same cover the other guardrails serve. See
[`docs/security/deter-agent.md`](docs/security/deter-agent.md).

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
- **Lane swap (`⇄`)**: on a raced query, the answer bubble names the lane that answered, its elapsed time, and a button to read the other one. See [Lane race](#lane-race-cloud-vs-local).

---

## Lane race (cloud vs local)

Two provider stacks answer the same query at once. The first one to finish is what
the analyst reads, and the answer bubble grows a `⇄` button for the other one.

| lane | NL→SQL | prose |
|---|---|---|
| `cloud` | Gemini | Gemini |
| `local` | AQLight | AQLight, or a second model if you serve one |

`LANE_RACE=auto` (the default) races only when a local endpoint is configured, so
the same image runs single-lane on a box with no GPU instead of firing off calls it
knows will fail. The show box goes further and pins `LANE_MODE=hybrid`, so a lost
local endpoint reads as a warning in the gear rather than a quiet drop to one lane.

Both lanes run the full pipeline, which means **a raced query scans Athena twice**.
Set `LANE_RACE=off` if that costs more than the comparison is worth.

Design notes, plus measured accuracy and latency for every configuration and why
local loses on both today: [`docs/llm/lane-race.md`](docs/llm/lane-race.md).

---

## Lane mode (cloud only, local only, hybrid)

The race is one of three modes. `hybrid` runs both lanes, `cloud` runs Gemini only,
and `local` runs the box only. Local never falls back to the cloud when the endpoint
is down: it fails loudly, because the reason to pick it is that the query text must
not leave the network.

The ⚙ gear in the audit monitor changes the mode without a redeploy, along with a
side-by-side checkbox (on by default) that decides whether the losing lane is shown
at all. That override is process state, so a restart comes back to whatever
`LANE_MODE` and `LANE_SIDE_BY_SIDE` say in `.env.s3`.

The same panel lists every local model, flags an endpoint that is serving the wrong
alias, and can start or stop the llama-server units. Starting a process on the host
goes through [`ops/model-supervisor/`](ops/model-supervisor/README.md), a small host
process rather than a container, so the orchestrator can name a vetted model key and
nothing more.

Full write-up: [`docs/llm/lane-mode.md`](docs/llm/lane-mode.md).

---

## Response cache (Redis)

A question somebody already asked comes back without re-running the pipeline. Booth
traffic is repetitive: two people click the same quick-pick chip a minute apart, and
the second one should not pay for a fresh Athena scan and two LLM calls.

Keyed on the question plus the answering agent plus the model config, in Redis so it
survives a redeploy and any replica can read it. This sits above the SQL cache in
`athena_client` and caches something different: `question → finished answer` rather
than `SQL → rows`, which is where the seconds actually are.

Two things about it are load-bearing and not obvious:

- **The lookup runs after every guardrail.** Quarantine, the restricted-range filter,
  the refusal verdict and the Athena kill-switch all return their cover before the
  cache is consulted. The key is the query text alone, so an entry is served to
  callers who did not populate it. Caching in front of those checks would replay a
  contained session's cover to everyone and would keep serving live answers past a
  kill-switch flip.
- **A hit is deliberately paced** to a random 2 to 5 seconds total, because an answer
  that returns in two milliseconds tells an observer which questions have been asked
  before. Applied to a cover that becomes a guardrail oracle.

Redis down degrades to "no cache", never to "no answers". Full write-up, including
the admin purge route: [`docs/cache/response-cache.md`](docs/cache/response-cache.md).

---

## Audit monitor (admin only)

`tools/audit-monitor/` — FastAPI + SSE live view of every agent span.

- **URL**: `https://ng.bhnoc.com/bh/1337/thetraces/`
- **Auth**: bearer token → HTTPOnly signed cookie (HMAC(expiry))
- **Data source**: polls `s3://blackhatnoc/corelight/dev/traces/` every 2 s
- **UI**: one swim-lane per service, color-coded card kinds (LLM, athena, agent, tool, http). Cards show query/prompt/SQL preview (≤300 chars). Click-to-expand for full attributes including LLM prompt/completion.
- **Startup preload**: pulls last 5 min of spans so lanes are populated immediately.
- **Raw admin view**: spans show **unredacted** queries, IPs, zone names — the restricted-range filter only touches end-user responses.

---

## Deployment

- **Target**: `ng.bhnoc.com` (EC2 `<INSTANCE-ID>`, us-west-2)
- **Creds**: instance role `blackhatnoc-usa2026-ec2-role` (S3 + Athena + Glue read; S3 write scoped to `blackhatnoc`)
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
| `LANE_RACE` | `auto` | race cloud vs local: `auto` (only if a local endpoint is set) \| `on` \| `off` |
| `LANE_MODE` | *(empty)*, `hybrid` on the box | `hybrid` \| `cloud` \| `local`; overrides `LANE_RACE`. Empty derives from it. |
| `LANE_SIDE_BY_SIDE` | `true` | show the losing lane and the swap. `false` still races, just hides it. |
| `MODEL_SUPERVISOR_URL` | *(empty)* | host model supervisor. Empty = model panel is read-only. |
| `MODEL_SUPERVISOR_TOKEN` | *(empty)* | shared secret with the host supervisor unit |
| `LOCAL_SQL_BASE_URL` | `LOCAL_LLM_BASE_URL` | local llama-server for NL→SQL |
| `LOCAL_SQL_MODEL` | `LOCAL_LLM_MODEL` | served alias for the local SQL model |
| `LOCAL_PROSE_BASE_URL` | `LOCAL_SQL_BASE_URL` | local llama-server for prose; unset = same one |
| `LOCAL_PROSE_MODEL` | `LOCAL_SQL_MODEL` | served alias for the local prose model |
| `OPENROUTER_API_KEY` | — | alternate provider |
| `RESPONSE_CACHE_ENABLED` | `true` | `false` skips Redis entirely |
| `REDIS_URL` | `redis://redis:6379/0` | response cache backend |
| `RESPONSE_CACHE_TTL_SECONDS` | `900` | how long a cached answer stays valid |
| `RESPONSE_CACHE_HIT_DELAY_MIN` | `2.0` | cache hits are paced to a random total in this window |
| `RESPONSE_CACHE_HIT_DELAY_MAX` | `5.0` | so a hit does not look instant |
| `ATHENA_DATABASE` | `blackhatnoc_glue` | |
| `ATHENA_WORKGROUP` | `blackhatnoc-usa2026` | |
| `ATHENA_REGION` | `us-east-2` | |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Manifold | trace export |
| `OTEL_EXPORTER_OTLP_API_KEY` | — | Manifold bearer |
| `TRACE_S3_BUCKET` | `blackhatnoc` | span archive bucket |
| `TRACE_S3_PREFIX` | `nocgentic/traces` | prod overrides to `corelight/dev/traces`; must match `AUDIT_PREFIX` or the swim lanes read an empty path |
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
  deter/
    main.py           contained-session answers + output screen
    safe_pool.py      the ONLY data a contained session can reach
  shared/
    llm_client.py     Gemini/OpenRouter unified client + metrics
    athena_client.py  SELECT-only SQL wrapper with date partitioning
    telemetry.py      OTel → Manifold + S3 span exporter
    s3_span_exporter.py  gzipped NDJSON span archive

packages/
  shared/             TS types / validation (Zod)
  web-server/         Fastify + Zod + WebSocket; static/{index.html,app.css,app.js}

tools/
  audit-monitor/      FastAPI + SSE swim-lane dashboard (Docker)

ops/
  deploy.sh           Canonical deploy (CI + on-box)
  run-tests.sh        Pre-deploy test runner

infrastructure/
  scripts/            Org/IAM setup helpers only

scripts/
  deploy-agents.sh    Thin wrapper → ops/deploy.sh
  refresh-env-creds.sh, seed-s3.py

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
