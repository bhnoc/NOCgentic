# Manifold Integration

How NOCgentic ships LLM and agent traces, metrics, and logs to **Manifold Security**, plus the parallel S3 span archive that backs Athena queries and the live audit monitor.

> **Source of truth.** Code paths and behaviors below are verified against the current tree. Conversation history (the Claude Code transcript and `PROGRESS.md`) is used to reconstruct *why* a decision was made; those passages are flagged "(per session history)" so future-you knows the difference between "this is how the code is" and "this is how I remember we got here".

---

## TL;DR

- **Tenant:** `blackcap.app.manifoldsecurity.io`
- **Endpoint:** `https://blackcap.app.manifoldsecurity.io:4318` (OTLP-HTTP)
- **Paths:** `/v1/traces`, `/v1/metrics`, `/v1/logs`
- **Auth:** `Authorization: Bearer ${OTEL_EXPORTER_OTLP_API_KEY}` header
- **Wire-up:** every Python agent calls `init_telemetry(service_name=...)` at startup (see `agents/shared/telemetry.py`), which registers OTLP exporters for traces+metrics+logs, plus a parallel `S3SpanExporter`.
- **LLM tracing:** done by the **OpenInference LangChain instrumentor** (`openinference-instrumentation-langchain`). `LangChainInstrumentor().instrument(tracer_provider=...)` in `init_telemetry()` hooks LangChain's callback manager, so every `ChatGoogleGenerativeAI.ainvoke()` / `ChatOpenAI.ainvoke()` emits an OpenInference LLM span (`openinference.span.kind=LLM`, `llm.model_name`, `llm.token_count.*`, `input.value`/`output.value`) through *our* `TracerProvider`. This **replaced the LangSmith OTEL bridge**, which emitted zero LLM spans in practice — see §3.
- **Agent-graph semantics:** hand-rolled request/tool spans are stamped with OpenInference span kinds (`AGENT` on root handlers, `CHAIN` on wrappers, `TOOL` on Athena/ThousandEyes calls) via helpers in `telemetry.py` (`set_agent_span`/`set_chain_span`/`set_tool_span`/`set_tool_resource`). This is what populates Manifold's **Inventory** (agents/models/tools) and **Agent Graph** (Agent→Model CALLS, Agent→Tool INVOKES, Tool→Resource ACCESSES).
- **Sister exporter:** every span is *also* gzipped to `s3://blackhat-pope-dev-logs/nocgentic/traces/service=<svc>/dt=YYYY-MM-DD/hour=HH/...jsonl.gz` (Hive-partitioned, Athena-queryable).
- **Live admin view:** `tools/audit-monitor/` (FastAPI + SSE swim-lane dashboard at `/bh/1337/thetraces/`) tails the S3 archive every 2 s.

---

## 1. What goes to Manifold

Four Python services emit OTel data to Manifold:

| Service name (`OTEL_SERVICE_NAME`) | What it spans |
|---|---|
| `bhnocgentic-orchestrator` | inbound `/api/v1/chat`, classification, agent dispatch, response sanitisation |
| `bhnocgentic-alert-triage` | Athena-backed alert summarisation |
| `bhnocgentic-athena-hunter` | NL → SQL generation, `execute_sql_*` per query, `gather_context` aggregation |
| `bhnocgentic-thousandeyes-analyst` | TE v7 API calls, health classification |

> `bhnocgentic-threat-hunter` was removed 2026-07-24 (QA sweep 2: orphaned; the orchestrator never routed to it). No S3 NDJSON agent runs anymore.

For each, Manifold receives:

1. **Application spans** that the code emits explicitly via `tracer.start_as_current_span(...)` — e.g. `orchestrator.query`, `orchestrator.classify`, `athena_hunter.generate_sql`, `athena_hunter.gather_context`, `athena_hunter.execute_sql_<n>`.
2. **HTTP spans** from auto-instrumentation:
   - **inbound:** `FastAPIInstrumentor.instrument_app(app)` — tags every request with method, route, status, and extracts `traceparent` from headers so caller traces are stitched in.
   - **outbound:** `HTTPXClientInstrumentor().instrument()` — injects `traceparent` into every outbound httpx request, which is how orchestrator → agent → Athena hops end up on one flame graph.
3. **LLM spans** from the OpenInference LangChain instrumentor (see §3). These are the OpenInference semantic-convention spans (`openinference.span.kind=LLM`, `llm.*`) Manifold's LLM/Activity panel keys off.
4. **Metrics** — see §4.
5. **Python logs** — `LoggingHandler` on the root logger forwards every `INFO+` record to `/v1/logs`. Records are auto-tagged with the active `trace_id`/`span_id`, so logs land next to the span that produced them.

Span attributes carry full context — every root `orchestrator.query` span is tagged with `client.ip`, `client.user_agent`, `client.session_id`, `client.referer`, `query.text`, `routing.intent`, `agent.used`, the three `filter.*` booleans, and timing — and that propagates downstream via W3C Trace Context.

---

## 2. Endpoint, auth, and env

`agents/shared/telemetry.py` defaults the endpoint to Manifold; everything else is env-driven.

| Env var | Default | Notes |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://blackcap.app.manifoldsecurity.io:4318` | base URL; `/v1/traces`, `/v1/metrics`, `/v1/logs` are appended internally |
| `OTEL_EXPORTER_OTLP_API_KEY` | *(empty)* | **required** — if unset, OTel is silently disabled with a warning |
| `OTEL_SERVICE_NAME` | `bhnocgentic-agent` | each container overrides this in `docker-compose.agents.yml` |
| `OTEL_ENABLED` | `true` | set to `false`/`0`/`no` to short-circuit init |
| `OTEL_SAMPLE_RATE` | `1.0` | parent-based ratio sampler when < 1.0 |
| `OTEL_METRICS_INTERVAL_MS` | `60000` | `PeriodicExportingMetricReader` cadence; floored at 1000ms |
| `OTEL_LOG_LEVEL` | `INFO` | minimum level forwarded to `/v1/logs` |
| `OTEL_CONSOLE_TRACES` | `true` | also dump spans to stderr (visible via `docker logs`) |
| `LANGSMITH_TRACING` | forced `false` by `init_telemetry` | old bridge disabled — LLM tracing is via OpenInference now (§3) |
| `LANGSMITH_OTEL_ENABLED` | forced `false` by `init_telemetry` | old bridge disabled; prevents duplicate spans alongside OpenInference |
| `LANGCHAIN_TRACING_V2` | forced `false` by `init_telemetry` | keep LangChain off the LangSmith *cloud* API |
| `TRACE_S3_ENABLED` | `true` | toggles the S3 sister exporter only |
| `TRACE_S3_BUCKET` | `blackhat-pope-dev-logs` | |
| `TRACE_S3_PREFIX` | `nocgentic/traces` | |
| `TRACE_S3_REGION` | `us-west-2` (falls through `S3_REGION` then `AWS_REGION`) | |

Every agent's compose service block sets the first two via `${...}` substitution from `.env.s3`, plus its own `OTEL_SERVICE_NAME=bhnocgentic-<role>`.

---

## 3. LLM tracing: OpenInference (replaced the dead LangSmith bridge)

### 3.1 What we do now

`init_telemetry()` instruments LangChain with OpenInference, *after* setting our provider:

```python
trace.set_tracer_provider(trace_provider)      # our provider: OTLP + S3 + console + redaction

os.environ["LANGSMITH_TRACING"] = "false"       # force the old bridge OFF (no double-emit)
os.environ["LANGSMITH_OTEL_ENABLED"] = "false"
os.environ["LANGCHAIN_TRACING_V2"] = "false"

from openinference.instrumentation.langchain import LangChainInstrumentor
LangChainInstrumentor().instrument(tracer_provider=trace_provider)
```

`agents/shared/llm_client.py` still just calls `await llm.ainvoke(messages)`. OpenInference hooks LangChain's **callback manager**, so even our bare `ChatGoogleGenerativeAI`/`ChatOpenAI` calls (we use no `AgentExecutor`/LangGraph) emit LLM spans through *our* `TracerProvider` — reaching Manifold *and* the S3 archive without any manual wrapping.

The order still matters: `init_telemetry()` MUST run before `langchain*` is imported. That's why it's called at the very top of every agent's `main.py`.

Captured LLM-span attributes (OpenInference semantic conventions, which is what Manifold's LLM/Activity panels read):

- `openinference.span.kind = LLM`
- `llm.model_name` (e.g. `gemini-3.5-flash-lite`)
- `llm.token_count.prompt`, `llm.token_count.completion`, `llm.token_count.total`
- `llm.invocation_parameters`
- `input.value` / `output.value` (prompt + completion; **redacted** at the export boundary — see §0/redaction)

### 3.2 Why the LangSmith bridge was replaced (postmortem)

The prior design set `LANGSMITH_TRACING=true` + `LANGSMITH_OTEL_ENABLED=true` and assumed LangSmith's OTEL bridge would auto-emit `gen_ai.*` spans through our provider. **It never did.** A 2026-07-27 audit of the S3 span archive (`backups/traces-*/`, which contains the exact spans shipped to Manifold) found **9,025 spans with zero `gen_ai.*`, zero `langsmith.*`, and empty `events: []` on every LLM-wrapper span.** The bridge silently no-op'd — most likely because LangSmith's OTEL export path needs an active LangSmith tracing pipeline (an API key / run tree) that was deliberately never configured, and `os.environ.setdefault` won't override a stale container env.

The visible symptom in Manifold: **"Most Active Agents" and "Most Invoked Assets" populated** (from HTTP/FastAPI spans + the `bhnoc.*` metrics, which *do* export) **but the "Activity" trace view was blank** — no real agent/LLM trace data ever arrived in a shape the trace explorer renders.

OpenInference fixes both halves: it actually produces LLM spans, and it produces them in the OpenInference shape Manifold's Activity + Agent Graph key off. Per Manifold's own guidance, we never run both LangSmith-OTEL and OpenInference at once (duplicate spans), so the LangSmith flags are force-disabled above.

### 3.3 Agent/tool/chain graph semantics

Because our agents are hand-rolled (not LangChain agents), the OpenInference instrumentor only classifies the *LLM* calls. To populate Manifold's **Inventory** and **Agent Graph**, the manual spans are stamped with OpenInference kinds via helpers in `telemetry.py`:

| Helper | Span kind | Applied to |
|---|---|---|
| `set_agent_span` | `AGENT` | root handlers: `orchestrator.query`, `athena_hunter.analyze`, `alert_triage.triage`, `thousandeyes_analyst.analyze` |
| `set_chain_span` | `CHAIN` | wrappers: `*.classify`, `*.generate_sql`, `*.gather_context`, `*.llm_analyze`, `orchestrator.route.*` |
| `set_tool_span` + `set_tool_resource` | `TOOL` | resource calls: `athena_hunter.execute_sql_*`, `athena_hunter.alerts_recent`, `alert_triage.athena.*` (Athena), `te.fetch_*` (ThousandEyes API) |

Nesting already exists (tools run inside the agent's `with` span), so stamping the kinds is what draws the edges: **Agent→Model CALLS** (AGENT parent of an LLM span), **Agent→Tool INVOKES** (AGENT/CHAIN parent of a TOOL span), **Tool→Resource ACCESSES** (TOOL span carrying `db.system`/`server.address`).

---

## 4. Custom OTel metrics

`llm_client.py::_record_otel_metrics` emits three meters per LLM call, in addition to the spans:

| Metric | Type | Attributes | Use |
|---|---|---|---|
| `bhnoc.tokens` | counter | `gen_ai.system`, `gen_ai.request.model`, `token.type=input\|output` | aggregate token spend |
| `bhnoc.cost.usd` | counter | same minus `token.type` | rough $ burn (`_estimate_cost_usd` table) |
| `bhnoc.llm.duration_ms` | histogram | same minus `token.type` | latency distribution by model |

These show up in Manifold under whatever metric explorer Manifold provides; they exist so we can chart cost/usage by model without recomputing from spans.

In addition, `llm_client.py` keeps a thread-local `_last_metrics` dict (`get_last_llm_metrics()`) that the orchestrator pulls *synchronously* and stitches into the chat HTTP response — that's how the UI metrics chip (latency, tok/sec, thinking tokens) displays without waiting on a Manifold round-trip.

---

## 5. The S3 sister exporter

`agents/shared/s3_span_exporter.py` defines `S3SpanExporter`, a `SpanExporter` subclass that batches `ReadableSpan`s into gzipped NDJSON and PUTs them to S3 under:

```
s3://blackhat-pope-dev-logs/nocgentic/traces/service=<svc>/dt=YYYY-MM-DD/hour=HH/<svc>-<ts>-<rand>.jsonl.gz
```

It is wrapped in a `BatchSpanProcessor(max_export_batch_size=256, schedule_delay_millis=5000)` and registered alongside the OTLP processor — both fire on every span; neither blocks the other.

### Why a sister exporter rather than only Manifold

The session history (`PROGRESS.md` §7 + transcript) frames the S3 archive as a deliberate *parallel* design, not a fix for Manifold dropping data:

- **Audit/forensics:** raw spans (including LLM prompt + completion text) need to live somewhere we control, retained on our terms, regardless of Manifold's retention or contract.
- **Athena queryability:** Hive partitions (`service=`, `dt=`, `hour=`) are the schema we'd need anyway to bolt the audit archive onto Athena later.
- **Live audit monitor:** the swim-lane dashboard at `/bh/1337/thetraces/` polls S3 directly — it never talks to Manifold, so it works even if the Manifold tenant is unreachable.
- **Local dev:** S3 spans land within seconds; you can `aws s3 sync` them locally and run `tools/trace-export.py` to get a CSV (one row per user query) without ever logging into Manifold.

### Implementation notes

- **No client caching.** `_get_client()` constructs a fresh `boto3.Session().client("s3")` per upload. This is intentional and matches the pattern in `athena_client._get_athena()` and `s3_tools._get_s3()` — see CLAUDE.md "Operational Gotchas §2" for the EC2 instance-role credential-refresh trap that caching would hit.
- **Span serialization** is best-effort: bytes → utf-8 with `errors="replace"`, unknown types → `str(...)`, encoding errors per-span are captured as `{"_encode_error": ..., "span_name": ...}` lines so one bad span doesn't drop the batch.
- **Keys include `uuid.uuid4().hex[:8]`** so concurrent uploads from multiple containers in the same partition don't collide.

---

## 6. Real-time audit monitor — `https://ng.bhnoc.com/bh/1337/thetraces/`

The most-used artifact of the whole observability stack isn't Manifold itself — it's the in-house **audit monitor**, a single-page swim-lane dashboard that turns the S3 span archive into a live SOC view. It's the screen that gets demoed and the screen that gets watched during a live presentation. Manifold is the long-term system of record; the audit monitor is the cockpit.

### 6.1 Why it exists separately from Manifold

Manifold's UI is a generic OTel/LLM observability product — strong on aggregate dashboards, weaker on "what is the agent literally doing right now in lane X". Three needs forced building our own surface:

1. **Demo legibility.** A Black Hat NOC audience needs to *see* the orchestrator → classify → athena-hunter → SQL → response chain unfold in real time, with the raw prompt and the actual SQL visible. A flame graph buried in a vendor UI doesn't carry on a projector.
2. **SOC-grade unfiltered view.** End users see sanitised cover responses (scrubbed IPs, "Network Service" instead of MySQL, generic copy on restricted ranges). SOC needs the *real* `query.text`, real `client.ip`, real zone names — without piping that data into a third-party SaaS.
3. **A panic button.** Mid-demo, if a query starts going somewhere bad, the operator needs a one-click way to disarm the `athena_hunter` route. Not a console SSH session, not a Manifold setting — a button visible on the same screen as the traffic.

The audit monitor delivers all three by reading directly from the S3 archive (which contains the same spans Manifold gets) and proxying admin actions to the orchestrator.

### 6.2 Architecture

Two FastAPI services and an HTML page:

```
       ┌────────────────────────────────────┐
       │  S3: nocgentic/traces/        │ ← Manifold gets the same data
       │  service=<svc>/dt=…/hour=…/*.gz    │   in parallel
       └──────────────────┬─────────────────┘
                          │ list_objects_v2(StartAfter=last_seen_key)
                          │ every AUDIT_POLL_S seconds (default 2 s)
                          ▼
       ┌────────────────────────────────────┐
       │  audit-monitor (FastAPI on :8787)  │
       │   • poll_loop() — S3 tail          │
       │   • _classify_span() — kind tag    │
       │   • deque(maxlen=2000) ring buffer │
       │   • subscribers[] — asyncio.Queue  │
       │     fan-out to SSE clients         │
       │   • httpx → orchestrator for admin │
       └──────────────────┬─────────────────┘
                          │ SSE (text/event-stream)
                          ▼
       ┌────────────────────────────────────┐
       │  static/index.html (single page)   │
       │   • EventSource('/api/stream')     │
       │   • 5 swim lanes                   │
       │   • drawer                         │
       │   • KILL ATHENA button             │
       └────────────────────────────────────┘
```

**Key file map:**

| Path | Role |
|---|---|
| `tools/audit-monitor/app.py` | FastAPI app — auth middleware, S3 poller, SSE stream, admin proxy |
| `tools/audit-monitor/static/index.html` | The whole UI: CSS, swim-lane layout, EventSource client, drawer, kill switch |
| `tools/audit-monitor/Dockerfile` | Python 3.12 base, listens on `:8787` |
| `tools/audit-monitor/requirements.txt` | `fastapi`, `uvicorn[standard]`, `boto3`, `python-multipart`, `httpx` |
| `docker-compose.agents.yml` | Service definition, env vars |

### 6.3 The S3 tail (poll_loop + preload)

`poll_loop()` in `app.py` is a 2-second loop that:

1. **Discovers service prefixes** every 30 s via `list_objects_v2(Prefix=…/, Delimiter=/)` — picks up new agents joining the fleet without restart.
2. **For each `service=<svc>/` prefix**, calls `list_objects_v2(StartAfter=last_seen_key[sp])`. This is the cheap-tail trick: S3 returns only keys lexicographically greater than the last one we saw, so we never re-fetch already-processed gzip files. With key format `<svc>-<YYYYMMDDTHHMMSS>-<rand>.jsonl.gz`, lex order ≈ chronological order.
3. **Downloads + gunzips + parses** each new `.jsonl.gz` (one network round-trip per file, all in `asyncio.to_thread` so the event loop keeps moving).
4. **Classifies and broadcasts:** `_classify_span()` tags the span with a `kind` (`llm`/`athena`/`agent`/`tool`/`http`/`span`) and pushes a slim event onto:
   - `recent_events: deque(maxlen=2000)` — the in-memory ring buffer used to bootstrap new SSE connections,
   - `subscribers: list[asyncio.Queue]` — every connected SSE client gets a copy via `q.put_nowait(event)` (drop-on-full, never blocks the poller).

`preload()` runs once at startup with `AUDIT_LOOKBACK=300` (5 min): it constructs a synthetic `StartAfter` key from "now − 300 s" and runs one poll cycle. This is what makes the lanes pre-populated the moment the page loads — no awkward "waiting for first span" empty state.

**Why no client caching:** `_s3()` builds a fresh `boto3.Session` per cycle, with the same comment as the agents (`agents/shared/s3_span_exporter.py`): instance-role credentials rotate every ~6 h and a cached client hangs onto the old session token. The session pattern was the production fix for an outage where the audit monitor stopped updating after a credential rotation.

### 6.4 The SSE pump

```python
@app.get("/api/stream")
async def stream():
    q = asyncio.Queue(maxsize=500)
    subscribers.append(q)

    async def gen():
        # 1. Replay current ring buffer to bootstrap UI immediately
        if recent_events:
            yield f"event: snapshot\ndata: {json.dumps(list(recent_events))}\n\n"
        # 2. Then live-stream
        while True:
            ev = await q.get()
            yield f"event: span\ndata: {json.dumps(ev)}\n\n"
    ...
    return StreamingResponse(gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"})
```

Two SSE event types:

- `snapshot` — sent once on connect, contains everything currently in `recent_events`. The browser uses it to render lanes immediately rather than waiting for the next span.
- `span` — sent on every newly-discovered span, fired by the poll loop pushing onto each subscriber's queue.

`X-Accel-Buffering: no` is critical — without it any reverse proxy in front of the service will buffer SSE chunks and the UI feels frozen.

Other read endpoints:

- `GET /api/recent?limit=N` — JSON dump of the ring buffer (debugging / scripting).
- `GET /api/services` — distinct service names currently in buffer.
- `GET /healthz` — liveness check.

### 6.5 The UI (`static/index.html`)

Single-page, retro-techno theme to match the public site, but admin-flavoured (orange/red/yellow accent vs. the public ice-blue).

- **One swim lane per service**: `orchestrator`, `alert-triage`, `athena-hunter`, `thousandeyes-analyst` (was five, incl. `threat-hunter`, removed 2026-07-24 QA sweep 2). Lane headers show a live count badge and the most-recent-event timestamp.
- **Cards** are color-coded by `kind`:
  - **LLM** (yellow) — anything with `gen_ai.*` attrs or `langsmith.span.kind`
  - **athena** (purple) — names matching `athena.*` or `executequery`
  - **agent** (cyan) — `*.analyze`, `*.triage`, `*.query`, `*.classify`, anything with "agent" in the name
  - **tool** (orange) — `tool` or `execute_sql_*`
  - **http** (green, off by default) — auto-instrumentation noise; toggleable via filter chip
  - **span** (default) — fall-through bucket
- **Card preview** is a single ≤300-char line, picked in priority order:
  1. LangSmith `gen_ai.prompt.N.content` (the actual prompt text)
  2. `sql.query` (Athena SQL)
  3. `query.text` (raw user query on the orchestrator span)
  4. httpx `method + URL path`
  5. span name as fallback
- **Filter chips** in the header toggle each `kind` on/off; state persists in localStorage.
- **Click-to-expand drawer** slides in from the right and shows:
  - Full span name, service, trace_id, span_id, parent_span_id, duration, status
  - All attributes (collapsible JSON)
  - Events array (which is where `gen_ai.content.prompt` and `gen_ai.content.completion` actually live as JSON-encoded message arrays)
  - Resource tags
  - Raw span JSON for power users
- **Status dot** in the header — green when SSE connected, red when disconnected. Auto-reconnects via `EventSource` semantics.

### 6.6 The kill switch

Top-right of the header sits a single button: **KILL ATHENA**. It's the one piece of admin functionality embedded in the dashboard, and the rest of this section is the contract for how it works.

UI states (CSS in `static/index.html`):

- **Disarmed** — outlined orange, label `KILL ATHENA`. Hover turns it yellow.
- **Armed** — solid red background, white text, slow pulse animation. Hover deepens.

Three actors and the flow between them:

```
              ┌──────────────────┐
              │   browser UI     │
              │   (KILL ATHENA   │
              │    button)       │
              └────────┬─────────┘
                       │ GET  /admin/killswitch    (every 5 s + on click confirm)
                       │ POST /admin/killswitch/athena {killed: bool}
                       ▼
              ┌──────────────────┐
              │  audit-monitor   │   thin authenticated proxy
              │  (FastAPI)       │   — holds NO state itself
              └────────┬─────────┘
                       │ httpx → ORCHESTRATOR_URL/admin/killswitch...
                       ▼
              ┌──────────────────┐
              │   orchestrator   │   owns the in-memory flag
              │  _kill_switches  │   {"athena_hunter": false}
              └────────┬─────────┘
                       │ on every inbound /api/v1/chat with intent=athena_hunter:
                       │   if _kill_switches["athena_hunter"]:
                       │       tag span filter.kill_switch=true
                       │       return same cover response as restricted ranges
                       │   else:
                       │       proceed to athena-hunter agent
                       ▼
                 user response
```

**Orchestrator (state owner)** — pseudo-code:

```
state:
    kill_switches := { "athena_hunter": false }   # in-memory only

route GET /admin/killswitch:
    return kill_switches

route POST /admin/killswitch/athena:
    body := parse JSON request
    kill_switches["athena_hunter"] := bool(body.killed)
    log WARNING "ADMIN kill-switch: athena_hunter={...}"
    return kill_switches

# inside the main /api/v1/chat handler, athena_hunter routing branch:
on intent == "athena_hunter":
    if kill_switches["athena_hunter"]:
        span.set("filter.kill_switch", true)
        return cover_response()        # same generic message restricted IPs get
    else:
        forward to athena-hunter agent
```

**Audit monitor (proxy)** — pseudo-code, no state:

```
config:
    ORCHESTRATOR_URL := env("ORCHESTRATOR_URL", "http://orchestrator:8001")
    ADMIN_BEARER_TOKEN := env("ADMIN_BEARER_TOKEN")

route GET /admin/killswitch:
    require authenticated session
    return GET ${ORCHESTRATOR_URL}/admin/killswitch
        with header Authorization: Bearer ${ADMIN_BEARER_TOKEN}

route POST /admin/killswitch/athena:
    require authenticated session
    body := parse JSON request
    return POST ${ORCHESTRATOR_URL}/admin/killswitch/athena with body
        and header Authorization: Bearer ${ADMIN_BEARER_TOKEN}
```

The orchestrator's `/admin/*` routes require that bearer token (2026-07-24 QA sweep 2); the audit-monitor proxy is the only caller and forwards it.

**Browser UI** — pseudo-code:

```
on page load AND every 5 seconds:
    state := GET /admin/killswitch
    if state.athena_hunter:
        button.classList.add("armed")
        button.label := "ATHENA KILLED — click to re-arm"
    else:
        button.classList.remove("armed")
        button.label := "KILL ATHENA"

on button click:
    desired := not currently_armed
    if not confirm("Stop routing user queries to Athena?"):
        return
    new_state := POST /admin/killswitch/athena { killed: desired }
    apply new_state immediately (don't wait for next 5 s poll)
```

Three properties of this design worth calling out:

- **Indistinguishable to outsiders.** When armed, an athena-hunter query gets the same generic "nothing notable on that range" cover response that restricted IPs get. No error, no "service unavailable" — an attacker on the public site can't tell that a switch was flipped. The orchestrator still emits the span, tagged `filter.kill_switch=true`, so SOC sees what happened in the swim lane on the very next refresh.
- **In-memory only by design.** Restarting the orchestrator container disarms the switch. Treat it as a panic brake, not a configuration setting — you don't want a tense mid-demo flip to silently persist past the event.
- **Audit monitor holds no state.** The proxy pattern means: if the audit monitor crashes, the switch (already set) keeps working; and the UI's 5 s poll is the only sync mechanism, so two operators on two browsers stay consistent within 5 s of each other automatically.

### 6.7 What the operator actually sees

Live, with no work after page load:

1. **Five lanes streaming** — orchestrator card appears the instant a user submits a query, athena-hunter card appears milliseconds later with the SQL preview, more athena-hunter cards as each `execute_sql_*` span closes, and so on through the response.
2. **Click any card** → drawer opens with the raw prompt, the raw SQL, the model used, token counts, and the raw span JSON.
3. **Lane counts and "last update" timestamps** in the headers — at-a-glance signal that traffic is flowing.
4. **Kill switch button always visible** — one click + one confirm to choke off the most-likely-to-misbehave route.

The result: every query the public site processes is observable end-to-end on a single screen, including the LLM prompt and the SQL it generated, with admin-grade unfiltered data and a one-click brake. That's the practical payoff of the dual Manifold + S3 export design — Manifold owns the historical analytics, the audit monitor owns the live operator surface, and they're both reading the same span stream.

---

## 7. Issues encountered (chronological-ish)

These come from the session transcript (per session history) plus what's still visible in the code as workarounds.

### 7.1 `ProxyTracerProvider` instead of real provider
**Symptom:** `init_telemetry()` ran but no traces showed up at Manifold; `trace.get_tracer_provider()` returned the global `ProxyTracerProvider`.
**Cause:** `init_telemetry()` was only being invoked in a *test process*, not in the actual uvicorn worker.
**Fix:** every agent's `main.py` calls `init_telemetry(service_name=...)` at module scope, before any LangChain import. Verified by exec'ing into the running container and inspecting `trace.get_tracer_provider()`.

### 7.2 Traceloop SDK was a dead end
**Symptom (per session history):** an early attempt to use `traceloop-sdk` for LangChain instrumentation demanded its own API key and tried to ship spans to `api.traceloop.com`.
**Fix:** abandoned Traceloop; used LangSmith's native OTEL bridge instead (a pure env-var flip — no third-party SDK on the Python side).

### 7.3 LangChain init order
**Symptom:** GenAI spans were missing `gen_ai.usage.*` until the env vars were set.
**Cause:** LangSmith reads `LANGSMITH_TRACING` / `LANGSMITH_OTEL_ENABLED` *at import time*. Importing `langchain_*` before `init_telemetry()` ran left the bridge inert.
**Fix:** `init_telemetry()` sets those env vars unconditionally, AND every agent module is structured so that `init_telemetry()` runs before any `langchain*` import.

### 7.4 EC2 credential expiry breaking S3 span exports
**Symptom:** after ~6 hours the S3 exporter started returning `ExpiredToken`.
**Cause:** module-level boto3 client cache held onto credentials from container start.
**Fix (in current code):** `_get_client()` builds a fresh `boto3.Session` per upload. Same fix applied to `athena_client.py` and `s3_tools.py` — see CLAUDE.md "Operational Gotchas §2".

### 7.5 nginx caching old container IPs (502 on `/bh/1337/thetraces/`)
Not strictly a Manifold issue, but it killed the audit monitor (which is the human-facing view of the data we're shipping to Manifold). Permanent fix: docker DNS resolver + variable-based `proxy_pass` in `nginx/nginx-ssl.conf` — see CLAUDE.md "Operational Gotchas §1".

### 7.6 Thinking models exceeding orchestrator timeout
**Symptom (per session history):** Gemini 3.1 Pro thinking-mode calls hit 504 with 3–5 min latency; orchestrator's downstream httpx timeout was 90 s.
**Fix:** raised the orchestrator → agent timeout to 180 s, then dropped `thinking_budget` to keep latency in human-friendly territory. Today's default model is `gemini-3.1-flash-lite-preview` with `thinking_budget=0` for the classifier.

### 7.7 Discrepancy worth knowing
The agent that summarised the transcript reported `OTEL_CONSOLE_TRACES` defaults to `false`. The current code defaults it to `true` (`telemetry.py:73`). Trust the code.

---

## 8. What's verified working vs. what's outstanding

**Verified working** (per `PROGRESS.md` "Verification (run today)" + spot-check of code):

- Every agent's `init_telemetry()` reaches Manifold without error on container start.
- S3 trace prefix populates every ~5 s (BatchSpanProcessor `schedule_delay_millis=5000`).
- OpenInference LangChain instrumentor produces LLM spans (`openinference.span.kind=LLM`, `llm.*`) — **replaces the LangSmith bridge, which produced none** (§3.2). Verify post-deploy per §11.
- Manual spans carry OpenInference `AGENT`/`CHAIN`/`TOOL` kinds so Manifold's Inventory + Agent Graph populate.
- Internal-IP redaction covers the full RFC-1918 space (fixed a bug where the 10/8 branch leaked the final octet).
- Distributed traces stitch orchestrator → agent → Athena/HTTP into a single trace via `httpx` + `FastAPI` auto-instrumentation.
- Custom metrics (`bhnoc.tokens`, `bhnoc.cost.usd`, `bhnoc.llm.duration_ms`) exporting to `/v1/metrics`.
- Python `INFO+` logs forwarded to `/v1/logs` with trace correlation.
- Audit monitor swim-lane dashboard renders live spans with prompt/SQL drawers.

**Outstanding / nice-to-have:**

- Audit monitor still polls S3 every 2 s rather than streaming spans straight from the orchestrator over WebSocket. Acceptable for the demo; the lag is visible but not bothersome.
- No alerting on Manifold-side LLM cost spikes; the data is there (`bhnoc.cost.usd` counter), but no dashboard is wired up.
- No verified rotation procedure for `OTEL_EXPORTER_OTLP_API_KEY` — currently lives in `.env.s3` on the host. Rotation would require updating the env file + `docker compose up -d` to recreate every agent container.
- Sampling is 1.0 (every span exported). Fine at current traffic; would need to drop to 0.1–0.25 in production-scale usage.

---

## 9. File map

```
agents/shared/
  telemetry.py            # init_telemetry(), exporters, LangSmith bridge wiring
  s3_span_exporter.py     # S3SpanExporter (gzip NDJSON → Hive partitions)
  llm_client.py           # LangChain wrapper, custom GenAI metrics, _last_metrics

agents/<svc>/main.py      # each calls init_telemetry(service_name="bhnocgentic-<svc>")
                          # at the very top, before any langchain import

docker-compose.agents.yml # OTEL_* env vars per service block

tools/audit-monitor/      # FastAPI + SSE swim-lane dashboard
                          # NB: reads S3, NOT Manifold
tools/trace-export.py     # offline CSV from a local sync of the S3 archive

PROGRESS.md §7            # short-form changelog of the observability work
README.md                 # user-facing summary of stack incl. Manifold endpoint
CLAUDE.md "Operational
  Gotchas"                # nginx + boto3 cred refresh footguns
```

---

## 10. Quick reference

**Test that an agent is actually exporting:**

```bash
docker exec -it bhnocgentic-orchestrator python3 -c "
from opentelemetry import trace
print(trace.get_tracer_provider())   # should NOT be ProxyTracerProvider
"
```

**Smoke-test the OTLP endpoint from the host:**

```bash
curl -i -H "Authorization: Bearer $OTEL_EXPORTER_OTLP_API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"resourceSpans":[]}' \
     https://blackcap.app.manifoldsecurity.io:4318/v1/traces
# expects 200 (or 4xx with a JSON body, not a connection error)
```

**Watch S3 spans land:**

```bash
aws s3 ls s3://blackhat-pope-dev-logs/nocgentic/traces/ --recursive \
  | tail -20
```

**Pull the most recent backup + extract a CSV of user queries:**

```bash
python tools/trace-export.py            # uses newest local backup
python tools/trace-export.py --by-session  # also prints per-session summary
```

---

## 11. Deploying & verifying the OpenInference fix (2026-07-27)

The LLM-span fix requires **rebuilding the agent images** (new pip dep
`openinference-instrumentation-langchain`) — a plain container restart is not
enough. A restart alone still gets the manual AGENT/TOOL/CHAIN span kinds (those
need no new package), but not the LLM spans.

### 11.1 Deploy

```bash
# From the repo root, rebuild + restart the agent fleet (see README for the
# canonical rsync + `docker compose up -d --build` invocation; do NOT use the
# broken scripts/deploy-agents.sh — CLAUDE.md Operational Gotcha §4).
docker compose -f docker-compose.agents.yml up -d --build
```

### 11.2 Confirm the instrumentor loaded (per container)

```bash
docker logs bhnocgentic-athena-hunter 2>&1 | grep -i openinference
# want: "OpenInference LangChain instrumentation enabled — LLM spans export via our TracerProvider"
# a "NOT installed" warning here means the image wasn't rebuilt with the new dep.
```

### 11.3 Confirm real LLM + graph spans are now emitted

Run one query through the site, then inspect a fresh S3 span (same data Manifold
gets). This is the definitive check — it's how the original breakage was found.

```bash
# newest object under any service prefix
aws s3 ls s3://blackhat-pope-dev-logs/nocgentic/traces/ --recursive | sort | tail -1
aws s3 cp s3://blackhat-pope-dev-logs/nocgentic/traces/<key>.jsonl.gz - | zcat | \
  python3 -c "import sys,json,collections
c=collections.Counter()
for l in sys.stdin:
    s=json.loads(l); a=s.get('attributes',{})
    if 'openinference.span.kind' in a: c[a['openinference.span.kind']]+=1
print(c)"
# BEFORE fix: Counter()            (no openinference kinds, no LLM spans)
# AFTER fix:  Counter({'LLM': N, 'AGENT': M, 'TOOL': K, 'CHAIN': J})
```

### 11.4 Confirm in Manifold

1. **Activity** — should now stream nested traces (AGENT → CHAIN → LLM/TOOL) with
   timing + token counts, instead of being blank.
2. **Inventory** — agents (`bhnocgentic-*`), models (`gemini-3.5-flash-lite`),
   and tools (`athena.query`, `thousandeyes.api`) appear as entities.
3. **Agent Graph** — edges appear: Agent→Model CALLS, Agent→Tool INVOKES,
   Tool→Resource ACCESSES (Athena `blackhat_pope_logs`, `api.thousandeyes.com`).

### 11.5 If Activity is still thin

- Duplicate LLM spans → something re-enabled the LangSmith bridge; confirm
  `LANGSMITH_OTEL_ENABLED=false` in the container env (we force it in code, but a
  compose/env override could fight it).
- No LLM spans but AGENT/TOOL present → the `openinference-*` dep didn't install;
  re-check §11.2.
- Prompts look over-redacted → that's intentional; internal IPs/secrets are
  scrubbed at the export boundary (redaction §0). Loosen only via policy change.
