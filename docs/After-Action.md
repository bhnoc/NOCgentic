# After-Action Report: BHNOCgentic x Manifold Integration

**Black Hat Asia 2026 NOC — AI-Powered Security Operations Platform**
**Date:** 2026-05-18
**Author:** Matt Spicer
**Addressed to:** Manifold Security

---

## Executive Summary

BHNOCgentic is an AI-powered, multi-agent Security Operations Center platform deployed live at the Black Hat Asia 2026 Network Operations Center. The platform enables real-time threat hunting against Corelight/Zeek telemetry by routing analyst questions through specialized LLM-driven agents backed by AWS Athena, ThousandEyes, and raw S3 log data — all observable end-to-end via OpenTelemetry exported to Manifold.

This report provides a technical debrief on the integration with Manifold, documents our architecture and design decisions, outlines challenges encountered, and lays out requirements for the upcoming Black Hat USA 2026 ("Vegas") deployment.

---

## 1. Platform Architecture

### 1.1 Infrastructure

The platform runs as an 8-container Docker Compose stack on a single EC2 instance (`aing.bhnoc.com`, g6e.4xlarge, us-west-2), fronted by nginx for TLS termination and reverse proxying.

```
Browser (static SPA) ──HTTPS──┐
                               ▼
                  ┌── nginx (443) ──────────┐
                  │                         │
                  ▼                         ▼
   Web Server (Fastify, :3000)    Audit Monitor (FastAPI, :8787)
        │                          (admin swim-lane dashboard at
        │ POST /query              /bh/1337/thetraces/)
        ▼
   Orchestrator (FastAPI, :8001)
        │  ┌─ Restricted-range filter (silent, <10ms)
        │  ├─ LLM classifier (Gemini Flash-Lite, ~500ms)
        │  ├─ Guardrail filter (silent cover on refused intent)
        │  └─ 4-intent router
        │
   ┌────┼──────────┬──────────────────┐
   ▼    ▼          ▼                  ▼
alert  thousandeyes  athena-hunter   threat-hunter
triage  analyst      :8005           :8002
:8003   :8004        (primary)       (S3 fallback)
  │      │              │               │
  │      │              ▼               ▼
  │      │         AWS Athena        S3 NDJSON
  │      │         (Parquet)         (raw Zeek TSV)
  └──────┴──────────┐
                    ▼
          Gemini 3.1 Flash-Lite Preview
          (via LangChain + LangSmith OTEL bridge)
```

**Key infrastructure decisions:**

- **EC2 + Docker Compose** over managed services (ECS/EKS) — cost-effective for a time-boxed event (~$25-35/week), rapid iteration during the build, and direct SSH access for live debugging during the NOC.
- **AWS Athena over OpenSearch** — migrated mid-build from OpenSearch to Athena-backed Parquet queries. Sub-second UID lookups, 1-5s aggregations, 5-15s full-day scans. Eliminated the operational burden of managing an OpenSearch cluster.
- **Instance role credentials** (no static keys in containers) — boto3 falls through to IMDSv2 for automatic credential rotation. We learned this the hard way after 6-hour credential expiry outages with cached clients (see Section 5).

### 1.2 Agents

The platform uses five specialized Python agents, each a FastAPI service with its own Docker container:

| Agent | Role | Data Source |
|-------|------|-------------|
| **Orchestrator** (:8001) | Routing brain — classifies intent, enforces guardrails, sanitizes output, manages trace context | LLM classifier (Gemini Flash-Lite) |
| **Athena Hunter** (:8005) | Primary threat hunt — generates SQL from natural language, executes against Corelight Parquet data | AWS Athena (`blackhatnoc_glue`) |
| **Alert Triage** (:8003) | Active alert prioritization and IDS feed summarization | Athena `alerts` / `suricata_corelight` tables |
| **Threat Hunter** (:8002) | Legacy S3-backed raw Zeek scanning, auto-secondary fallback | S3 raw NDJSON logs |
| **ThousandEyes Analyst** (:8004) | BGP health, packet loss, latency, reachability analysis | ThousandEyes v7 REST API |

> Note (2026-07-24 QA sweep 2): **Threat Hunter (:8002) has since been removed** as orphaned. The orchestrator never routed to it (the `threat_hunter` intent maps to `athena_hunter`). The live platform is now four agents, and agent ports are internal-only (only nginx 80/443 is public). This report reflects the state at the Asia event.

**Query routing** uses a two-phase approach:

1. **Heuristic pre-filter**: Restricted subnet/zone checks execute in <10ms, returning a silent cover response for sensitive infrastructure ranges.
2. **LLM classifier** (Gemini Flash-Lite, `thinking_budget=0`, ~500ms): Routes to one of four intents — `alert_triage`, `thousandeyes_analyst`, `athena_hunter` (default), or `refused` (guardrail). Heuristic fallback engages if the LLM call fails.

All guardrail and restricted-range responses return the **identical** generic cover response ("nothing notable on that range") with 5 hunt hints. This prevents outsiders from fuzzing the system to discover what's blocked.

### 1.3 User-Facing Application

The web UI (`https://aing.bhnoc.com`) is a single-page application with a Black Hat retro-techno theme:

- Chat interface with WebSocket streaming + 2s HTTP polling fallback (race-safe via `renderedJobs` Set)
- Collapsible answer sections (Key Entities, Next Steps, Evidence, Recommended Actions)
- Live alert sidebar fed from Athena (30-min refresh, 9s trickle, deduped by signature+IP)
- 6 curated starter prompts covering threat hunting and network quality
- Mobile layout (iPhone 12) with single rotating alert card
- Session tracking via dual-channel identity (`bh_sid` HttpOnly cookie + `X-Client-Session` localStorage header)

---

## 2. Manifold Integration — OpenTelemetry Architecture

### 2.1 What We Export

Every Python agent calls `init_telemetry(service_name="bhnocgentic-<role>")` at startup, which registers exporters for:

- **Traces** → Manifold OTLP-HTTP (`blackcap.app.manifoldsecurity.io:4318/v1/traces`)
- **Metrics** → Manifold (`/v1/metrics`)
- **Logs** → Manifold (`/v1/logs`)
- **Traces (parallel)** → S3 gzipped NDJSON archive (`s3://blackhatnoc/bh-asia-26/aing-trace/`)

Five services emit telemetry: `bhnocgentic-orchestrator`, `bhnocgentic-athena-hunter`, `bhnocgentic-alert-triage`, `bhnocgentic-threat-hunter`, `bhnocgentic-thousandeyes-analyst`.

### 2.2 Trace Depth — High Level to Individual Trace

The OTel integration captures the full lifecycle of every query, from high-level routing decisions down to individual LLM token counts:

**High-level spans (orchestrator):**
- `orchestrator.query` — root span carrying `client.ip`, `client.user_agent`, `client.session_id`, `query.text` (raw), `routing.intent`, `classification.confidence`, `classification.reasoning`
- Filter status attributes: `filter.restricted`, `filter.guardrail`, `filter.kill_switch`
- `orchestrator.classify` — the LLM classification sub-span
- `orchestrator.dispatch` — agent dispatch with timing

**Agent-level spans:**
- `athena_hunter.generate_sql` — NL-to-SQL generation
- `athena_hunter.execute_sql_<n>` — each Athena query with `sql.query`, `sql.row_count`, `athena.execution_time_ms`, `athena.data_scanned_mb`
- `athena_hunter.gather_context` — multi-query aggregation
- `alert_triage.analyze` — alert summarization
- `thousandeyes_analyst.query` — TE API calls

**LLM spans (via LangSmith OTEL bridge):**
- `gen_ai.system`, `gen_ai.request.model`, `gen_ai.request.max_tokens`
- `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`
- `gen_ai.response.finish_reason`
- Events: `gen_ai.content.prompt` (full message array), `gen_ai.content.completion`
- LangSmith metadata: `langsmith.span.kind` (`llm`, `chain`, `tool`, `retriever`)

**HTTP spans (auto-instrumentation):**
- Inbound: `FastAPIInstrumentor` tags every request with method, route, status, and extracts `traceparent`
- Outbound: `HTTPXClientInstrumentor` injects `traceparent` into every inter-service call

All spans are stitched into distributed traces via W3C Trace Context propagation, so a single user query produces a flame graph from browser → web server → orchestrator → specialist agent → Athena/API → LLM.

**Custom metrics:**
- `bhnoc.tokens` (counter, split by `token.type=input|output`)
- `bhnoc.cost.usd` (counter, estimated per-model cost)
- `bhnoc.llm.duration_ms` (histogram, latency distribution by model)

### 2.3 The LangSmith OTEL Bridge — The Load-Bearing Trick

The single most important integration decision was leveraging LangSmith's native OTEL bridge rather than manual LLM span instrumentation. The entire wire-up is three environment variables set in `init_telemetry()` **before any LangChain import**:

```python
trace.set_tracer_provider(trace_provider)   # our provider with OTLP+S3+console
os.environ.setdefault("LANGSMITH_TRACING", "true")
os.environ.setdefault("LANGSMITH_OTEL_ENABLED", "true")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")  # don't also send to LangSmith cloud
```

When `ChatGoogleGenerativeAI.ainvoke()` is called, LangSmith intercepts it and emits GenAI semantic-convention spans through **our** TracerProvider — so every LLM call lands at Manifold and in the S3 archive without any manual wrapping. This is what populates Manifold's LLM panel with prompt text, completion text, token counts, and finish reasons.

**The order is critical**: `init_telemetry()` must run before `langchain*` is imported, otherwise LangSmith never sees the env vars and falls back to no-op. Every agent's `main.py` is structured accordingly.

### 2.4 The S3 Sister Exporter

Every span exported to Manifold is simultaneously written to S3 via a parallel `BatchSpanProcessor`:

```
s3://blackhatnoc/bh-asia-26/aing-trace/
  service=bhnocgentic-orchestrator/dt=2026-04-23/hour=14/orchestrator-20260423T140532-a3f8b2c1.jsonl.gz
  service=bhnocgentic-athena-hunter/dt=2026-04-23/hour=14/athena-hunter-20260423T140535-e7d91ab4.jsonl.gz
  ...
```

**Why dual export:**
- **Forensics**: Raw spans (including full LLM prompts) live in infrastructure we control, on our retention terms
- **Resilience**: The admin audit monitor reads S3 directly — it works even if the Manifold tenant is unreachable
- **Queryability**: Hive-partitioned (`service=`, `dt=`, `hour=`) for future Athena analysis of our own telemetry
- **Local dev**: `aws s3 sync` + `tools/trace-export.py` gives a CSV of all queries without logging into any vendor UI

---

## 3. Administrative Swim-Lane Dashboard

### 3.1 Purpose and Design

The most operationally critical artifact of the observability stack is our custom **audit monitor** — a real-time swim-lane dashboard at `https://aing.bhnoc.com/bh/1337/thetraces/` that turns the S3 span archive into a live SOC operator view.

Three needs drove building a custom admin surface rather than relying solely on Manifold's UI:

1. **Demo legibility**: A Black Hat NOC audience needs to see the orchestrator → classify → athena-hunter → SQL → response chain unfold in real time, with raw prompts and actual SQL visible. A flame graph in a vendor UI doesn't carry on a projector.
2. **SOC-grade unfiltered view**: End users see sanitized cover responses (scrubbed IPs, generic copy). SOC operators need the real `query.text`, real `client.ip`, real zone names — without piping sensitive data into a third-party SaaS.
3. **A panic button**: Mid-demo, if a query starts going somewhere problematic, the operator needs a one-click kill switch visible on the same screen as the traffic.

### 3.2 UI Layout

- **Five swim lanes** — one per service (orchestrator, threat-hunter, alert-triage, athena-hunter, thousandeyes-analyst)
- **Color-coded cards by kind**: LLM (yellow), Athena (purple), Agent (cyan), Tool (orange), HTTP (green, off by default)
- **Card preview**: <=300-char snippet showing (in priority): LLM prompt text, SQL query, raw user query, or HTTP method+path
- **Click-to-expand drawer**: Full span attributes, LLM prompt/completion, events, resource tags, raw JSON
- **Filter chips**: Toggle card kinds on/off, persisted in localStorage
- **Status dot**: Green (SSE connected) / Red (disconnected), auto-reconnect
- **Lane count badges + timestamps**: At-a-glance confirmation that traffic is flowing

### 3.3 Data Pipeline

The audit monitor polls S3 every 2 seconds using `list_objects_v2(StartAfter=last_seen_key)` — a cheap-tail trick that only returns keys newer than the last one processed. Spans are gunzipped, classified by kind, and broadcast to connected browsers via Server-Sent Events (SSE).

On startup, a preload cycle pulls the last 5 minutes of spans so lanes are populated immediately — no empty-state waiting.

---

## 4. Kill Switch

### 4.1 Design

The kill switch is an in-memory flag in the orchestrator that, when armed, causes all `athena_hunter` intent queries to return the same generic cover response as restricted-range queries. It is operated from the audit monitor dashboard via a single button: **KILL ATHENA**.

```
Browser (KILL ATHENA button)
    │ GET  /admin/killswitch        (poll every 5s)
    │ POST /admin/killswitch/athena {killed: bool}
    ▼
Audit Monitor (FastAPI) ──httpx──▶ Orchestrator (state owner)
    (stateless proxy)               _kill_switches = {"athena_hunter": false}
```

### 4.2 Key Properties

- **Indistinguishable to outsiders**: When armed, the user receives the exact same cover response as restricted-IP queries. No error, no "service unavailable" — an attacker cannot detect the switch was flipped. The orchestrator span is tagged `filter.kill_switch=true` for admin visibility.
- **In-memory only**: Restarting the orchestrator disarms the switch. This is intentional — it's a panic brake, not a persistent configuration. You don't want a tense mid-demo flip to silently persist past the event.
- **Audit monitor holds no state**: If the audit monitor crashes, the switch (already set in the orchestrator) keeps working. The browser's 5s poll is the only sync mechanism — two operators on two browsers stay consistent within 5s automatically.

### 4.3 Future: Manifold-Driven Kill Switch

For Black Hat Vegas, a key objective is extending kill switch control to be triggered by **Manifold rulesets** — not just manual operator action. If Manifold detects anomalous LLM behavior, cost spikes, prompt injection patterns, or other policy violations in the trace data, it should be able to programmatically arm the kill switch via the orchestrator's admin API.

---

## 5. Challenges Encountered

### 5.1 Project Nearly Cancelled — 72-Hour Pivot

The most significant challenge was non-technical. This project was nearly cancelled by the team, which severely limited prior planning and build-out time. Traditional approaches to design review, architecture approval, and phased development were not available.

I was able to pivot the idea by reframing the value proposition: the platform could **securely limit access to dangerous unencrypted traffic** while still enabling meaningful threat hunting. This addressed the team's primary concern — that exposing raw NOC telemetry to an LLM-powered interface could leak sensitive infrastructure details.

The solution was the silent guardrail architecture: restricted subnet ranges, zone names, and sensitive service identifiers are filtered at both the input (pre-classification) and output (post-agent) stages. The cover responses are indistinguishable from normal "no results" responses, so even adversarial probing cannot reveal what's protected.

With this security model validated, I built the proof of concept in **72 hours** while simultaneously performing my primary Black Hat NOC operational functions. The platform went from concept to live deployment serving real analyst queries against real Corelight/Zeek telemetry.

The result: I now have buy-in from the team. We are building toward a **"Remote NOC"** deployment for Black Hat USA 2026 in Vegas, which will be on the vendor floor and will target having **attendees perform threat hunting using the agentic platform**. This is a significant expansion from a back-of-house NOC tool to a public-facing interactive experience.

### 5.2 Custom Agent Connection Integration

Integrating Manifold with our custom agent architecture presented friction. Our agents are not off-the-shelf LangChain agents or standard chatbot frameworks — they're purpose-built FastAPI services with custom routing, guardrails, and multi-agent orchestration. The standard Manifold integration paths assume a more conventional agent topology.

Specific challenges:
- **Traceloop SDK was a dead end**: An early attempt to use `traceloop-sdk` for LangChain instrumentation demanded its own API key and tried to ship spans to `api.traceloop.com` — not to our Manifold tenant. Abandoned in favor of the LangSmith OTEL bridge.
- **LangChain import order sensitivity**: LangSmith's OTEL bridge reads environment variables at import time. If any `langchain*` module was imported before `init_telemetry()` ran, the bridge was inert and no GenAI spans were emitted. Required restructuring every agent's module initialization.
- **`ProxyTracerProvider` confusion**: `init_telemetry()` was being invoked in test processes but not in the actual uvicorn worker, resulting in traces silently going nowhere. Diagnosed by exec'ing into containers and inspecting `trace.get_tracer_provider()`.
- **Thinking model timeouts**: Gemini 3.1 Pro thinking-mode calls hit 504s with 3-5 minute latency, exceeding the orchestrator's 90s downstream timeout. Required raising timeouts and ultimately switching to `thinking_budget=0` on Flash-Lite paths.
- **EC2 credential expiry**: Module-level boto3 client caching held onto credentials from container start. After ~6 hours, S3 span exports and Athena queries started returning `ExpiredToken`. Fixed by constructing fresh `boto3.Session` per call — a pattern now enforced across all shared modules.

### 5.3 Nginx Upstream Caching

Docker container recreation (image rebuild, env change) assigns new IPs. Nginx's `upstream {}` blocks resolve service hostnames once at config-load time and cache forever, causing 502s after any container restart. Fixed with variable-based `proxy_pass` that forces re-resolution via Docker's embedded DNS every 10 seconds.

---

## 6. What We Observed

### 6.1 Platform Performance

- **Typical query latency**: 5-15s (athena-hunter/alert-triage), 2-4s (thousandeyes), <1s (cover/guardrail paths)
- **LLM classifier accuracy**: 15/15 routing tests passing across all 4 intents + guardrail
- **Guardrail integrity**: 5/5 leak probes returned zero leak strings — no `guardrail`, `refused`, `rephrase`, or `off-topic` appeared in any response
- **Telemetry lag**: S3 spans land within ~5s of query completion; audit monitor updates within 2s of S3 write
- **Model**: Gemini 3.1 Flash-Lite-Preview at `(0.05, 0.20)` per 1M in/out tokens — cost-effective for demo-scale traffic

### 6.2 Real Threat Findings

During live NOC operation, the platform surfaced actionable findings including:
- **NetSupport RAT C2 patterns** in connection logs
- **Registration Web-to-DB lateral movement** across zone boundaries
- **27 Zoho TLS connections** to unexpected endpoints
- **Beaconing patterns** in DNS and connection duration data

### 6.3 Observability Value

The dual Manifold + S3 export design proved its worth:
- **Manifold** provides the long-term system of record — aggregate dashboards, LLM cost tracking, historical query analysis
- **S3 + audit monitor** provides the real-time operator cockpit — immediate visibility during live demos and NOC operations
- Both read the same span stream, so there's no data divergence

---

## 7. Key Requirements from Manifold for Black Hat Vegas

Black Hat USA 2026 in Las Vegas represents a major expansion: from a back-of-house NOC tool to a **public-facing, vendor-floor "Remote NOC"** where conference attendees will perform interactive threat hunting using the agentic platform. The scale, visibility, and security requirements are significantly higher.

### 7.1 Seamless Integration into Our Custom Application

We need Manifold to integrate seamlessly into our custom multi-agent architecture with full visibility and monitoring of LLM/agent interactions. Specifically:

- **Support for custom agent topologies**: Our orchestrator → specialist agent routing doesn't map to standard chatbot or single-agent patterns. Manifold should be able to ingest and visualize our multi-hop distributed traces (orchestrator → classify → dispatch → agent → Athena/API → LLM) as a coherent workflow, not just individual spans.
- **GenAI semantic convention support**: The LangSmith OTEL bridge emits `gen_ai.*` attributes and events. Manifold's LLM panel should fully parse these for prompt/completion display, token accounting, and cost estimation.
- **Custom attribute visibility**: Our spans carry domain-specific attributes (`filter.restricted`, `filter.guardrail`, `filter.kill_switch`, `routing.intent`, `classification.confidence`, `sql.query`, `athena.data_scanned_mb`). These should be searchable and filterable in Manifold's UI.
- **Reduced integration friction**: The Traceloop SDK dead-end and LangChain import-order issues cost significant time during the Asia build. For Vegas, we need a documented, tested integration path for custom Python FastAPI agents using LangChain + LangSmith OTEL bridge that doesn't require trial-and-error.

### 7.2 Alert Triggering and Kill Switch Control Based on Manifold Rulesets

The current kill switch is manually operated from our audit monitor. For Vegas, we need Manifold to be an active participant in threat response:

- **Automated kill switch activation**: Manifold should be able to call our orchestrator's `POST /admin/killswitch/athena` endpoint when its rulesets detect concerning patterns — anomalous LLM behavior, prompt injection attempts, cost spikes, or policy violations.
- **Alert rules on custom metrics**: `bhnoc.tokens`, `bhnoc.cost.usd`, and `bhnoc.llm.duration_ms` are already being exported. Manifold should support alerting thresholds on these (e.g., "if `bhnoc.cost.usd` exceeds $X in Y minutes, trigger kill switch").
- **Pattern detection on trace attributes**: Alert when `filter.guardrail=true` spikes above a threshold (indicating active probing), or when `classification.confidence` drops consistently (indicating model confusion).
- **Webhook / API callback**: A documented webhook mechanism for Manifold to push alerts back to our infrastructure for automated response.

### 7.3 Administrative Dashboard with Easy Real-Time Monitoring

We built our own swim-lane dashboard because we needed real-time, unfiltered, demo-legible visibility. For Vegas, we'd like to evaluate whether Manifold can provide this natively:

- **Real-time span streaming**: Sub-5-second latency from span emission to dashboard visibility. Our current S3 poll loop achieves ~7s end-to-end; direct OTLP → dashboard should be faster.
- **Swim-lane or workflow view**: Ability to see the orchestrator → agent → LLM chain unfold per-query, not just aggregated metrics. Think "what is this specific query doing right now" rather than "what's the P99 latency."
- **LLM prompt/completion inspection**: Click-to-expand on any LLM span to see the full prompt messages and completion text. This is the primary debugging and demo tool for SOC operators.
- **Custom dashboard embedding**: If Manifold provides a dashboard URL or iframe-able view, we can embed it in our admin interface alongside the swim lanes, giving operators a unified console.
- **See our custom swim-lane implementation** (`tools/audit-monitor/`) as a reference for the UX we need — it was built because this specific view didn't exist elsewhere.

### 7.4 Technical Debrief on Observed Data

We are exporting comprehensive telemetry to Manifold — distributed traces, LLM spans with full prompt/completion text, custom metrics, and correlated logs. For Vegas planning, we need Manifold's analysis of what they observed:

- **LLM behavior patterns**: What did the GenAI span data reveal about model performance, token efficiency, and response quality across the different agent types?
- **Cost and usage trends**: What does the `bhnoc.cost.usd` and `bhnoc.tokens` data show over the course of the Asia event? Are there optimization opportunities?
- **Trace topology insights**: From Manifold's perspective, how does our multi-agent distributed trace topology compare to other integrations? Are there structural improvements that would make the data more useful in Manifold's analytics?
- **Security observations**: Did Manifold's analysis surface any patterns in the trace data that we didn't catch ourselves — unusual query patterns, LLM behavior anomalies, or telemetry gaps?
- **Recommendations for Vegas scale**: The Vegas deployment will have significantly more concurrent users (vendor floor attendees vs. NOC operators). What changes to sampling rate, export frequency, or span structure would Manifold recommend?

---

## 8. Design Decisions Worth Highlighting

### 8.1 Silent Guardrails

Every filtered response — restricted range, guardrail refusal, kill switch — returns the **identical** cover response. No error codes, no "I can't help with that," no signal whatsoever that content was blocked. This prevents adversarial fuzzing and maintains the illusion of a fully open system while protecting sensitive infrastructure. Admin spans carry the truth (`filter.*` attributes) for operator visibility.

### 8.2 Dual Export (Manifold + S3)

Not a hedge against Manifold reliability — a deliberate architectural decision. Manifold owns historical analytics and alerting. S3 owns forensic retention on our terms plus the real-time admin surface. Same data, different access patterns, different retention policies, different failure domains.

### 8.3 LangSmith Bridge Over Custom Instrumentation

Zero lines of manual LLM span code. The LangSmith OTEL bridge captures everything automatically through env-var configuration. This means adding a new agent or changing the LLM provider requires no instrumentation changes — spans just appear.

### 8.4 In-Memory Kill Switch

Restarting the container disarms the switch. This is a feature, not a bug — panic brakes shouldn't persist past the event that triggered them, and the operator who flipped it should be the one who decides when to re-enable.

---

## 9. Looking Forward — Black Hat Vegas 2026

### 9.1 The Remote NOC

The Vegas deployment represents a fundamental expansion: from a back-of-house NOC analyst tool to a **public-facing "Remote NOC" on the vendor floor** where conference attendees will interactively hunt threats using the agentic platform.

This changes the requirements profile:
- **Higher concurrency** — dozens of simultaneous users vs. a handful of NOC analysts
- **Adversarial users** — attendees at a security conference will absolutely probe the guardrails
- **Demo reliability** — every query needs to return something useful in a reasonable time, with graceful degradation
- **Manifold as mission-critical** — real-time monitoring and automated kill switch become operational requirements, not nice-to-haves

### 9.2 What We're Building

- Scaled infrastructure (likely multi-instance or container orchestration)
- Hardened guardrails tested against red-team probing
- Manifold-integrated alerting and automated response
- Enhanced audit dashboard (potentially co-developed with Manifold)
- Attendee-facing onboarding flow with guided threat hunting scenarios

### 9.3 Partnership Model

The Asia deployment proved the concept. Vegas is where we prove the partnership. We're looking for Manifold to be a deeply integrated observability and safety layer — not just a trace destination, but an active participant in the platform's security posture through ruleset-driven alerting and automated response.

---

## Appendix A: File Map

| Path | Role |
|------|------|
| `agents/shared/telemetry.py` | `init_telemetry()`, OTLP + S3 exporters, LangSmith bridge wiring |
| `agents/shared/s3_span_exporter.py` | S3SpanExporter (gzip NDJSON to Hive partitions) |
| `agents/shared/llm_client.py` | LangChain wrapper, custom GenAI metrics |
| `agents/shared/athena_client.py` | SELECT-only Athena wrapper, date partitioning |
| `agents/orchestrator/main.py` | Routing, classify, guardrails, kill switch, output sanitizer |
| `agents/athena-hunter/main.py` | NL-to-SQL, multi-query execution, result synthesis |
| `agents/alert-triage/main.py` | Athena-backed alert prioritization |
| `agents/threat-hunter/main.py` | S3 raw Zeek fallback |
| `agents/thousandeyes-analyst/main.py` | ThousandEyes API integration |
| `packages/web-server/` | Fastify web server + static SPA |
| `tools/audit-monitor/` | FastAPI + SSE swim-lane dashboard |
| `docker-compose.agents.yml` | Full 8-container stack |
| `nginx/nginx-ssl.conf` | TLS + reverse proxy with DNS re-resolution |

## Appendix B: Environment Variables (Manifold-Relevant)

| Variable | Default | Purpose |
|----------|---------|---------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `https://blackcap.app.manifoldsecurity.io:4318` | Manifold OTLP base URL |
| `OTEL_EXPORTER_OTLP_API_KEY` | *(required)* | Manifold bearer token |
| `OTEL_SERVICE_NAME` | per agent | `bhnocgentic-<role>` |
| `OTEL_ENABLED` | `true` | Master toggle |
| `OTEL_SAMPLE_RATE` | `1.0` | Parent-based ratio sampler |
| `OTEL_METRICS_INTERVAL_MS` | `60000` | Metric export cadence |
| `TRACE_S3_ENABLED` | `true` | S3 sister exporter toggle |
| `TRACE_S3_BUCKET` | `blackhatnoc` | Span archive bucket |
| `TRACE_S3_PREFIX` | `bh-asia-26/aing-trace` | S3 path prefix |

---

*BHNOCgentic — Black Hat Asia 2026 NOC*
*Live at `https://aing.bhnoc.com`*
*Report date: 2026-05-18*
