# HANDOFF — level9000: port virtual_resident/PostCog patterns into NOCgentic

**Branch:** `level9000` (off `main`). **Started:** 2026-07-30. **Driver:** rapid-prototype harness.
**Goal (one sentence):** Take NOCgentic from single-pass Q&A microservices to an autonomous
SOC-analyst platform — an iterative investigation loop with a glass-box reasoning trace,
operational-context memory, a triage hub, and (new) vector search over unstructured traces —
Athena-only, no multi-tenant/multi-SIEM.

## The three codebases

### Target: NOCgentic (this repo) — Python/FastAPI + TS/Fastify, Athena-backed
- Live at `https://aing.bhnoc.com` on EC2 box AING (`i-0430224b1ac82701e`, us-west-2). Docker-compose stack.
- **Agents (Python, FastAPI HTTP microservices, all SINGLE-PASS, no loop/memory/vector):**
  - `agents/orchestrator/main.py` (8001) — intent classifier → routes to ONE specialist over HTTP. `POST /query`.
  - `agents/alert-triage/main.py` (8003) — Athena alerts triage; deterministic `score_alert`, `correlate_alerts_with_flows`.
  - `agents/athena-hunter/main.py` (8005) — NL→SQL hunt: `generate_sql`→execute-all→`llm_analyze`. One round, no pivot loop.
  - `agents/thousandeyes-analyst/main.py` (8004) — TE REST API (not Athena).
- **agents/shared/ (the seams to REUSE):**
  - `athena_client.py` — `execute_query(sql)`, `execute_custom_sql`, `query_by_ip/uid/alerts/dns/ssl/top_talkers`, `sanitize_sql` (SELECT-only, blocks DDL/DML/UNION/comments), date-partition helpers. Fresh boto3 client per call (IMDS cred rotation). 500-row cap. DB `blackhat_pope_logs`, workgroup `blackhat-pope-dev`.
  - `llm_client.py` — `llm_complete(system, user, ...)`, `get_last_llm_metrics()`. Providers via `LLM_PROVIDER`: gemini (default `gemini-3.5-flash-lite`), openrouter, local (AQLight). Hybrid: `SQLGEN_PROVIDER=local` routes NL→SQL to AQLight. LangChain-based, OpenInference auto-traced.
  - `telemetry.py` — OTEL + OpenInference. `init_telemetry`, `set_agent_span/set_chain_span/set_tool_span`. Ships to Manifold + gzip NDJSON to S3.
  - `s3_span_exporter.py` — S3 NDJSON span archive (only S3 writer).
- **TS layer (thin gateway):** `packages/web-server` Fastify — `POST /api/v1/chat` (mint job, dispatch to orchestrator), `GET /api/v1/chat/:id` (poll), `/ws` (alert feed broadcast), `static/index.html` (1736-line single-file chat SOC console: chat + alert sidebar + 4 stat tiles + agent badges + confidence bar + hint chips). Job store = in-memory Map, 1h TTL. `agent-sdk`/`shared` packages largely vestigial.
- **NO persistence DB anywhere.** NO vector/embeddings/Drain/KG/semantic memory. Athena + in-memory only.
- **LLM eval history:** hybrid Gemini+AQLight is default; docs/llm/ has the eval reports.

### Port source A: virtual_resident (`/Users/landbeforetime/Documents/dev/mcp/virtual_resident`) — Nx TS monorepo, the CROWN JEWEL
- **The agentic loop is `apps/vr-backend/src/agent/graph.ts`** (LangGraph StateGraph, NOT the investigator/ dir):
  - Two nodes `agent`↔`delegation`, hub-and-spoke (specialists NEVER talk peer-to-peer; orchestrator synthesizes).
  - `GraphState` blackboard: messages[], agentSlug, runId, pendingDelegation, delegationResults[], skillResults[], status, humanInputRequired, checkpointData.
  - `agentNode`: load def → resolve model+fallback → **inject memory into system prompt** (rank active/candidate by confidence→usage→recency, cap 40) → run skillExecutor OR tool-loop (`MAX_TOOL_ROUNDS=10`) → parse delegation JSON or finalize. **"Answer now" interrupt** polls between rounds → unbound synthesis.
  - `parseDelegation`: balanced-brace JSON `{delegate_to, skill, reason, inputs}` + ~18 text-pattern fallbacks.
  - **`emitEvent`** = the glass-box: writes `agent_events` row + fires live callback. Event enum: delegation, tool_call, tool_result, llm_start/chunk/end, llm_fallback, skill_step_start/end, memory_write, dynamic_step_inserted, verdict, stage_transition, human_input_required, error.
- **`apps/vr-backend/src/agent/skillExecutor.ts`** — multi-step skill runner + **actor/judge dynamic re-planning** (`proposeAndJudgeLead`): after each step, ACTOR proposes one new lead from observed indicators, separate JUDGE (senior-SOC-lead prompt) approves/rejects; approved leads splice into queue. Bounded `maxDynamicSteps=5`, depth-1. Skills = YAML (steps w/ system_prompt, mustache user_prompt_template, expected_outputs, tools).
- **Persistence (`apps/vr-backend/drizzle/0000_baseline.sql`, Postgres):**
  - `agent_runs` (agent_slug, parent_run_id, trigger enum, input/output jsonb, status enum, checkpoint_data, token_usage, conversation_id, alert_id, finding_id) + `agent_events` (append-only trace, event_type enum, data jsonb) — **event-sourced glass box**.
  - `agent_memory` (agent_slug+key unique, category [fact/prompt_refinement/preference/lesson_learned], memory_status [draft→candidate→active→retired], version, confidence_pct, usage_count, drift_score_pct) + `agent_memory_versions` + `memory_events` + `memory_proposals` (shadow-mode human-approval). Self-improve engine `memorySelfImprove.ts`+`driftStats.ts` (z-test + CUSUM + Wilson CI, off/shadow/live). **NO embeddings — key/value + stats.**
  - `assets` (ip unique, hostname, mac, classification enum, criticality, services/software/network_profile jsonb, is_ephemeral) + `asset_snapshots`/`asset_review_items`/`asset_imports` — operational-context inventory. Signal-based classifier (`assetClassifier.ts`), not ML.
  - `alerts` (dedup_key unique, **bucket enum** = triage state machine: alerts→validating→validated_true_positive/false_positive/bad_hygiene + hunting_* + traffic_anomaly + tuning_queue) + `bucket_transitions` (audit from/to/reason). `findings` (finding_type, stage, hypothesis, mitre_technique, evidence jsonb, verdict, confidence, reasoning). `investigations` (entities/relationships/timeline jsonb = link-analysis graph).
  - `0002_cve_mirror.sql` — offline NVD mirror `cve_entries`(cpe,cve_id,cvss,severity)+`cve_sync_state`. Maps asset CPEs → CVEs offline.
- **Finding contract `apps/vr-backend/src/reports/findingContract.ts`** — `ReportFinding {id,title,severity,category,summary,affected{subnets/hosts/entities},evidence{metrics,queries:EvidenceQuery[]},reasoning,recommendation,runId,stepNumber}`; `EvidenceQuery {tool,query,rowCount,rowsSample,resultText}`. Evidence back-filled from agent_events tool_call→tool_result. **MOST reusable glass-box output model.**
- **Portable pure logic (TS→Python):** `libs/connectors/src/investigator/logic.ts` (parseTimeRange, calculateResultLimit, isThreatQuery, parseSearchQuery, `guardCql`→adapt to guard SQL, severityToScoreRange), `logsExecutor.ts` (structured-input→query-string + injection-safe quoting), `utils/threatClassifier.ts` (9 THREAT_CATEGORIES static playbook dict), `entityDetection.ts` (IOC regex), `relationshipDetection.ts` (tool-result→graph edges), `parameterExtractor.ts` (auto-fill next query from last result), `tokenCompressor.ts`.
  - `libs/connectors/src/lib/schemas/*` + `INVESTIGATOR_SCHEMA_META` — Zeek/Corelight field catalog (conn/dns/http/ssl/files/notice/weird/suricata_corelight) + `commonWorkflows` playbook recipes. Field names match Corelight-in-Athena tables. Use for query-field validation.
- **`.agents/*.md`** — 5 role prompts (orchestrator/analyst/threat-hunter/detection-engineer/ir-responder), YAML frontmatter (slug, model primary/fallback, skills[], delegates_to[], schedule). Model-agnostic prompt content, port as-is.
- **Design docs (`plans/`):** EXECUTIVE_SUMMARY + MULTI_AGENT_ANALYSIS warn of the "multi-agent trap": token explosion, memory prompt-injection (memories injected unsanitized into system prompts — SANITIZE on port), 13-agent sprawl (>4 coordination threshold). CONNECTOR_CONTRACT = typed-tool + capability-registry (read ungated, mutating human-approval) + golden-fixture pattern. qa/HANDOFF.md cautionary tale: asset classification starved at INGESTION (only recorded dialed ports, not responder) — get log→asset signals right first.

### Port source B: PostCog (`/Users/landbeforetime/Documents/dev/blackhat/PostCog`) — Python Slack bot, PROVEN Athena analyst loop
- **`analyst.py` (1788 lines) = a working Python agentic loop already** — the closest substrate:
  - `LLMProvider` ABC + Gemini/OpenAI/Anthropic impls, `get_provider()` factory. Provider-neutral message dicts.
  - `ThreatAnalyst.analyze(thread_id, question, mode)` → `_chat_with_tools(messages, depth)` = **recursive multi-step tool loop, `MAX_TOOL_DEPTH=30`**, single `query_athena` tool. Genuine iterate: query→read→query.
  - **DATA/VOICE SPLIT (the hard-won lesson, `DESIGN-data-voice-split.md`):** code owns FACTS + control flow, LLM owns only PROSE. `_finalize_structured` returns JSON (voice_intro/findings/assessment), code renders deterministically (defanged) so model physically can't leak raw IP or paste SQL. `detect_high_signal` = code-computed threat verdict (scans for non-INFO Suricata sigs), forces threat block regardless of model lean. `_compute_host_facts` runs deterministic queries so code owns facts the model got wrong.
  - `SHARED_ATHENA_KNOWLEDGE` = persona-neutral Corelight schema + pivot tables + query templates (reusable prompt asset).
  - `defang()` / `defang_ip()` in `profiler.py` — robust standalone defanger.
  - Coupled only to `athena_client.athena` + persona strings. Highly portable.
- **`profiler.py`** — deterministic parallel-query IP→identity/org/platform profiler (5 fixed steps, thread pool). No LLM.
- **harness.py/suite.py** — offline eval: FakeClient sink + `check_policies` (no raw IPs, no links, context retention, no injection echo) + **LLM-as-judge** (`judge()` returns {factual,useful,persona,verdict,issues}). Reusable test pattern.

## Architecture decision (the port)
NOCgentic brain = Python + Athena. So: build a **new Python investigation engine** that fuses
PostCog's proven `_chat_with_tools` loop (already Python, already Athena) with VR's STRUCTURE
(event-sourced trace, memory lifecycle, finding+evidence contract, bucket state machine,
actor/judge re-planning). Reuse `agents/shared/{athena_client,llm_client,telemetry}.py`. Surface
the glass-box in the existing `static/index.html` chat console. Port VR/PostCog pure logic
(threatClassifier, entityDetection, guardSql, schema catalog) as deterministic Python — NOT LLM calls.

**Persistence:** VR uses Postgres. NOCgentic has none. DECISION PENDING (see scope Q): add a
postgres container to docker-compose vs SQLite to start. Event trace + memory + findings + buckets need it.

**New surfaces the user asked for that DON'T exist anywhere yet (genuinely additive):**
- Vector search over unstructured traces: Drain template clustering → embed unique templates (Bedrock Titan / OpenAI) → vector store (pgvector likely, since we're adding PG). Filter WARN/ERROR/stack only.
- Semantic memory / incident knowledge graph: link logs → deploy markers / commit SHAs; correlate spikes with pushes.
- Agentic root-cause: anomaly (Athena time-series) → fetch traces → vector-similar past incidents → propose fix.

## Model ladder (fetched live 2026-07-30 from ai.taileb6e.ts.net/v1/models)
- haiku-4-5 ($1) → sonnet-5 ($2) → opus-4-8 / opus-5 ($5, take highest). `opus-5` now exists.
- gemini-3.5-flash ($1.5), gemini-3-flash-preview ($0.5) also served.

## STATUS
User granted full autonomy (2026-07-30): build each slice, run gates, move to next without stopping.
Persistence decided: **Postgres+pgvector** container. First slice: **vector search + agentic root-cause**.

### SLICE 1 — DONE & GREEN (2026-07-30). Vector recall + agentic root-cause.
- New shared primitives: `agents/shared/{templating.py (drain3), embeddings.py (gemini text-embedding-004 + deterministic stub), store.py (psycopg3+pgvector)}`.
- New service: `agents/root-cause/` (FastAPI :8006) — `/ingest /similar /incidents /markers /investigate /runs/{id}`. The 9-step data/voice-split loop: plan→anomaly→cluster→recall→correlate→verdict→synthesis. Only 1 LLM call (prose), rest deterministic code. Codification pass done: LLM surface already minimal.
- Persistence: `postgres` (pgvector/pgvector:pg16) + `root-cause` added to docker-compose.agents.yml, `pgdata` volume. Migration `agents/root-cause/migrations/0000_recall.sql`.
- Gates: `agents/root-cause/qa/{smoke,acid}.sh`. Tests: test_templating(20)+test_embeddings(13)+test_store(11)+test_root_cause(12) = **56 green**. Gate proven to fail on broken state (reverted ::vector cast → 4 fail).
- **Verified from CLEAN**: cold `docker compose up postgres root-cause` → live HTTP: health, ingest dedup(50→1), similar(identical text dist=0.0), incident recall, /investigate returns run_id+finding+trace, graceful no-Athena degrade.
- Docs: `agents/root-cause/README.md` (deploy/ops/gotchas), `ATHENA_NOTES.md`. Routing memory: `ROUTING.md`.
- 2 real bugs caught ONLY by clean-state verify: pgvector `%s::vector` cast; migration path local-vs-container (now `store._resolve_migration_path()` + `RECALL_MIGRATION_PATH` env).
- Test venv is Python 3.14; psycopg_pool `__del__` PythonFinalizationError at shutdown is harmless.
- Throwaway `nocgentic-pgtest` container (port 5432) is up for the acid harness between rounds.
- NOT YET wired into orchestrator routing (deferred: orchestrator has a tuned eval suite; wire in a later gated step). Service is standalone + API-verified.

### SLICE 2 — NEXT: autonomous investigation loop + glass-box in the orchestrator/chat path.
Rationale: slice 1 built the trace/store substrate (agent_runs+agent_events) + a proven loop pattern
for ONE analysis type. Slice 2 generalizes it: port PostCog's `_chat_with_tools` multi-step Athena
loop into a first-class investigation engine the orchestrator can invoke, persisting the same
event-sourced trace, and surface the glass-box steps in static/index.html. This is the spine the
remaining features (triage hub, collaboration) all hang off. Reuse store.py's run/event tables.

## Open tasks / next steps
1. SLICE 2: investigation engine (port PostCog analyst loop → Python, Athena tool loop, event trace).
2. Then: triage hub + bucket state machine (slice 3).
3. Eventually wire root-cause + investigation into orchestrator routing (gated against its eval suite).

## Ranked gotcha list (most likely to bite)
1. **Memory prompt-injection** (VR design docs flag it): memories/asset-context injected into system prompts. SANITIZE before injection (length/char caps, malicious-pattern regex). Data/voice split from PostCog mitigates leaks outbound.
2. **Data/voice discipline**: don't give the LLM control over facts/flow. Code computes verdicts, renders findings, owns the loop. Every recurring PostCog bug came from violating this.
3. **Athena creds rotate** (~hours): never cache boto3 client (shared athena_client already handles this — reuse it, don't reinvent).
4. **Ingestion-starvation** (VR qa/HANDOFF): asset/context classification is only as good as the signals collected. Get the Athena queries to collect responder-side signals, not just initiated.
5. **Token explosion / loop cost**: bound tool rounds, per-run token budget + circuit breaker. VR RECOMMENDATIONS #2.
6. **Agent sprawl**: keep specialists ≤ ~4 (coordination threshold). Don't port all 5 VR agents if not needed.
7. **nginx upstream caching** (CLAUDE.md gotcha 1) + **nginx config edits need --force-recreate** not reload (ops skill).
8. **Never `pkill -f app.py`** on the box (hits PostCog too).
