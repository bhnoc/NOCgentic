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

### SLICE 2 — DONE & GREEN (2026-07-30). Autonomous investigation loop + glass-box trace.
- New: `agents/shared/tool_provider.py` (ToolProvider protocol; GeminiToolProvider via langchain_google_genai bind_tools, lazy import; FixtureProvider + InfiniteToolProvider for offline tests; is_stub()).
- New service: `agents/investigator/` (FastAPI :8007) — `POST /investigate {query,window_hours,max_depth}` → `{run_id,finding,evidence}`, `GET /runs/{id}`, `GET /health`. Ported PostCog `_chat_with_tools` recursive Athena tool loop + `validate_query` (dt-filter/SELECT guard) + `format_results` (_FIELD_BUDGETS) + `detect_high_signal` (_HIGH_SIGNAL_RE). Reuses store.py run/event tables (kind="investigation"), NO new tables.
- Data/voice split: code owns validate/format/high-signal/severity/verdict/evidence; ONE llm_complete prose call + the tool-loop provider.chat (both irreducible). Codification pass done.
- docker-compose: `investigator` service added (:8007, depends postgres healthy).
- Gates: added test_investigator.py to acid.sh. Full suite now **63 green** (20+13+11+12+7).
- **Verified from CLEAN**: acid 63 green; cold `docker compose up postgres investigator` → schema init OK, /health llm_stub:true, /investigate w/o key → clean **503** + persisted failed run (trace: plan,error).
- BUG FIXED (caught by container verify, same class as slice 1): the recall migration was only COPYed by root-cause's Dockerfile, so investigator couldn't init schema. MOVED migration to `agents/shared/migrations/0000_recall.sql` (ships with agents/shared/ to every service); store._resolve_migration_path() now finds it beside store.py; removed root-cause Dockerfile's migration COPY.
- ROBUSTNESS FIX: /investigate creates the run + emits "plan" BEFORE constructing the provider, so an immediate provider failure still leaves an auditable trace; provider-init failure → 503 (config problem) not 500 (bug).
- NOT yet wired into orchestrator/UI (deferred, same as root-cause).

### SLICE 3 — DONE & GREEN (2026-07-30). Triage hub + alert bucket state machine.
- New migration `agents/shared/migrations/0001_triage.sql`: `alerts` (dedup_key unique, bucket TEXT, severity, ips, signature, count, raw_data) + `bucket_transitions` (from/to bucket, reason, investigation_run_id). init_schema() now globs migrations/*.sql sorted (runs 0000+0001).
- store.py: added BUCKETS + LEGAL_EDGES state machine + upsert_alert/get_alert/list_alerts/transition_alert(guard+force)/alert_transitions.
- New service `agents/triage/` (FastAPI :8008): POST /alerts (dedup), GET /triage/queue, POST /triage/{id}/investigate (alerts→validating→verdict, calls investigator, files bucket + 2 audited transitions linked to run_id), GET /triage/{id}, POST /triage/{id}/transition (guarded, force overrides+audits). InvestigatorClient seam (HttpInvestigatorClient prod / Fake for tests). ZERO LLM calls — pure deterministic orchestration + code verdict→bucket mapping.
- docker-compose: `triage` service (:8008, INVESTIGATOR_URL=http://investigator:8007).
- Gates: added test_triage.py to acid. Full suite now **82 green** (20+13+11+12+7+19).
- **Verified from CLEAN**: acid 82 green; guard gate PROVEN to bite (patched LEGAL_EDGES → illegal-edge test fails, restored → passes). Cold `docker compose up postgres investigator triage` → both migrations init in-container; live HTTP: ingest+dedup(count→2), queue ordered, illegal edge→409, unknown→400, force→200+audit, investigate w/ keyless investigator→502 + alert rolled back alerts→validating→alerts (both audited).
- NOT yet wired into orchestrator/UI (deferred).

### SLICE 4 — DONE & GREEN (2026-07-30). Wire services into the app: glass-box + triage UI.
- BACKEND: `packages/web-server/src/api/proxy.ts` — same-origin /api/v1 proxy to investigator/triage/root-cause (6 routes, :id validated, querystring passthrough, 502 on upstream down). Registered in index.ts. Env INVESTIGATOR_URL/TRIAGE_URL/ROOT_CAUSE_URL added to web-server compose + depends_on. vitest 36/36 (13 new in proxy.test.ts), tsc clean, chat.ts untouched.
- FRONTEND: `static/index.html` (1736→2373 lines) — Chat|Triage view switcher, Triage Queue (grouped by bucket, severity chips, Run-triage buttons), slide-in Glass Box panel (ordered event timeline: plan→queried Athena→read→verdict→finding, with SQL + deductions). Deep links ?view=triage & ?trace=<run_id>. Reuses existing CSS vars + escHtml. No new deps.
- FIX (caught by live screenshot, NOT unit tests): triage severity is NUMERIC (1..4) from store, frontend assumed string → `(a.severity||'low').toLowerCase()` threw. Added sevLabel() mapping int|string. THIRD instance of "clean-state/live verify catches what unit tests miss" this session.
- Demo seed: `agents/triage/qa/seed_demo.py` (gitignored dir, force-added) — seeds alerts + one traced run.
- **Verified from CLEAN**: full compose stack up, seeded, headless-Chrome screenshots of BOTH surfaces (triage queue + glass-box trace) render correctly against live services. Screenshots in temp/shots/.
- Delivers 3 headline features: Glass Box Transparency, Investigations Triage Hub, AI Chatbot Interface (chat preserved).

### SLICE 5 — DONE & GREEN (2026-07-30). Operational-context memory / semantic DB.
- New migration `0002_memory.sql`: agent_memory (versioned, lifecycle status, confidence, usage, drift cols for later) + memory_events audit.
- store.py: MEMORY_STATUSES/CATEGORIES/LIFECYCLE + upsert_memory (version bump on agent_slug+key) / get / list / transition_memory (guard mirrors alert bucket) / active_memories / bump_memory_usage.
- `agents/shared/memory_prompt.py`: SECURITY-CRITICAL sanitizer — 15-pattern injection deny-list, in-place [redacted], length cap, control-char strip; build_memory_block routes EVERY string through it + defensive header. PURE.
- `agents/memory/` service (:8009): CRUD + promote/retire/transition + /memory/context. ZERO LLM (deterministic store + regex).
- INTEGRATION: investigator injects the sanitized active-memory block into its system prompt (in-process, guarded; emits memory_write trace event). tool_provider.FixtureProvider now records seen_messages.
- docker-compose: `memory` service (:8009).
- Gates: test_memory_prompt (35, pure) + test_memory (30) + investigator memory-injection integration test. Full acid **224 green**. Security gate PROVEN to bite (neuter sanitizer → 20 fail).
- **Verified from CLEAN**: memory service container lifecycle over HTTP (draft→candidate→active, 409 on illegal promote, /memory/context redacts injection while keeping the operational fact). Used `down -v` to reset pgdata volume when a stale-volume reading confused a smoke run — lesson: reset the volume for clean container smokes.
- Delivers: Operational Context Memory, Semantic Database, Automated Learning (manual/API-driven promotion this slice; auto-drift engine deferred).

## CURRENT STANDING (2026-07-30)
Branch level9000, 8 commits past main. Python acid **224 green** + web-server vitest 36 green. Docker: colima;
throwaway `nocgentic-pgtest` on host:5432 for the acid gate (NOTE: compose has a `pgdata` volume — use
`docker compose down -v` for a truly clean container smoke). NOT deployed to AING box (local only).

SIX new services/modules, all API+container verified from clean, none yet wired into the orchestrator's
intent router. BLOCKER for orchestrator wiring: `bench/prompt_eval/run_eval.py` hits a LIVE app
(aing.bhnoc.com) + real Gemini classifier — cannot gate that change locally without the key/box. Must be
done on/against the box. No Gemini key locally → investigate/embed live LLM paths degrade gracefully
(503/stub) and are proven in-process; full LLM path needs the key on the box.

### Remaining candidate slices (not yet built)
- Wire new services into orchestrator intent routing — GATED vs bench/prompt_eval, must run against the box.
- Auto-drift memory engine (VR memorySelfImprove: z-test/CUSUM/Wilson promote/retire) — deferred from slice 5.
- Proactive threat-hunting scheduler (cron the investigator over MITRE hunt templates from VR th-guide.json).
- Autonomous agent collaboration (orchestrator delegates + shares context across the new agents).
- Deploy to AING box + on-box smoke with real Gemini key + run prompt_eval.

### SLICE 3 (original heading, superseded):
Port VR's alert `bucket` lifecycle (alerts→validating→validated_TP/FP/bad_hygiene + hunting_*) +
`bucket_transitions` audit + finding contract, with an autonomous triage worker that pulls alerts
(alert-triage agent / Athena alerts table), runs the investigator loop per alert, and files a
verdict into a bucket. Reuses store.py (add alerts + bucket_transitions tables via a new migration
0001) + the investigator service. Surfaces as a triage queue API. This is the "Investigations Triage
Hub" feature. THEN: wire investigator+root-cause+triage into orchestrator routing (gated vs its eval suite); UI glass-box.

### (superseded) SLICE 2 original heading:
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
