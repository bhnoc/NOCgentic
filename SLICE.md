# SLICE 1 — Vector recall + agentic root-cause (level9000)

## Contract
- **Goal:** Given a network-security anomaly, answer "have we seen this before?" — cluster the
  spiking events into templates, vector-search past templates/incidents, correlate with deploy/commit
  markers, and propose a root cause — with a fully auditable glass-box reasoning trace.
- **Acceptance (observable, via API):**
  1. `POST /ingest` of raw Corelight events → Drain templates created; 50k identical lines collapse to 1 template; IPs/UIDs/ports masked out of the template.
  2. `GET /similar?text=<known signature>` → returns the previously-ingested template as nearest neighbor (distance ~0).
  3. `POST /incidents` records a resolved incident with its embedding.
  4. `POST /investigate` → returns a `finding` (title/severity/summary/root_cause/recommendation) + `evidence` (the exact queries/templates + sampled rows) + a `run_id`.
  5. `GET /runs/:id` → the append-only event trace for that run, in order: plan → anomaly query → cluster → recall → correlate → verdict.
  6. When a seeded `deploy_marker` sits inside the spike window, the finding's root_cause references it (code-computed correlation, not LLM guess).
- **Done:** acid harness green from a clean `docker compose up` (postgres+pgvector + root-cause), using the stub embedder + fixture data source (no live Athena/Gemini needed offline). Live Athena/Gemini path smoke-tested on-box at deploy.

## Data reality
Athena holds **Corelight/Zeek network telemetry**, NOT app logs/stack traces. So the "novel stack trace"
analogue = a rare/new `suricata_corelight` alert signature, Zeek `notice.note`, or `weird.name`. Filter
to high-signal only (drop ET INFO noise, drop routine notices) — the NOC equivalent of "drop INFO/DEBUG".

## Architecture — new service `root-cause` (port 8006) + postgres(pgvector) container
Reuses `agents/shared/{athena_client,llm_client,telemetry}.py`. Data/voice split from PostCog:
**code owns anomaly detection, clustering, similarity, correlation, verdicts; the LLM writes only prose.**

## Pinned interfaces (build to these exactly)

### agents/shared/templating.py  (pure, deterministic, drain3-backed — NO LLM)
```python
EMBED_MASK_TOKENS = {...}  # <IP> <UID> <PORT> <HEX> <NUM> <TS> <MAC> <DOMAIN>
def premask(raw: str) -> tuple[str, dict[str,list[str]]]:
    """Deterministically mask dynamic tokens BEFORE Drain. Returns (masked, {tok:[vals]})."""
class TemplateMiner:
    def __init__(self, state_path: str | None = None): ...   # drain3, persistent state optional
    def add(self, raw: str) -> dict:   # {"template_id":str,"template":str,"cluster_size":int,"params":dict}
    def match(self, raw: str) -> dict | None:  # non-mutating lookup
    def templates(self) -> list[dict]
```
Tests (own gate, `tests/python/test_templating.py`): determinism (same in→same template);
IP/UID/port masked; N identical → 1 cluster; two different sigs → 2 templates.

### agents/shared/embeddings.py  (pluggable; real=irreducible LLM, stub=deterministic)
```python
EMBED_DIM = 768   # gemini text-embedding-004
def is_stub() -> bool               # True when GEMINI_API_KEY unset
async def embed(texts: list[str]) -> list[list[float]]   # L2-normalized, len==EMBED_DIM each
```
Real: gemini `text-embedding-004` via langchain_google_genai (reuse GEMINI_API_KEY). Stub: hashed
char-ngram → fixed 768 vec, L2-normalized, deterministic (same text→same vec; different→different).
Tests: dim==768, normalized, deterministic, stub active without key.

### agents/shared/store.py  (+ agents/root-cause/migrations/0000_recall.sql)
Postgres via psycopg (v3). PG creds are static env (unlike Athena/IMDS) so a module-level pool is fine.
Env: `PG_DSN` (e.g. postgresql://nocgentic:pw@postgres:5432/nocgentic).
```python
def init_schema() -> None                         # idempotent; CREATE EXTENSION vector; run migration
def upsert_template(template, sample, mask_keys, source, embedding) -> str
def similar_templates(embedding, k=5) -> list[dict]   # {id,template,distance,count,source,last_seen}
def record_incident(title, summary, root_cause, resolution, embedding, template_id=None,
                    deploy_marker=None, commit_sha=None) -> str
def similar_incidents(embedding, k=5) -> list[dict]
def add_deploy_marker(ts, kind, ref, commit_sha=None, note=None) -> str
def markers_near(ts_start, ts_end) -> list[dict]
def start_run(kind, input) -> str
def emit(run_id, event_type, data) -> None        # append-only agent_events, auto seq
def finish_run(run_id, status, output) -> None
def get_run(run_id) -> dict                        # {run:{...}, events:[...ordered]}
```
Migration tables: `log_templates(id,template UNIQUE,sample,mask_keys jsonb,source,first_seen,last_seen,count,embedding vector(768))`,
`incidents(id,title,summary,root_cause,resolution,template_id,embedding vector(768),created_at,resolved_at,deploy_marker,commit_sha,status)`,
`deploy_markers(id,ts,kind,ref,commit_sha,note)`,
`agent_runs(id,kind,input jsonb,output jsonb,status,started_at,finished_at,token_usage jsonb)`,
`agent_events(id bigserial,run_id,seq int,ts,event_type,data jsonb)`. HNSW/ivfflat index on both embeddings.
Tests: schema init idempotent; upsert dedups on template; similar_* returns nearest by cosine; run/event round-trip. (Uses a local postgres — gate skips if `PG_DSN` unreachable.)

### agents/root-cause/main.py  (FastAPI, port 8006) — the integrator + agentic loop
Data source seam: `AnomalySource` protocol — prod impl uses athena_client; tests inject a fixture.
```
GET  /health
POST /ingest       {events:[{raw,source,ts}]}  OR {from_athena:true,hours:N} -> {templates_upserted,...}
GET  /similar?text=...&k=5   -> {templates:[...], incidents:[...]}
POST /incidents    {title,summary,root_cause,resolution,deploy_marker?,commit_sha?} -> {id}
POST /investigate  {query, window_hours} -> {run_id, finding, evidence}
GET  /runs/{id}    -> {run, events}
```
`/investigate` loop (each step -> store.emit): plan → detect_anomaly(window) [Athena time-series, code] →
cluster spiking events (templating) → embed top template → similar_incidents+similar_templates (recall) →
markers_near(spike window) correlate (code) → code-computed assessment → LLM prose synthesis (voice only) →
finding. Bound: max window 48h, top-K templates, per-run token budget.

## Model routing (this slice)
- templating.py → sonnet-5 (masking correctness matters)
- embeddings.py → sonnet-5 (small but seam design)
- store.py + migration + compose → sonnet-5 (schema design)
- root-cause service (integrator) → sonnet-5, judge/verify at opus if it misses
- harnesses → build after primitives land
