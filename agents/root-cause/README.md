# root-cause service (level9000)

Vector recall + agentic root-cause for NOCgentic. Answers "have we seen this network
anomaly before?" — clusters spiking Corelight/Suricata events into templates, vector-searches
past templates + resolved incidents, correlates with deploy markers, and proposes a root cause,
emitting a fully auditable glass-box reasoning trace.

## What it is
- FastAPI service, port **8006** (internal only, like the other agents).
- Backed by a **Postgres + pgvector** container (`postgres` service, db `nocgentic`).
- Reuses `agents/shared/{athena_client,llm_client,telemetry}.py`.
- New shared primitives: `agents/shared/{templating,embeddings,store}.py`.

## Data/voice split (the discipline, ported from PostCog)
Code owns every FACT and the control flow; the LLM writes ONLY the final 2-3 sentence prose.
- **Code:** anomaly detection (per-signature time-series, mean+stddev, z-score, novelty),
  spike selection, Drain clustering, pgvector similarity, deploy-marker correlation, severity,
  recommendation selection, and all structured `finding`/`evidence` fields.
- **LLM (1 call):** `finding.summary` narrative, from a verified FACTS dict. Falls back to a
  deterministic string on any error. This is the only irreducible model call besides embeddings.

## Endpoints
| Method | Path | What |
|---|---|---|
| GET | `/health` | `{status, service, embed_stub}` |
| POST | `/ingest` | `{events:[{raw,source,ts}]}` or `{from_athena:true,hours:N}` → Drain-cluster + embed + upsert templates |
| GET | `/similar?text=&k=5` | nearest templates + incidents by cosine distance |
| POST | `/incidents` | record a resolved incident (embedded for recall) |
| POST | `/markers` | seed a deploy/config-change marker (ts,kind,ref,commit_sha?,note?) |
| POST | `/investigate` | `{query,window_hours}` → runs the loop → `{run_id, finding, evidence}` |
| GET | `/runs/{id}` | the append-only reasoning trace (ordered events) |

## The /investigate loop (each step → store.emit, forming the glass-box trace)
`plan → anomaly_detected → tool_call(fetch_events) → tool_result → cluster → recall → correlate →
verdict → synthesis → finding`. If no spike: `plan → anomaly_detected → verdict` (baseline nominal).

## Embeddings
Gemini `text-embedding-004` (768-dim) via the existing `GEMINI_API_KEY`. With no key,
`embeddings.is_stub()` is True and a deterministic char-ngram stub is used (offline dev/tests).
Set `EMBED_PROVIDER=stub` to force the stub even with a key.

## Anomaly source
`AnomalySource` protocol. Prod = `AthenaAnomalySource` (queries `suricata_corelight`, code-computes
z-scores; see `ATHENA_NOTES.md`). Tests inject `FixtureAnomalySource` so the loop runs with no AWS creds.

## Run locally (from clean)
```bash
# 1. Postgres+pgvector + service, cold:
EMBED_PROVIDER=stub docker compose -f docker-compose.agents.yml up -d --build postgres root-cause
# 2. Health (internal port; exec into the container or curl from another service):
docker compose -f docker-compose.agents.yml exec root-cause \
  python -c "import urllib.request;print(urllib.request.urlopen('http://localhost:8006/health').read())"
# 3. Tests (needs a reachable Postgres at PG_DSN):
bash agents/root-cause/qa/acid.sh     # full slice suite, 56 tests
bash agents/root-cause/qa/smoke.sh    # fast plumbing check
```

## Gotchas (learned building it)
1. **pgvector `<=>` needs `%s::vector` casts** on query params — a bound Python list adapts to
   `double precision[]` and the operator has no column to coerce against (INSERT works, ORDER BY doesn't).
2. **Migration path differs local vs container** (`agents/root-cause/migrations` vs `/app/agents/root-cause/migrations`).
   `store._resolve_migration_path()` tries both + honors `RECALL_MIGRATION_PATH`. Startup logs which it used.
3. **`premask` over-masks `alert.signature` → `<DOMAIN>=`** (the field name looks like a domain).
   Harmless (deterministic, all instances mask identically) but a future refinement.
4. Test venv is Python 3.14; the `PythonFinalizationError` from psycopg_pool `__del__` at interpreter
   shutdown is harmless noise, not a failure.
