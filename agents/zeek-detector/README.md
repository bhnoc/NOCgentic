# zeek-detector

Turns Zeek `ssl.log` / `conn.log` into AI-service findings: which internal
hosts are talking to which AI services, whether the timing looks like an
autonomous agent (context-reset sawtooth, tight tool-call loop), and how
confident we are. It is the APE-85 / APE-86 research pipeline packaged as a
service; the pipeline modules under `pipeline/` are vendored from the
research-pipeline repo (commit `0c90759`).

## Run

```bash
# Part of the main stack, opt-in via the "zeek" compose profile:
COMPOSE_PROFILES=zeek docker compose -f docker-compose.agents.yml up -d --build zeek-detector

# Or standalone for a quick look:
docker build -f agents/zeek-detector/Dockerfile -t zeek-detector .
docker run --rm -p 8007:8007 -v zeek-data:/data -e ANTHROPIC_API_KEY zeek-detector
```

## API

```bash
# Upload one or both logs. Type is inferred from the filename or the #path header.
curl -s -F files=@ssl.log -F files=@conn.log http://localhost:8007/analyze | jq .summary

# Or name the parts explicitly, and pick the classifier per request:
curl -s -F ssl=@ssl.log -F conn=@conn.log 'http://localhost:8007/analyze?classifier=rules'

curl -s http://localhost:8007/analyses                          # recent analyses
curl -s http://localhost:8007/analyses/<id>                     # one, with findings
curl -s http://localhost:8007/analyses/<id>/findings.csv        # CISO summary
curl -s 'http://localhost:8007/findings?min_severity=high&host=192.168.1.20'
curl -s http://localhost:8007/health
```

A finding looks like:

```json
{
  "finding_id": "AI-0001",
  "host": "192.168.1.20",
  "destination": "104.18.6.192:443",
  "service_id": "openai",
  "service_name": "OpenAI (ChatGPT / API)",
  "behavior_classification": "agentic-orchestration",
  "confidence": 0.93,
  "confidence_level": "high",
  "severity": "high",
  "classifier_mode": "rules",
  "detected_patterns": ["context_reset", "agentic_loop"],
  "playbooks": ["PB-04", "PB-09", "PB-01", "PB-13"],
  "evidence_chain": ["SNI/server_name: api.openai.com", "..."],
  "timeline": {"first_seen": "...", "last_seen": "...", "session_duration_seconds": 100.5},
  "metrics": {"request_count": 24, "sawtooth_score": 0.72, "loop_score": 0.46, "...": "..."},
  "recommendation": "Investigate: ...",
  "narrative": "Host 192.168.1.20 was observed connecting to OpenAI ..."
}
```

## Classifier modes

| `ZEEK_CLASSIFIER_MODE` | What runs |
|---|---|
| `auto` (default) | `llm` if `ANTHROPIC_API_KEY` is set, else `rules` |
| `llm` | LangGraph ReAct agent on Claude (`ZEEK_CLASSIFIER_MODEL`, default `claude-opus-5`) calling the three tools |
| `rules` | The same three tools called directly. Deterministic, no network |

The tools (service catalogue lookup, behaviour map, weighted confidence) are
what carry the evidence in both modes; the model adds judgement on top. Every
model answer is validated field by field against the rules result, and a
failed model call degrades that one cluster to `rules-fallback` rather than
failing the upload. `ZEEK_LLM_MAX_CLUSTERS` (default 200) caps how many
clusters of one upload are sent to the model.

## Storage

SQLite at `ZEEK_DB_PATH` (compose: named volume `zeek-detector-data` mounted
at `/data`). Tables `analyses` and `findings`; every SQL statement is in
`storage.py`, which is the one file to rewrite for PostgreSQL.

## Config

| Var | Default | Meaning |
|---|---|---|
| `ANTHROPIC_API_KEY` | unset | Enables `llm` mode |
| `ZEEK_CLASSIFIER_MODE` | `auto` | `auto` / `llm` / `rules` |
| `ZEEK_CLASSIFIER_MODEL` | `claude-opus-5` | Model for `llm` mode |
| `ZEEK_DB_PATH` | `/data/zeek-detector.db` | SQLite file |
| `ZEEK_MAX_UPLOAD_BYTES` | `52428800` | Per-file cap, 413 above it |
| `ZEEK_LLM_MAX_CLUSTERS` | `200` | Clusters per upload sent to the model |
| `ZEEK_LLM_TIMEOUT` | `60` | Seconds per model call |
| `ZEEK_DETECTOR_API_TOKEN` | unset | When set, bearer required on all routes but `/health` |
| `ZEEK_PLAYBOOK_MAP` | unset | Override path to `finding-playbook-map.json`; default is the copy next to `main.py`, then the repo's `threathunt-catalog/` |

## Tests

```bash
tests/python/.venv/bin/python -m pytest tests/python/test_zeek_detector.py -q
```

Fixtures under `tests/python/fixtures/zeek/` are the research repo's synthetic
logs: four ordinary browsing clusters plus one agentic session against
`api.openai.com` (three context windows of eight ~0.5 s requests).
