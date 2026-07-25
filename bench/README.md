# NOCgentic Model Benchmark Harness

Apples-to-apples comparison of LLM providers/models on the three REAL agent
tasks, measuring both speed and accuracy. Built to capture a Gemini cloud
baseline now and run the same suite against local open-weight models (llama.cpp
on the GPU box, `LLM_PROVIDER=local`) later.

The harness calls the REAL `llm_complete` from `agents/shared/llm_client.py`
with the REAL system prompts imported straight out of the agent modules, so it
exercises the exact code path the app uses. Provider selection is by env alone,
identical to how the agents pick a provider.

## The three tasks

| Task        | Source prompt                                   | What is scored |
|-------------|-------------------------------------------------|----------------|
| `nl_sql`    | `SQL_GEN_PROMPT` (agents/athena-hunter/main.py) | Structural SQL quality |
| `classify`  | `CLASSIFY_SYSTEM_PROMPT` (agents/orchestrator/main.py) | Routing correctness |
| `summarize` | `SYSTEM_PROMPT` (agents/alert-triage/main.py)   | Faithful triage summary |

Test cases live in `cases.json` (10 + 10 + 8 = 28 fixed, deterministic cases).
No live Athena: NL->SQL is scored structurally, and summarization feeds a canned
triage-data blob per case.

### Scoring rubric

**nl_sql**: the model's raw output is parsed with the REAL `_parse_sql_response`
from the athena-hunter agent, then the best of the (up to 3) generated queries is
scored on four equal checks (0.25 each):
1. Well-formed: parses as a single `SELECT` (via `sqlparse` if installed, else a
   regex single-statement/starts-with-SELECT check). If nothing parses as a
   SELECT, the case scores 0.
2. Hits the expected table for the question (e.g. "top talkers" -> `conn`,
   "how many alerts" -> `alerts`, uid pivot -> `uid_lookup`).
3. Has a `dt` partition filter.
4. Has a `LIMIT`.

**classify**: the raw output is parsed with the REAL orchestrator `extract_json`:
- 0.5 for valid JSON containing an `intent` field.
- +0.5 (total 1.0) if the intent matches the expected route. The legacy
  `threat_hunter` alias is remapped to `athena_hunter` exactly as the app does.
- Junk that will not parse scores 0.

**summarize**: three equal checks on the raw summary (confidence fence stripped
before number extraction so its value is not mistaken for a data number):
1. Cites the required numbers from the input (the expected counts/severities).
2. No hallucinated numbers: every 2+ digit number in the summary traces back to
   the input blob (a small allow-list covers list ordinals and the year).
3. A parseable ```` ```json {"confidence": ...} ```` fence is present.
For empty-data cases a 4th check requires confidence < 0.3 (the prompt's own
rule), so a confidently-wrong summary of nothing is penalized.

Every case that raises is caught and scored 0 with the error recorded, so a
local model returning junk is a real accuracy signal, not a crash.

## Install

The harness needs the same LLM client deps the agents use (LangChain), plus the
agent import-time deps (fastapi/pydantic/httpx/boto3) because we import the real
prompts out of the agent `main.py` modules, plus `sqlparse` for SQL scoring.

```bash
# from repo root, ideally in the agent venv
pip install -r agents/shared/requirements.txt -r bench/requirements.txt
```

`--dry-run` needs NONE of these (see below).

## Run it

### 1. Gemini baseline (cloud)

```bash
LLM_PROVIDER=gemini GEMINI_API_KEY=sk-... \
  python bench/run_bench.py
```

Optionally pin the model (defaults to `gemini-3.5-flash-lite`, the deploy pin):

```bash
LLM_PROVIDER=gemini GEMINI_API_KEY=sk-... GEMINI_MODEL=gemini-3.5-flash-lite \
  python bench/run_bench.py
```

### 2. Local open-weight model (GPU box)

Point at any OpenAI-compatible server (llama.cpp `llama-server`, Ollama, vLLM):

```bash
LLM_PROVIDER=local \
  LOCAL_LLM_BASE_URL=http://localhost:8080/v1 \
  LOCAL_LLM_MODEL=qwen2.5-7b-instruct \
  python bench/run_bench.py
```

### 3. Compare

```bash
python bench/compare.py \
  bench/results/gemini_gemini-3.5-flash-lite_<ts>.json \
  bench/results/local_qwen2.5-7b-instruct_<ts>.json
```

Prints baseline vs candidate per task (accuracy %, mean/p50/p95 latency,
tokens/sec, errors) with deltas. `win`/`REGRESS` is from the candidate's
perspective: higher accuracy and tokens/sec are better, lower latency and errors
are better.

### CLI overrides

`--provider`, `--model`, `--today YYYY-MM-DD`, `--cases <path>` all override the
env/defaults. Provider and model also flow through to the REAL `llm_complete`.

## Dry run (no network, no deps)

Proves the scoring, timing, and output plumbing end to end on a bare interpreter.
It stubs the import-time deps (fastapi/pydantic/httpx/boto3) so the REAL prompts
and REAL parser helpers still import, and replaces `llm_complete` with a stub
that emits canned good or bad outputs. OTEL is forced off, so nothing hits the
network.

```bash
python bench/run_bench.py --dry-run                # 'good' stub -> high scores
python bench/run_bench.py --dry-run --dry-mode bad # junk -> scores ~0, no crashes
```

## Output

Each run writes `bench/results/<provider>_<model>_<timestamp>.json` (full
per-case raw output, scores, score detail, latency, and token metrics pulled
from `get_last_llm_metrics()`), plus a human-readable summary table to stdout.

## Notes

- Tokens/sec and token counts come from the LLM response metadata via the
  agents' own `get_last_llm_metrics()`. Some local servers do not return usage
  metadata; in that case tokens/sec shows `-` while latency is always measured
  as wall-clock.
- The harness deliberately calls `llm_complete` directly rather than going
  through each agent's fallback wrapper (`_fallback_queries`,
  `_heuristic_classify`). Those fallbacks exist to keep the live app resilient
  when the model fails, but they would mask a weak model's failures and inflate
  the score. The benchmark wants the raw model signal.
- Read-only against the app: nothing here modifies `agents/**`.
