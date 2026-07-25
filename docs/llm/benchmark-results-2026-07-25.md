# LLM benchmark results (2026-07-25)

Head-to-head on the three real NOCgentic agent tasks (NL to Athena SQL, JSON intent classification, SOC-voice summarization), run via `bench/` on the box. Gemini is the cloud baseline; the local models ran on the L40S via llama.cpp `llama-server`. 28 cases per run, 0 harness errors. Raw result JSONs archived in `bench/results-archive/`.

Ranked on the three things that matter most, in order: **it works (accuracy), it does not make things up (faithfulness), speed.**

## 1. Works (task accuracy)

| task | Gemini (cloud) | Qwen3-Coder-30B (local) | Mistral-7B Presto (local) |
|------|---------------:|------------------------:|--------------------------:|
| NL to SQL | **100.0%** | 97.5% | 60.0% |
| classify | **100.0%** | **100.0%** | 80.0% |
| summarize | **84.7%** | 77.4% | 51.4% |
| **OVERALL** | **95.6%** | **92.7%** | 64.7% |

Gemini leads at 95.6%. **Qwen3-Coder-30B is right behind at 92.7%** and ties Gemini on classification. Mistral-7B Presto is not competitive (64.7%): it knows Presto syntax but not our Corelight schema, and its 7B v0.1 base is weak at summarization.

## 2. Does not make things up (faithfulness)

The summarize scorer flags any number in the answer that is NOT present in the input data (a fabricated statistic). This is the single most important trait for a SOC tool: a confident wrong number is worse than "I do not know."

| model | summarize cases clean (no fabricated numbers) | what it made up |
|-------|:---:|-----------------|
| Gemini | **7 / 8** | one case emitted a formatting artifact (`00000000000001`), not a real fabricated stat |
| Qwen3-Coder-30B | 6 / 8 | invented plausible-but-wrong counts (`31`, `64`) in 2 cases |
| Mistral-7B Presto | 3 / 8 | repeated the literal token `123` in 5 of 8 cases (a broken generation pattern) |

**Gemini is the most faithful.** Qwen fabricates occasionally (2/8) and, worse, its fabrications are *plausible* wrong numbers, which is the dangerous kind (an operator can't spot them). Mistral is disqualified on this axis alone: it hallucinated in 5 of 8 summaries. NL to SQL and classify have their own structural checks (does the SQL parse and hit the right table; is the JSON valid with the right intent), so this fabrication axis is measured on summarization where free-text invention is possible.

## 3. Speed

| metric | Gemini (cloud) | Qwen3-Coder-30B (local) | Mistral-7B Presto (local) |
|--------|---------------:|------------------------:|--------------------------:|
| NL to SQL p50 | 711 ms | 1267 ms | 1121 ms |
| classify p50 | 564 ms | **285 ms** | 264 ms |
| summarize p50 | 5086 ms | **1233 ms** | 1290 ms |
| **OVERALL mean** | 2019 ms | **921 ms** | 2474 ms |
| **OVERALL p95** | 6133 ms | **1908 ms** | 11056 ms |
| tokens/sec | **198** | 170 | 130 |

The surprise: **Qwen3-Coder-30B local is over 2x faster end to end than the Gemini cloud baseline** (mean 921ms vs 2019ms) with a far tighter tail (p95 1908ms vs 6133ms). Two reasons: no network round-trip (the server is on-box), and Gemini's summarizer is slow (5.1s p50) which drags its overall up. Gemini wins on raw throughput (tok/s) once generation starts, but for this workload (short SQL, tiny JSON, brief summaries) per-request latency dominates, and local wins there. Classify is where local shines most: 285ms vs 564ms at the same 100% accuracy, and that decision gates every query. Mistral's p95 of 11s (a 24s outlier on one SQL case) is another disqualifier: a small model without the schema wandered on hard prompts.

## Verdict

| | works | no-fabrication | speed | overall |
|-|-------|----------------|-------|---------|
| **Gemini 3.5 Flash Lite** | best (95.6%) | best (7/8) | slowest e2e, best throughput | cloud/CPU default |
| **Qwen3-Coder-30B** | close (92.7%) | good (6/8) | fastest e2e | local/air-gap pick |
| **Mistral-7B Presto** | poor (64.7%) | poor (3/8) | worst tail | dropped |

- **Keep Gemini as the default** on cloud/CPU boxes: highest accuracy and the most faithful. The classify fix (below) is deployed.
- **Qwen3-Coder-30B-A3B is the local pick** for the GPU/air-gapped box: 92.7% at less than half the latency, ~19.6GB VRAM at Q4_K_M (huge headroom on the 46GB L40S), Apache 2.0. The trade vs cloud is ~3 points of accuracy and one extra fabricated-summary case out of eight, in exchange for zero cloud dependency, no per-call cost, and 2x faster responses.
- **Drop Mistral-7B Presto.** Loses on all three axes. Confirmed the research: dialect-fluency without schema-grounding loses to a strong generalist coder that gets the schema in-prompt.
- **The one caveat for Qwen going to production:** its fabrications are plausible wrong numbers (2/8), which is the risky kind. Before trusting it on live SOC data, add **GBNF grammar-constrained decoding** (guarantees valid JSON for classify and single-statement SQL) and consider a post-hoc check that every number in a summary appears in the source data. That is the next quality lever.

## The classify bug this benchmark found (fixed, commit 8450433)
The first Gemini run scored classify 0% / overall 58.1%. Not a Gemini failure: the orchestrator's `llm_classify` used `max_tokens=256, thinking_budget=0`, and on flash-lite `thinking_budget=0` clamps to -1 (unbounded dynamic thinking) which shares the output budget, so the JSON truncated mid-object and every classification silently fell back to the keyword heuristic. Fixed with `max_tokens=1024, thinking_budget=512` (mirroring the athena-hunter SQL-gen fix). After the fix Gemini classify went 0% to 100% and overall to 95.6%. The QA sweeps missed it because acid tested end to end (the fallback masks it); the benchmark caught it because it exercises the LLM path in isolation. Best single outcome of the whole exercise.

## Reproduce
```bash
# on the box, bench venv at /home/ubuntu/bench-venv, write results OUTSIDE /opt/bhasia/app
export BENCH_RESULTS_DIR=/home/ubuntu/bench-results OTEL_ENABLED=false
# Gemini baseline
cd /opt/bhasia/app && export $(sudo grep -E '^(GEMINI_API_KEY|GEMINI_MODEL)=' .env.s3 | xargs)
LLM_PROVIDER=gemini /home/ubuntu/bench-venv/bin/python bench/run_bench.py
# local model: start llama-server first, poll /health until ready, THEN benchmark
/home/ubuntu/llama.cpp/build/bin/llama-server -m <gguf> -ngl 999 --host 127.0.0.1 --port 8080 -a <name> &
LLM_PROVIDER=local LOCAL_LLM_BASE_URL=http://127.0.0.1:8080/v1 LOCAL_LLM_MODEL=<name> \
  /home/ubuntu/bench-venv/bin/python bench/run_bench.py
```

## Gotchas learned
- **Benchmark results on the box are wiped by deploys.** `bench/results/*.json` is gitignored and `ops/deploy.sh` rsyncs the checkout with `--delete`, so results under `/opt/bhasia/app` vanish on the next deploy (lost the first Gemini + Mistral runs this way). Fix applied: `run_bench.py` honors `BENCH_RESULTS_DIR`; point it at `/home/ubuntu/bench-results` (outside the app dir), and archive the JSON off-box. The archived raw runs are in `bench/results-archive/`.
- **Always poll `llama-server /health` until ready before benchmarking.** A `pkill` + immediate restart raced once and the harness hit a not-yet-listening server, scoring a false 0% (28 connection errors). Wait for `{"status":"ok"}`.
