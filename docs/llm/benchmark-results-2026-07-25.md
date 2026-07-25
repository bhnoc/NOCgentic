# LLM benchmark results (2026-07-25)

Head-to-head on the three real NOCgentic agent tasks (NL to Athena SQL, JSON intent classification, SOC-voice summarization), run via `bench/` on the box. Gemini is the cloud baseline; the local models ran on the L40S via llama.cpp `llama-server`.

## Results

| metric | Gemini 3.5 Flash Lite (cloud) | Qwen3-Coder-30B-A3B (local) | Mistral-7B Presto-SQL (local) |
|--------|------------------------------:|----------------------------:|------------------------------:|
| NL to SQL acc | **100.0%** | 97.5% | 60.0% |
| classify acc | **100.0%** | **100.0%** | 80.0% |
| summarize acc | **86.1%** | 81.6% | 40.6% |
| **OVERALL acc** | **96.0%** | **93.8%** | 61.6% |
| overall p50 latency | 663 ms | 887 ms | 592 ms |
| tokens/sec | 204 | 170 | 130 |

All runs: 28 cases (10 NL-SQL, 10 classify, 8 summarize), 0 errors, through the real `llm_complete` + real agent prompts/parsers.

## Read

**Qwen3-Coder-30B is the clear local winner and it is close to the cloud baseline: 93.8% vs 96.0% overall.** It ties Gemini on classification (100%), is within 2.5 points on SQL (97.5% vs 100%), and within ~5 points on summarization (81.6% vs 86.1%). On a 48GB L40S it uses ~19.6GB VRAM at Q4_K_M (lots of headroom), runs fully air-gapped, and generates at ~170 tok/s. For the air-gapped / no-cloud posture this is a genuinely viable replacement: you trade ~2 points of accuracy for zero cloud dependency and no per-call cost.

**The Mistral-7B Presto specialist is not competitive: 61.6% overall.** It confirmed the research prediction. It knows Presto *syntax* but not our Corelight schema or the prompt instructions, and as a 7B v0.1 base it is weak at summarization (40.6%). Dialect-fluency without schema-grounding loses to a strong generalist coder that gets the schema in its prompt. Drop it from the shortlist. (It was also flagged eval-only: the HF repo declares no license.)

**Gemini remains the accuracy leader (96.0%)** and is the right default for the cloud/CPU deployment. Latency is comparable across all three at p50; the local models are actually faster at p50 (single-user, on-box, no network) but Gemini has higher throughput.

## The classify bug this benchmark found (already fixed)
The first Gemini run scored classify 0% / overall 58.1%. That was NOT a Gemini failure: the orchestrator's `llm_classify` called with `max_tokens=256, thinking_budget=0`, and on flash-lite `thinking_budget=0` clamps to -1 (unbounded dynamic thinking) which shares the output budget, so the JSON truncated mid-object and every classification silently fell back to the keyword heuristic. Fixed (commit 8450433) with `max_tokens=1024, thinking_budget=512`, mirroring the athena-hunter SQL-gen fix. After the fix, Gemini classify went 0% to 100% and overall to 96.0%. The QA sweeps missed this because acid tested end to end (the fallback masks it); the benchmark caught it because it exercises the LLM path in isolation.

## Recommendation
1. **Keep Gemini as the default** (cloud/CPU boxes): highest accuracy, the classify fix is deployed.
2. **Qwen3-Coder-30B-A3B is the local pick** for the GPU/air-gapped box: 93.8%, fits easily, Apache 2.0. Set `LLM_PROVIDER=local` + point at a `llama-server` running it.
3. **Drop the Mistral Presto specialist.** Optionally still A/B **XiYanSQL-QwenCoder-32B** (the research control) if you want to confirm no SQL-specialist beats the generalist, but the evidence strongly says it will not.
4. **Next quality lever:** GBNF grammar-constrained decoding on the local runtime to guarantee valid JSON (classify) and single-statement SQL. That could push the local model's SQL/classify reliability to match or exceed the cloud on well-formedness.

## Gotcha: benchmark results on the box are wiped by deploys
`bench/results/*.json` is gitignored, and `ops/deploy.sh` rsyncs the git checkout into `/opt/bhasia/app` with `--delete`, so any results file on the box is deleted on the next deploy. The Gemini and Mistral result JSONs were lost this way (their numbers are preserved here). To keep raw result files, either run the benchmark somewhere outside `/opt/bhasia/app`, or copy the JSON off the box immediately, or commit the summary (like this doc) rather than the raw files.
