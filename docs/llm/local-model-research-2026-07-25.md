# Local LLM research for NOCgentic (2026-07-25)

Goal: pick local open-weight models to run on the GPU box (NVIDIA L40S, 48GB, Ada Lovelace) via llama.cpp, to replace or supplement the Gemini 3.5 Flash Lite cloud baseline for the air-gapped / GPU deployment. Workload is three narrow tasks: NL to Athena SQL over Corelight/Zeek logs, short SOC-voice summarization, and JSON intent routing.

Produced by a multi-agent deep-research pass (102 agents, adversarially verified, cited). Findings are dated because this is past the assistant's training cutoff.

## Bottom line
No open-weight model closes the text-to-SQL quality gap to the closed cloud baselines: on the contamination-free LiveSQLBench leaderboard the best open model (DeepSeek R1, 24.50%) trails Gemini 3.1 Pro (36.50%), Claude Opus 4.6 (35.50%), and GPT-5.5-low (33.50%) by roughly 11 to 12 points. Expect a measurable SQL-accuracy trade for going local. That is exactly why we benchmark rather than assume: the summarization and JSON-routing tasks are far easier than SQL and a good local model may match the baseline on those while trading only on SQL.

## Ranked shortlist to download and benchmark

1. **Qwen3-Coder-30B-A3B-Instruct** (TOP PICK). 30.5B total / 3.3B active MoE (128 experts, 8 active). **Apache 2.0** (clean commercial use). ~18GB at Q4_K_M, ~21GB at Q5, so it fits 48GB with large context headroom. Native GGUF + Unsloth dynamic quants, runs on llama.cpp/Ollama/LM Studio/MLX-LM. Coding-specialized, so best structural fit for NL to SQL. Confidence high, 3-0.

2. **Qwen2.5-Coder-32B-Instruct**. The **best-scoring sub-48GB model on LiveSQLBench (12.50%)** among fits-on-one-GPU options, narrowly beating Llama 3.3 70B (12.17%) despite being smaller and roughly doubling Codestral 22B (8.67%). Apache 2.0. This is the strongest *measured* text-to-SQL evidence for a deployable model. Confidence high, 3-0.

3. **Qwen3-32B dense**. Apache 2.0, thinking/non-thinking modes. General-purpose 32B that fits comfortably; good all-rounder for the summarization + routing tasks even if SQL is a touch behind the coder variants. Confidence high.

Stretch / experiment:
- **Qwen3-Coder-Next** (80B total / 3B active MoE, 262K native context, Apache 2.0). Quality-max, but 4-bit quants need >45GB and the Q4_K_M GGUF (~48.5GB) does NOT fit comfortably in 48GB once KV cache is added (fit-refutation 0-3). Only viable at sub-4-bit quant with reduced context. Treat as a marginal experiment, not a safe default.

Alternative, with a licensing caveat:
- **Gemma 3 27B**. Viable non-coding alternative, and Unsloth's Dynamic 2.0 4-bit build is ~2GB smaller than Google's QAT build while gaining ~1% MMLU. BUT it ships under Google's custom non-OSI **Gemma Terms of Use** (commercial-OK-with-restrictions, not clean Apache) which is a wrinkle for a conference deployment. (Gemma 4 reportedly moved to Apache 2.0; verify before choosing.)

Ruled out / notable:
- The top open text-to-SQL models (DeepSeek R1 24.50%, Qwen3-235B-A22B 22.17%, Qwen3 Coder 480B 19.17%) are all far too large for a single 48GB L40S.
- The Llama 4.x line is effectively legacy after Meta pivoted to the proprietary Muse Spark (April 2026), so it is not a forward pick.

## Quant + format guidance
Prefer **Unsloth Dynamic 2.0 GGUFs** as the download format: they run natively on llama.cpp (standard GGUF) and give favorable size/quality tradeoffs. Target Q4_K_M or Q5 for the 30-32B models: both leave plenty of the 48GB for KV cache / long context. The VRAM footprint of an MoE is driven by TOTAL params (30.5B), not active (3.3B), so budget for the full model.

## Runtime: llama.cpp vs Ollama vs vLLM
All three expose an OpenAI-compatible endpoint, so the app's `local` provider (base-URL driven) works with any of them.
- **llama.cpp (`llama-server`)**: leanest OpenAI-compatible server, native GGUF + Unsloth support, full control of GPU offload. Best single-user latency and the closest to "just the engine." James's lean choice; matches the shortlist's GGUF format.
- **Ollama**: a management wrapper around llama.cpp. One-line model pulls, same GGUF support, slightly less control. Easiest operationally.
- **vLLM**: different engine, higher throughput / better GPU utilization for concurrent load, but heavier setup, its own quant formats, more VRAM overhead. Overkill for single-analyst demo queries.

Recommendation: start with **llama.cpp `llama-server`** (leanest, native Unsloth GGUF, best single-user latency), keep the provider base-URL generic so we can swap to vLLM later if concurrency ever matters.

## Prerequisites on the box (not yet installed)
The L40S is present (confirmed via lspci: NVIDIA AD102GL [L40S]) but the box has **no NVIDIA driver / CUDA installed** and no `nvidia-smi`. 460GB disk free (plenty for weights). Before any local model runs: install the NVIDIA driver + CUDA, build/install llama.cpp with CUDA, then pull a shortlist GGUF.

## Flagged uncertainties
- LiveSQLBench leaderboard last updated 2026-03-02, so it may lag the very latest July 2026 releases; Qwen3-Coder-30B-A3B is not yet on it, so its SQL score is inferred from family lineage, not measured.
- Some Qwen3-Coder-Next GGUF page date fields were inconsistent (Feb references), a minor flag on exact release timing.
- Gemma 4 Apache-license claim should be re-verified against the official model card before relying on it.

## SQL-specialist follow-up (does a purpose-built text-to-SQL model beat the generalists for Athena?)
Second research pass, 2026-07-25. Verdict: **stick with the Qwen-Coder generalists.** Reasons:
- **No open text-to-SQL specialist or major benchmark targets the Presto/Trino/Athena dialect.** BIRD, Spider 2.0, and LiveSQLBench all score SQLite/PostgreSQL/MySQL. XiYanSQL's own README says it supports "SQLite, PostgreSQL, and MySQL" only. So a specialist's edge is on dialects we don't use.
- **Narrow SQL models overfit SQLite idioms** (`strftime`, `||` concat, LIMIT semantics) that are wrong or suboptimal in Presto. Our dialect needs (`date_parse`, `from_unixtime`, `approx_distinct`, `UNNEST`, `dt=` Hive-partition filters) are closer to general code-reasoning + prompt-injected dialect rules.
- On Spider 2.0 the open-weight baseline used is literally Spider-Agent + **Qwen2.5-Coder-32B**; on LiveSQLBench the open ranking is Qwen-dominated. The generalist coder is already the reference.
- **Defog SQLCoder is dead** (newest is llama-3-sqlcoder-8b, 2024-07; no 2025/2026 successor). CodeS, DTS-SQL are 2024 SQLite-tuned academic artifacts. Skip.

One specialist worth a **control-group** benchmark slot only:
- **XiYanSQL-QwenCoder-32B-2504** (Apache 2.0, 2025-04). It IS Qwen2.5-Coder-32B SQL-SFT'd, so it's a clean A/B against its own base. GGUF: `mradermacher/XiYanSQL-QwenCoder-32B-2504-GGUF` (~19-20GB Q4_K_M). Prediction: it won't beat its base on Presto because its SFT was SQLite/Postgres/MySQL. Keep only if it does.

Verify-later flag: **AWS "Q-SQL" (30B-A3B MoE)** leads BIRD (76.47%, 2025-12) and would be directly relevant to an AWS/Athena stack, but an open-weight release / license / GGUF was NOT confirmed. Worth a targeted check before assuming it's downloadable.

## Bigger lever than model choice: GBNF grammar-constrained decoding
For our two hard constraints (valid JSON intent routing + well-formed single-statement SQL), **llama.cpp GBNF grammar constraints matter more than which model we pick.** A GBNF grammar *guarantees* syntactically valid JSON and can force SQL to a single statement / no markdown fences. This is a local-runtime capability the cloud API does not give us. Plan: once a model is chosen, invest in GBNF grammars for the classify (JSON) and SQL-gen paths rather than more model hunting.

## Sources
LiveSQLBench (https://livesqlbench.ai), BIRD (bird-bench.github.io), Spider 2.0 (spider2-sql.github.io), Qwen HF cards, XiYanSQL/XGenerationLab + mradermacher GGUF cards, Unsloth Dynamic 2.0 docs, Defog HF. Full per-claim sources in the research transcripts.
