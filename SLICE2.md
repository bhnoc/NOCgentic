# SLICE 2 — Autonomous investigation loop + glass-box trace (level9000)

## Contract
- **Goal:** A first-class investigation engine that takes an analyst's NL question, runs a
  multi-step Athena tool loop (query → read result → decide next query → …) to gather evidence,
  and returns a structured finding — persisting every step as an event-sourced glass-box trace
  the UI can replay. Ported from PostCog's proven `_chat_with_tools` loop; data/voice split enforced.
- **Acceptance (observable, via API):**
  1. `POST /investigate {query, window_hours}` → `{run_id, finding, evidence}`. Finding has
     verdict/severity/summary; evidence lists the exact SQL queries run + row samples.
  2. `GET /runs/:id` → ordered event trace: `plan`, one `tool_call`+`tool_result` PER Athena query
     the loop ran (≥1), `verdict`, `synthesis`. Same agent_runs/agent_events tables as slice 1.
  3. The loop is MULTI-STEP: given a question that needs a pivot (e.g. "what did the host that
     triggered alert X talk to?"), the trace shows ≥2 tool_calls (initial query, then a pivot query
     derived from the first result). Proven with a FixtureLLM that scripts a 2-query plan.
  4. Query guard (code, not LLM): any generated SQL without a `dt` partition filter is rejected
     back to the model with a correction, NOT executed. Non-SELECT refused. (ported _validate_query)
  5. Tool-depth bound enforced: loop stops at MAX_TOOL_DEPTH and finalizes from gathered data.
  6. Data/voice split: verdict/severity code-decided where a signal is code-detectable
     (reuse detect_high_signal idea for suricata sigs); LLM writes prose only.
- **Done:** acid green from clean (`docker compose up postgres investigator`), FixtureLLM +
  FixtureAthena drive the loop offline (no AWS/Gemini). Live HTTP smoke against the container.

## Architecture — new service `investigator` (port 8007), reuses shared
- Reuse `agents/shared/{athena_client, llm_client, telemetry, store}.py`. NO new tables — use
  store.start_run/emit/finish_run/get_run (kind="investigation").
- Port from PostCog analyst.py: the LLMProvider tool-call abstraction is ALREADY in llm_client?
  NO — llm_client.llm_complete has no tool-calling. So build a thin `ToolLoop` that uses the
  gemini/openrouter/local providers WITH function-calling. Simplest correct path: port PostCog's
  provider `chat(messages, use_tools) -> (text, tool_calls)` for the ACTIVE provider only (gemini
  default), plus a FixtureProvider for tests. Keep it minimal — one tool: query_athena.
- `_validate_query` (dt-filter + SELECT-only), `_format_results` (per-field truncation budgets),
  `detect_high_signal` (suricata signature scan) — port these deterministic pieces near-verbatim.

## Pinned interface — agents/investigator/main.py (FastAPI :8007)
```
GET  /health                          -> {status, service, llm_stub}
POST /investigate {query, window_hours=24, max_depth=8}
     -> {run_id, finding:{verdict,severity,summary,recommendation}, evidence:{queries:[{sql,row_count,rows_sample}], high_signals:[...]}}
GET  /runs/{id}                       -> store.get_run(id)
```
Loop (each step -> store.emit):
1. start_run("investigation", {query, window_hours}); emit "plan".
2. ToolLoop.run(question): recursive, MAX_TOOL_DEPTH bound. Each iteration:
   provider.chat(messages) -> (text, tool_calls). For each query_athena tool_call:
   emit "tool_call" {sql}; _validate_query -> if bad emit "tool_result" {rejected, reason} + feed
   correction back (no execute); else athena.run_query -> emit "tool_result" {row_count, sample};
   append formatted result; recurse. No tool_calls -> break (finalize). Depth cap -> forced finalize.
3. detect_high_signal(collected results) -> code-computed list. emit "verdict" {high_signals, severity}.
4. LLM prose synthesis ONLY (facts = collected evidence + high_signals). emit "synthesis".
5. finish_run; return finding+evidence (evidence.queries reconstructed from the emitted tool events).

## Provider abstraction (agents/shared/tool_provider.py — NEW, small)
Port PostCog's provider.chat tool-calling for gemini (default) + a FixtureProvider. Keep the
existing llm_client for non-tool synthesis calls (reuse llm_complete for step 4 prose).
`class ToolProvider(Protocol): async def chat(messages, tools, temperature) -> (text, list[toolcall])`
- GeminiToolProvider: langchain_google_genai bind_tools OR google.genai function calling. Use whatever
  the installed lib supports; FixtureProvider covers tests so this can be gemini-only + best-effort.
- FixtureProvider(scripted_calls): returns pre-scripted (text, tool_calls) per turn — drives acid.

## Tests — tests/python/test_investigator.py (FixtureProvider + FixtureAthena, PG skip-guard)
Covers acceptance 1-6. Multi-step: FixtureProvider scripted to emit query1 -> (given result) ->
query2 -> finalize; assert trace has 2 tool_calls in order. Guard: scripted bad SQL (no dt) ->
assert tool_result rejected + not executed. Depth: script infinite tool calls -> assert stops at cap.

## Model routing: sonnet-5 for the port (tool-calling provider correctness); judge at opus if it misses.
