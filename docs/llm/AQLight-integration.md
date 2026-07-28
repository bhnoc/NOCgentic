# AQLight (local NL->SQL model): how NOCgentic uses it

_2026-07-28. Companion to the model handoff at `slm-athena/AQLight_handoff.md`._

## What AQLight is

AQLight is a fine-tuned Qwen2.5-Coder-7B served as a 4.4GB q4 GGUF on the AING box. It turns
a natural-language analyst question into ONE Athena SQL query for `blackhat_pope_logs`. On a
100-case execution-validated eval it beats Gemini 3.5 Flash Lite on NL->SQL (0.962 vs 0.942)
at ~129 tok/s, ~5GB VRAM. Full detail and provenance: `slm-athena/AQLight_handoff.md`.

**It is a SQL specialist, not a general model.** It was trained only for NL->SQL. It does
NOT do intent classification (JSON routing), answer synthesis, or alert-triage prose. So
`LLM_PROVIDER=local` across ALL agents is NOT a drop-in replacement for Gemini: the
orchestrator's classify and the synthesis/triage steps would get a model that was never
trained for them. Point the SQL path at AQLight; keep the rest on Gemini (that wiring is
someone else's task and is intentionally NOT done here).

## What is wired now (this repo)

The plumbing to REACH AQLight exists and defaults to its name, so it is available to flip on:

- `agents/shared/llm_client.py` supports `LLM_PROVIDER=local` (OpenAI-compatible client, no
  cloud fallback), with `LOCAL_LLM_MODEL` defaulting to `AQLight` and `LOCAL_LLM_BASE_URL`
  to the local llama-server.
- `docker-compose.agents.yml` now passes `LOCAL_LLM_BASE_URL` / `LOCAL_LLM_MODEL` /
  `LOCAL_LLM_API_KEY` into all four LLM-calling agents (orchestrator, alert-triage,
  athena-hunter, thousandeyes-analyst) and adds `extra_hosts: host.docker.internal:
  host-gateway` so a container can reach the host's llama-server on Linux.
- Defaults are inert: with nothing set, every agent still uses Gemini. Setting the local
  vars is a deliberate opt-in.

## Turn it on

1. **Serve AQLight on the box** (from the slm-athena project, its call to deploy):
   ```bash
   ~/slm-athena/serve.sh ~/slm-athena/training/gguf/athena-v3-q4_k_m.gguf AQLight
   curl -sf http://127.0.0.1:8080/health   # {"status":"ok"}
   ```
2. **Point NOCgentic at it.** The clean, low-risk choice is SQL-only. Since a per-step
   provider knob is not built yet, the two options today are:
   - **athena-hunter only** (recommended): run the athena-hunter container with
     `LLM_PROVIDER=local` while the others stay on Gemini. Every athena-hunter LLM call
     (NL->SQL + its answer synthesis) then goes to AQLight. NOTE: AQLight is weak at the
     synthesis half; if synthesis quality drops, that is expected and is why the real fix is
     a per-step SQLGEN_PROVIDER knob (deferred, someone else's task).
   - **A/B a single query** without changing the deployment: hit the athena-hunter with the
     provider overridden per call (the `provider=`/`model=` args on `llm_complete` already
     support this), useful for eval runs via `bench/`.
3. **Prompt note (matters):** AQLight was trained with a SHORT ~456-char system prompt, not
   NOCgentic's ~9KB `SQL_GEN_PROMPT`. The big prompt still works (schema knowledge is baked
   into the weights) but wastes context. If SQL quality is off when pointed at AQLight, try
   the short prompt from `slm-athena/data/format_dataset.py` (SYSTEM_PROMPT). The
   athena-hunter `_parse_sql_response` / `sanitize_sql` are compatible as-is.

## Env reference

| var | default | meaning |
|-----|---------|---------|
| `LLM_PROVIDER` | `gemini` | `gemini` \| `openrouter` \| `local`. `local` selects AQLight. |
| `LOCAL_LLM_BASE_URL` | `http://host.docker.internal:8080/v1` | where AQLight's llama-server listens (host, via the bridge gateway) |
| `LOCAL_LLM_MODEL` | `AQLight` | served model alias (llama-server `--alias AQLight`) |
| `LOCAL_LLM_API_KEY` | `not-needed` | placeholder; llama.cpp ignores it |

Set these in `.env.s3` on the box (authoritative env), then
`docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d` the affected service.

## Gotchas

- **`host.docker.internal` on Linux** needs the `extra_hosts` host-gateway mapping (added).
  Alternatively set `LOCAL_LLM_BASE_URL` to the host's bridge IP (`172.17.0.1` or the
  compose network gateway) if the mapping is unavailable.
- **No cloud fallback for `local`.** If `LLM_PROVIDER=local` and the llama-server is down,
  calls error rather than silently phoning home to Gemini, by design. Start the server
  first; health-check it.
- **Weights are not in git.** AQLight lives on the box under `~/slm-athena/training/gguf/`
  and in the GitLab Model Registry (see the slm-athena handoff). NOCgentic only references
  it over HTTP; it does not ship the weights.
