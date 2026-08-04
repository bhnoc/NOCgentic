# AQLight (local NL->SQL model): how NOCgentic uses it

_2026-07-28. Companion to the model handoff at `slm-athena/AQLight_handoff.md`._

## What AQLight is

AQLight is a fine-tuned Qwen2.5-Coder-7B served as a 4.4GB q4 GGUF on the AING box. It turns
a natural-language analyst question into ONE Athena SQL query for `blackhat_pope_logs`. On a
100-case execution-validated eval it beats Gemini 3.5 Flash Lite on NL->SQL (0.962 vs 0.942)
at ~129 tok/s, ~5GB VRAM. Full detail and provenance: `slm-athena/AQLight_handoff.md`.

**It is SQL-tuned but NOT a narrow specialist.** It was fine-tuned for NL->SQL on top of
Qwen2.5-Coder-7B, a capable general model, so the SQL skill was added WITHOUT destroying
general reasoning/prose. An end-to-end capability test on 2026-07-30 (app switched to
`LLM_PROVIDER=local`, full 14-scenario eval) REFUTED the earlier assumption that it can
only do SQL:
- Routing/classify: all 14 scenarios routed to the correct agent, 0 misroutes, 0 errors.
- NL->SQL: correct SQL through the app's real prompt (exact top-talker counts).
- Answer synthesis: correct, well-structured SOC prose (e.g. alert-01 -> CONFIRMED verdict
  with the 880 scan + 45 password-cracking corroboration).
- Alert-triage: exact severity breakdown (67,941; 34,829 low / 31,312 medium / 1,491 high).
- Deterministic accuracy 92.5% vs Gemini's 98.8%; SPEED faster (on-box, no network hop).
The gap lives in the same hard scenarios Gemini also dips on, not a categorical failure.
So `LLM_PROVIDER=local` across all agents IS viable end to end, with a few points of
accuracy traded for zero cloud dependency, no per-call cost, and lower latency. (Test
detail: `qa/AQLight-capability-sweep.md`, gitignored.)

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

## Current default: HYBRID (AQLight SQL + Gemini prose)

As of 2026-07-30 the box runs **hybrid** and it is the recommended default:
`LLM_PROVIDER=gemini` + `SQLGEN_PROVIDER=local`. Only athena-hunter's NL->SQL generation
goes to AQLight; classify, answer synthesis, and alert-triage stay on Gemini.

**Clean three-way eval** (all three modes run back to back on ONE data seed with ONE Gemini
judge session, so golden-drift + judge variance hit all three equally; trust the RANKING,
not the absolute levels, which are depressed by stale goldens):

| mode | accuracy | relevance | speed |
|------|----------|-----------|-------|
| Gemini all | 98.8% | 0.693 | 11.7s |
| **Hybrid (default)** | **98.0%** | **0.586** | 10.9s |
| AQLight all | 94.0% | 0.411 | 9.1s |

Ranking is unambiguous: **Gemini >= Hybrid > AQLight-all** on both accuracy and relevance.

- **Hybrid vs AQLight-all:** hybrid clearly wins. AQLight-all hallucinates in synthesis
  (invented alert details; told the analyst to block the legitimate DNS forwarder), which
  hybrid's Gemini synthesis removes. AQLight is NOT good enough on its own for whole-app.
- **Hybrid vs Gemini-all:** hybrid trails slightly on relevance EVEN THOUGH synthesis is
  identical Gemini. That gap is real and it is AQLight's SQL: it writes correct, valid, but
  SIMPLER queries (single literal SELECTs) where Gemini writes multi-query aggregating
  hunts. On open-ended profile/hunt questions (byip-01, hunt-02) AQLight retrieves less
  complete data, so even Gemini-the-synthesizer has less to work with. On targeted
  questions (alert-01, triage-01, hunt-04, bymac) hybrid matches or beats Gemini.

Net: hybrid is the right default (near-Gemini accuracy, no hallucination, faster/cheaper
SQL), with a known ceiling on exploratory hunts. Lifting it means a richer AQLight SQL-gen
prompt or more multi-query-hunt training data, not a provider change. AQLight generates
correct SQL through the app's real 9KB prompt (the wrong-columns behavior only shows with a
generic prompt).

## Turn it on

1. **AQLight runs as a systemd service** (set up 2026-07-30): `aqlight.service`, enabled,
   `Restart=always`, binds 0.0.0.0:8080, survives reboot/crash.
   ```bash
   sudo systemctl status aqlight     # active (running)
   sudo systemctl restart aqlight    # if it needs a bounce
   curl -sf http://127.0.0.1:8080/health   # {"status":"ok"}
   ```
   Manual fallback (no service): `~/llama.cpp/build/bin/llama-server -m
   ~/slm-athena/training/gguf/athena-v3-q4_k_m.gguf --host 0.0.0.0 --port 8080 -ngl 99
   -c 8192 --alias AQLight &`. It MUST bind 0.0.0.0, not 127.0.0.1 (see Gotchas).
2. **Enable hybrid** (the default): in `.env.s3` set `LLM_PROVIDER=gemini` and
   `SQLGEN_PROVIDER=local`, then `docker compose ... up -d athena-hunter`. To turn hybrid
   OFF and go pure-Gemini, unset `SQLGEN_PROVIDER` and recreate. Other modes:
   - **Whole app local**: `LLM_PROVIDER=local` (all agents on AQLight). Air-gap / Gemini-key
     capped only; synthesis quality drops (relevance 0.464, hallucinations).
   - **A/B a single query**: override provider per call (the `provider=`/`model=` args on
     `llm_complete`), useful for `bench/`.
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
| `SQLGEN_PROVIDER` | (unset) | route ONLY NL->SQL gen here; `local` = hybrid (the default on the box). Unset = SQL gen uses `LLM_PROVIDER`. |
| `SQLGEN_MODEL` | (unset) | optional model override paired with `SQLGEN_PROVIDER` |

Related: **[`lane-race.md`](lane-race.md)**, which runs AQLight *against* Gemini
concurrently and shows whichever finishes first, with a UI swap for the other. Where
the hybrid above reroutes one step, that is a full second lane: AQLight runs the
whole pipeline, prose included. Note that it measures slower than Gemini on the
current T4 box, contrary to the throughput figures earlier in this doc.

Set these in `.env.s3` on the box (authoritative env), then
`docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d` the affected service.

## Gotchas

- **Hybrid has NO fallback if AQLight is down.** With `SQLGEN_PROVIDER=local`, the SQL-gen
  call goes only to AQLight (the local provider does not fall back to cloud, by design). If
  `aqlight.service` is stopped/crashed, athena-hunter SQL gen ERRORS. That is why AQLight is
  a systemd service with `Restart=always`. If athena-hunter starts failing on every query,
  check `systemctl status aqlight` first, or unset `SQLGEN_PROVIDER` to fall back to Gemini
  SQL gen. (Adding a code-level SQLGEN fallback-to-LLM_PROVIDER on connection error would be
  a nice hardening; not built yet.)
- **llama-server MUST bind 0.0.0.0, not 127.0.0.1.** `slm-athena/serve.sh` launches with
  `--host 127.0.0.1`, which only accepts loopback connections. The app containers reach the
  model via `host.docker.internal` (the docker bridge gateway, a non-loopback address), so a
  127.0.0.1-bound server refuses them and `LLM_PROVIDER=local` silently fails to connect.
  Launch with `--host 0.0.0.0` (as in "Turn it on"). If serve.sh is ever wired into a
  durable systemd unit, fix the bind there too.
- **`host.docker.internal` on Linux** needs the `extra_hosts` host-gateway mapping (added).
  Alternatively set `LOCAL_LLM_BASE_URL` to the host's bridge IP (`172.17.0.1` or the
  compose network gateway) if the mapping is unavailable.
- **The Gemini judge in `bench/` can cap out.** The prompt-eval relevance channel uses
  Gemini as judge; if the Gemini key hits its monthly spend cap (429 RESOURCE_EXHAUSTED),
  relevance reads "unavailable" for every scenario even though the app-under-test (AQLight,
  local) answered fine. That is a judge-billing issue, not a model failure. Restore the cap
  at ai.studio/spend or judge with another provider.
- **No cloud fallback for `local`.** If `LLM_PROVIDER=local` and the llama-server is down,
  calls error rather than silently phoning home to Gemini, by design. Start the server
  first; health-check it.
- **Weights are not in git.** AQLight lives on the box under `~/slm-athena/training/gguf/`
  and in the GitLab Model Registry (see the slm-athena handoff). NOCgentic only references
  it over HTTP; it does not ship the weights.
