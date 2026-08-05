# AQLight (local NL->SQL model): how NOCgentic uses it

_2026-07-28. Companion to the model handoff at `slm-athena/AQLight_handoff.md`._

## What AQLight is

AQLight is a fine-tuned Qwen2.5-Coder-7B served as a 4.4GB q4 GGUF on the AING box. It turns
a natural-language analyst question into ONE Athena SQL query for `blackhatnoc_glue`. On a
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

## Current default: the LANE RACE, not SQLGEN_PROVIDER

**As of 2026-08-04 the box runs `LANE_MODE=hybrid` + `LANE_SIDE_BY_SIDE=true` with
`SQLGEN_PROVIDER` unset.** Every query runs two full lanes concurrently, cloud Gemini
against local AQLight, and the UI shows the winner with a swap to the other. That is a
strictly better version of what `SQLGEN_PROVIDER=local` bought: AQLight reaches SQL gen
through `role="sqlgen"` on the local lane, and its answers are visible next to Gemini's
instead of blended invisibly into one. See [`lane-race.md`](lane-race.md) and
[`lane-mode.md`](lane-mode.md).

**Do not set `SQLGEN_PROVIDER=local` while the race is on.** It was first disabled on
2026-08-04 because llama-server ran `-c 8192` and could not hold `SQL_GEN_PROMPT` plus
4096 output tokens, so every SQL gen 500d. That reason is now stale (the live unit runs
`-c 32768`), but a second and worse one replaced it. `llm_complete` treats an explicit
`provider=` as winning over the lane, so `SQLGEN_PROVIDER=local` reaches the **cloud**
lane too: `provider="local"`, `model=GEMINI_MODEL` from the lane default, and no
`base_url` override because `resolve_lane_base_url` returns None for the cloud lane. The
request lands on the local llama-server, which ignores the model field, so both lanes
would silently generate SQL on AQLight and the race would collapse into a prose-only
comparison with nothing logged to say so.

The three-way eval below predates lanes. It still describes the SQLGEN_PROVIDER hybrid
accurately and is why the local lane is worth racing at all, but the "default" column is
historical.

**Clean three-way eval** (all three modes run back to back on ONE data seed with ONE Gemini
judge session, so golden-drift + judge variance hit all three equally; trust the RANKING,
not the absolute levels, which are depressed by stale goldens):

| mode | accuracy | relevance | speed |
|------|----------|-----------|-------|
| Gemini all | 98.8% | 0.693 | 11.7s |
| Hybrid (SQLGEN_PROVIDER=local) | 98.0% | 0.586 | 10.9s |
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

Net: hybrid beat both single-provider modes at the time (near-Gemini accuracy, no
hallucination, faster/cheaper SQL), with a known ceiling on exploratory hunts. Lifting it
means a richer AQLight SQL-gen
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
   The live unit as of 2026-08-04, worth matching if you launch by hand:
   `llama-server -m ~/slm-athena/training/gguf/AQLight-v4-q4_k_m.gguf --host 0.0.0.0
   --port 8080 -ngl 99 -c 32768 --parallel 2 --alias AQLight`. `--parallel 2` is what lets
   the two racing lanes hit it without queueing behind each other, and `-c 32768` is the
   window that holds `SQL_GEN_PROMPT` (about 7k tokens) plus 4096 of output. It MUST bind
   0.0.0.0, not 127.0.0.1 (see Gotchas).
2. **Enable the race** (the default): in `.env.s3` set `LLM_PROVIDER=gemini`,
   `LANE_MODE=hybrid`, `LANE_SIDE_BY_SIDE=true`, leave `SQLGEN_PROVIDER` unset, then
   `docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d orchestrator`.
   Other modes:
   - **Cloud only / local only**: `LANE_MODE=cloud` or `LANE_MODE=local`, or flip it at
     runtime from the audit-monitor gear (process state, reverts on restart).
   - **Whole app local**: `LLM_PROVIDER=local` (all agents on AQLight, no race). Air-gap /
     Gemini-key capped only; synthesis quality drops (relevance 0.464, hallucinations).
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
| `SQLGEN_PROVIDER` | (unset) | route ONLY NL->SQL gen here. Leave unset: it wins over the lane and would send BOTH lanes' SQL gen local. |
| `SQLGEN_MODEL` | (unset) | optional model override paired with `SQLGEN_PROVIDER` |
| `LANE_MODE` | `hybrid` on the box | `hybrid` \| `cloud` \| `local`. This is the live setting; see [`lane-mode.md`](lane-mode.md). |
| `LANE_SIDE_BY_SIDE` | `true` | show the losing lane and offer a swap. `false` races but reports one answer. |

Related: **[`lane-race.md`](lane-race.md)**, which is how AQLight actually runs today: a
full second lane against Gemini, prose included, whichever finishes first shown with a UI
swap for the other. The `SQLGEN_PROVIDER` hybrid above rerouted one step instead, and the
two do not compose. Note the local lane measures slower than Gemini on the current T4 box,
contrary to the throughput figures earlier in this doc.

Set these in `.env.s3` on the box (authoritative env), then
`docker compose -f docker-compose.agents.yml --env-file .env.s3 up -d` the affected service.

## Gotchas

- **`SQLGEN_PROVIDER` is not compatible with the lane race.** An explicit `provider=` beats
  the lane in `llm_complete`, so setting it local sends the cloud lane's SQL gen to the
  local server as well, with `GEMINI_MODEL` as the model name and no base-URL override.
  llama.cpp ignores the model field, so nothing errors: both lanes just generate SQL on
  AQLight and the race quietly becomes a prose-only comparison. Leave it unset while
  `LANE_MODE=hybrid`. The local lane already reaches AQLight for SQL through `role="sqlgen"`.
- **Neither hybrid nor the local lane falls back if AQLight is down.** The local provider
  does not fall back to cloud, by design. With `SQLGEN_PROVIDER=local` that meant every
  athena-hunter SQL gen ERRORS; with the race it means the local lane loses and the cloud
  lane answers, which is the better failure. Either way AQLight is a systemd service with
  `Restart=always`. If the local lane goes permanently silent, check `systemctl status
  aqlight` first.
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
