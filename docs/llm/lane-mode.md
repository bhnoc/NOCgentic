# Lane mode: cloud only, local only, or hybrid

[`lane-race.md`](lane-race.md) covers *how* two lanes race. This covers *whether they
run at all*, and how an operator changes that mid-show without a redeploy.

Three modes:

| mode | what runs | when you want it |
|------|-----------|------------------|
| `hybrid` | both lanes race, fastest shown, swap to the other | the demo default on the GPU box |
| `cloud` | Gemini only | a CPU-only deployment, or when the GPU box is down |
| `local` | the box only | nothing may leave the network |

Plus one independent flag, `side_by_side`, which decides whether the loser is shown
at all. It only means anything in hybrid.

## Where the mode comes from

Boot default is the env. `LANE_MODE` wins outright when it holds a valid mode;
otherwise the mode is derived from `LANE_RACE`, so every existing box keeps behaving
exactly as it did:

```
LANE_MODE=hybrid|cloud|local   -> that mode
LANE_MODE unset or a typo      -> LANE_RACE=off  -> cloud
                                  LANE_RACE=on   -> hybrid
                                  LANE_RACE=auto -> hybrid iff a local endpoint is set
```

A typo falls through rather than failing. Bricking the box over a misspelled
`hybird` in `.env.s3` would be a poor trade.

### Derived cloud is not the same as chosen cloud

An *inherited* cloud mode (from `LANE_RACE=off`) does not pin a lane: calls go to the
ambient `LLM_PROVIDER`, which is what `off` has always meant. An *explicitly chosen*
cloud mode pins the cloud lane. The distinction matters because pinning on inherit
would silently move a box running `LLM_PROVIDER=openrouter` onto Gemini, which nobody
asked for. `mode_was_chosen()` is the check; `single_lane()` returns `None` when the
mode was merely inherited.

## Local only does not fall back

If the local endpoint is down and the mode is `local`, queries fail. They are not
quietly sent to Gemini.

Someone selects local only because conference query text must not leave the box. A
silent fallback would defeat exactly that control, at the moment nobody is watching
the panel. So the failure is loud, and `lane_mode_state()` reports
`local_missing: true` so the gear can warn before anyone tries.

## Runtime overrides are process state

Changing the mode from the gear changes it in memory in the orchestrator process. It
does not write `.env.s3`, and it does not survive a restart: the container comes back
on whatever the env says.

That is deliberate. A mode flipped at 2am to get a demo out of trouble should not
still be in force next week with nobody remembering why. The panel labels the env
value as the deployed default and shows when the live mode differs from it.

The mode is folded into the response cache key
(`_lane_fingerprint()`), so a mode change does not serve answers produced by a
different lane. Nothing is purged on a mode change, and nothing needs to be.

## side_by_side off keeps the race

`LANE_SIDE_BY_SIDE=false` (or the checkbox) means "show one answer, no swap". The
second lane still runs. That is not an oversight: the race is what makes a dead or
slow lane free, since first *success* wins. What changes is that the loser is
cancelled instead of drained into the lane store, and no lane metadata is reported.

Cover responses mirror whatever the real answers do here. If covers offered a swap
while real answers did not, the presence of the swap control alone would tell a
caller which questions were filtered. See the cover-parity note in
[`lane-race.md`](lane-race.md).

## The settings gear

In the audit monitor (`/bh/1337/thetraces/`), the ⚙ button next to the kill switch
opens a panel with:

- the three modes as radios, with the deployed default marked and a warning when
  local is selected but not configured
- the side-by-side checkbox, shown only for hybrid, on by default
- every local model the box knows about, with what each endpoint is actually
  serving, and start/stop controls when a supervisor is configured

Reading the panel needs the audit cookie you already have. **Changing** anything
needs the admin bearer, prompted once and held for the life of the panel. The
audit monitor proxies to the orchestrator's `/admin/lanemode` and `/admin/models`;
the browser never talks to the orchestrator directly.

While the panel is open it polls every 5s, so a model that is still mapping into VRAM
turns from offline to serving without a manual refresh.

### The model rows

Each role row shows one of three states, which are worth distinguishing:

| pill | meaning |
|------|---------|
| offline | the endpoint did not answer. Normal on a CPU box. |
| serving | the endpoint answers and serves the model the lane asks for. |
| wrong model | **the silent one.** The endpoint answers, so nothing looks broken, but it serves a different alias than `LOCAL_*_MODEL` names, so every local call 404s. |

## Starting and stopping models

Start/stop is not something the orchestrator can do by itself. It runs in a
container, and every way of letting a container spawn host processes (docker socket,
host PID namespace, an SSH key) ends with the container that ships conference traffic
to an external LLM able to run root commands on the box.

So the capability lives in a separate tiny process on the host,
[`ops/model-supervisor/`](../../ops/model-supervisor/README.md). The boundary rule:
**the caller names an allowlist key, the host file decides the command.** No paths,
ports, flags or command strings cross. Auth fails closed, and the supervisor refuses
to bind all interfaces.

Leave `MODEL_SUPERVISOR_URL` unset on any box without local models. The panel then
renders read-only, which is the correct state, not a broken one. Discovery works
either way.

## Admin API

| route | auth | does |
|-------|------|------|
| `GET /admin/lanemode` | bearer | current mode, env default, side-by-side, whether local is configured |
| `POST /admin/lanemode` | bearer | `{mode, side_by_side}`. `mode: "env"` drops the override. Either field may be omitted and is then left alone. |
| `GET /admin/models` | bearer | per-role endpoint, configured alias, what is actually served, supervisor allowlist |
| `POST /admin/models/start` | bearer | `{role, model}` where `model` is an allowlist key |
| `POST /admin/models/stop` | bearer | `{role}` |

## Env reference

| var | default | meaning |
|-----|---------|---------|
| `LANE_MODE` | *(empty)* | `hybrid` \| `cloud` \| `local`. Empty derives from `LANE_RACE`. |
| `LANE_SIDE_BY_SIDE` | `true` | show the losing lane and the swap |
| `MODEL_SUPERVISOR_URL` | *(empty)* | host supervisor, e.g. `http://host.docker.internal:8790`. Empty = read-only model panel. |
| `MODEL_SUPERVISOR_TOKEN` | *(empty)* | shared secret with the host unit |

Tests: `tests/python/test_lane_mode.py` (env derivation, override scope, the
no-fallback property, pinning, side-by-side, orchestrator wiring),
`tests/python/test_local_models.py` (discovery, the control boundary),
`tests/python/test_model_supervisor.py` (allowlist, argv invariant, fail-closed
auth, bind refusal).
