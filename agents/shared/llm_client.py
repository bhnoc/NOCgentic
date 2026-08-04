"""
llm_client.py — Unified LLM client using LangChain + OpenInference OTEL tracing.

The OpenInference LangChain instrumentor (wired up in telemetry.py via
LangChainInstrumentor().instrument()) hooks LangChain's callback manager, so
every ainvoke() below is auto-captured as an OpenInference LLM span (prompts,
completions, token usage, latency) and exported via the TracerProvider
configured in telemetry.py — no manual span creation needed here.

Spans include openinference.span.kind=LLM, llm.model_name, llm.token_count.*,
and input.value/output.value. (This replaced the LangSmith OTEL bridge, which
emitted no LLM spans in practice — see docs/MANIFOLD_INTEGRATION.md §3.)

Usage:
    from llm_client import llm_complete

    answer = await llm_complete(
        system_prompt="You are a security analyst.",
        user_content="Analyze this IP: 1.2.3.4",
        max_tokens=1024,
        temperature=0.1,
    )

Environment variables:
    LLM_PROVIDER        "gemini" (cloud), "openrouter" (cloud), or "local" (on-box). Default "gemini".
    GEMINI_API_KEY      Google Gemini API key
    OPENROUTER_API_KEY  OpenRouter API key
    GEMINI_MODEL        default: gemini-3.5-flash-lite
    OPENROUTER_MODEL    default: anthropic/claude-3-haiku
    LOCAL_LLM_BASE_URL  OpenAI-compatible local server (llama.cpp/Ollama/vLLM). Default http://localhost:8080/v1
    LOCAL_LLM_MODEL     served model name for the local provider. Default "AQLight"
    SQLGEN_PROVIDER     optional: route ONLY NL->SQL gen to this provider (e.g. "local"),
                        leaving synthesis/classify/triage on LLM_PROVIDER. Hybrid mode.
    SQLGEN_MODEL        optional model override paired with SQLGEN_PROVIDER
    LOCAL_LLM_API_KEY   placeholder key for local servers. Default "not-needed"

Provider selection is per-box: a CPU/no-GPU host runs LLM_PROVIDER=gemini (cloud),
the GPU box can run LLM_PROVIDER=local against an on-box llama.cpp server. Same image,
different env. OpenRouter is the cloud fallback / alternative.

LANES (dual-provider race)
--------------------------
On top of the single-provider config above, a request may nominate a *lane*: a
named provider stack applied per ROLE within one pipeline run. Two lanes ship:

    "cloud"  sqlgen -> Gemini            prose -> Gemini
    "local"  sqlgen -> AQLight (local)   prose -> AQLight (local)   [default]

The local lane defaults to ONE model doing both roles, because AQLight is the only
local model that runs as a durable service on the box. Roles stay separate in the
code (role="sqlgen" vs "prose") so a second model can be split off with env alone.

Measured 2026-08-04 on the live g4dn.xlarge / Tesla T4
(temp/lane-bench-2026-08-04/RESULTS.md, 28 cases via bench/run_bench.py):

    Gemini everything          100.0% mean   8.7s   <- best on BOTH axes
    Foundation-Sec everything   97.4%        18.7s  <- best fully local
    AQLight SQL + Fnd-Sec       95.8%        13.4s
    AQLight everything          93.0%        14.6s  <- the default here

Two things that contradict the earlier design notes and are worth knowing before
tuning this: local is SLOWER than cloud here (~25 tok/s vs ~194 — earlier docs
assumed a 46GB L40S at 129 tok/s, not this 15GB T4), and Foundation-Sec beats
AQLight at NL->SQL (97.5% vs 92.5%), the one job AQLight was fine-tuned for. The
race is a comparison affordance on this hardware, not a latency win.

The orchestrator runs both lanes concurrently and shows whichever finishes
first; see agents/orchestrator/main.py. Lane env:

    LANE_RACE               "auto" (default) | "on" | "off". auto races only when a
                            local endpoint is actually configured, so a CPU-only box
                            degrades to single-lane with no dead calls.
    LOCAL_SQL_BASE_URL      llama-server for NL->SQL. Falls back to LOCAL_LLM_BASE_URL.
    LOCAL_SQL_MODEL         served alias for the SQL role. Falls back to LOCAL_LLM_MODEL.
    LOCAL_PROSE_BASE_URL    llama-server for prose. Falls back to LOCAL_SQL_BASE_URL
                            (-> AQLight everything). Set it to split the roles across
                            two ports; two GGUFs cannot share one llama-server.
    LOCAL_PROSE_MODEL       served alias for the prose role. Falls back to LOCAL_SQL_MODEL.

Passing lane=None (the default) keeps the legacy single-provider behaviour
exactly, so every existing call site is unaffected.

LANE MODE (runtime override of the env above)
---------------------------------------------
The env vars are the BOOT default. An operator can change what the box does for the
rest of the show without a redeploy, through the settings gear in the audit monitor:

    hybrid   race both lanes                  (the env default where local exists)
    cloud    Gemini only, no local calls      (a box with no GPU, or local is down)
    local    local models only, no Gemini     (an all-local demo, or the API key is
                                              gone, or someone will not allow
                                              conference data to leave the box)

and a separate `side_by_side` flag, default on, which decides whether hybrid RETAINS
the losing lane and offers the swap. Turn it off and hybrid still races for
resilience (first success wins, a dead lane costs nothing) but the analyst sees one
answer and no swap control.

The override is process state, deliberately not persisted. It reverts to the env on
restart, which is the failure mode you want: whatever someone set at 2am during a
demo does not silently outlive the container.

`local` mode is honoured even when no local endpoint is configured. That looks wrong
but is not: silently serving Gemini to someone who explicitly asked for local-only
would be the worst possible failure of a control whose whole point may be "this data
does not leave the box". It fails loudly instead.
"""

from __future__ import annotations

import contextvars
import logging
import os
import time
from typing import Any

from telemetry import get_meter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OTEL Metrics instruments (lazily initialised on first LLM call)
# ---------------------------------------------------------------------------

_metrics_ready = False
_token_counter = None
_cost_counter = None
_llm_duration = None


def _ensure_metrics() -> None:
    global _metrics_ready, _token_counter, _cost_counter, _llm_duration
    if _metrics_ready:
        return
    meter = get_meter()
    _token_counter = meter.create_counter(
        "bhnoc.tokens", unit="tokens",
        description="LLM token usage by type (input, output)",
    )
    _cost_counter = meter.create_counter(
        "bhnoc.cost.usd", unit="USD",
        description="Estimated LLM cost in USD",
    )
    _llm_duration = meter.create_histogram(
        "bhnoc.llm.duration_ms", unit="ms",
        description="LLM call end-to-end latency in milliseconds",
    )
    _metrics_ready = True


_COST_PER_1M: dict[str, tuple[float, float]] = {
    "gemini-2.5-flash":                (0.075, 0.30),
    "gemini-2.5-flash-preview":        (0.075, 0.30),
    "gemini-2.0-flash":                (0.075, 0.30),
    "gemini-3.1-flash-lite-preview":   (0.05,  0.20),
    "gemini-3.5-flash-lite":           (0.05,  0.20),
    "gemini-3.1-pro-preview":          (1.25, 10.00),
    "anthropic/claude-3-haiku":        (0.25,  1.25),
    "anthropic/claude-3-5-sonnet":     (3.00, 15.00),
}


def _estimate_cost_usd(model: str, input_tokens: int, output_tokens: int) -> float:
    in_rate, out_rate = _COST_PER_1M.get(model, (1.0, 1.0))
    return (input_tokens * in_rate + output_tokens * out_rate) / 1_000_000


def _record_otel_metrics(
    provider: str, model: str, latency_ms: float,
    input_tokens: int, output_tokens: int,
) -> None:
    _ensure_metrics()
    attrs = {"gen_ai.system": provider, "gen_ai.request.model": model}
    _token_counter.add(input_tokens, {**attrs, "token.type": "input"})
    _token_counter.add(output_tokens, {**attrs, "token.type": "output"})
    _cost_counter.add(_estimate_cost_usd(model, input_tokens, output_tokens), attrs)
    _llm_duration.record(latency_ms, attrs)


# ---------------------------------------------------------------------------
# In-process metrics snapshot (used by agents for span attrs)
# ---------------------------------------------------------------------------
# Held in a ContextVar, NOT a module global. Lane racing runs two pipelines
# concurrently in one process, and a plain dict is shared mutable state: both
# lanes would write it and each would then read whichever finished last. The
# reported model/latency/tok-per-sec is exactly what the UI's lane swap compares,
# so a clobber here means the local lane can be labelled "gemini-3.5-flash-lite"
# at the cloud lane's latency — a silently wrong benchmark rather than a crash.
#
# asyncio.Task copies the ambient context at creation, so each lane task gets its
# own binding for free. The default is a shared sentinel that is never mutated in
# place: _record_metrics always SETS a fresh dict, so no writer can reach across.

_last_metrics: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar(
    "bhnoc_last_llm_metrics", default={},
)


def get_last_llm_metrics() -> dict[str, Any]:
    """Return metrics from the most recent llm_complete call in THIS context."""
    return dict(_last_metrics.get())


def _record_metrics(
    provider: str, model: str, latency_ms: float,
    input_tokens: int, output_tokens: int,
    thinking_tokens: int, finish_reason: str,
    lane: str | None = None, role: str | None = None,
) -> None:
    tok_per_sec = round(output_tokens / (latency_ms / 1000), 1) if latency_ms > 0 else 0
    _last_metrics.set({
        "lane": lane,
        "role": role,
        "provider": provider,
        "model": model,
        "latency_ms": round(latency_ms, 1),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "thinking_tokens": thinking_tokens,
        "total_tokens": input_tokens + output_tokens,
        "tok_per_sec": tok_per_sec,
        "finish_reason": finish_reason,
    })


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "gemini").lower()

GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
# Default matches the deploy reality (docker-compose.agents.yml pins
# gemini-3.5-flash-lite). Defaulting to the pro-preview would silently route
# unset-env callers to the expensive/slow pro model AND skip the flash-lite
# thinking_budget 0->-1 clamp below (400 INVALID_ARGUMENT risk).
GEMINI_MODEL: str = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite")

OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL: str = os.getenv("OPENROUTER_MODEL", "anthropic/claude-3-haiku")

# Local provider: any OpenAI-compatible server (llama.cpp `llama-server`, Ollama,
# or vLLM) running on the GPU box. Selected with LLM_PROVIDER=local. The base URL
# is where that server listens; the API key is usually a placeholder for local
# servers (llama.cpp ignores it, Ollama accepts anything). Set LOCAL_LLM_MODEL to
# the served model name (e.g. the GGUF alias for llama.cpp, or "qwen3:8b" for Ollama).
# Default model name is AQLight (the fine-tuned Qwen2.5-Coder-7B NL->SQL model served
# on the GPU box via llama.cpp; see docs/llm/AQLight-integration.md). AQLight is a SQL
# SPECIALIST, great for athena-hunter's NL->SQL, but it does not do routing/classify,
# answer synthesis, or triage prose, so LLM_PROVIDER=local across ALL agents is not a
# drop-in for Gemini. Point only the SQL path at it, or run a general local model too.
LOCAL_LLM_BASE_URL: str = os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:8080/v1")
LOCAL_LLM_MODEL: str = os.getenv("LOCAL_LLM_MODEL", "AQLight")
LOCAL_LLM_API_KEY: str = os.getenv("LOCAL_LLM_API_KEY", "not-needed")

# HYBRID knob: route ONLY the NL->SQL generation step to a chosen provider, leaving every
# other call (classify, synthesis, triage) on LLM_PROVIDER. This exists because the
# capability eval (2026-07-30) showed AQLight is EXCELLENT at NL->SQL (routing 100%, its
# own eval 0.962) but HALLUCINATES in free-text synthesis (relevance 0.464 vs Gemini's
# 0.718 whole-app; it invented alert details and told the analyst to block the DNS
# forwarder). So the win is hybrid: AQLight writes the SQL, Gemini writes the prose.
# Unset by default -> SQL gen uses whatever LLM_PROVIDER already is (no behavior change).
# Set SQLGEN_PROVIDER=local (+ the LOCAL_LLM_* vars) to send only SQL gen to AQLight.
SQLGEN_PROVIDER: str = os.getenv("SQLGEN_PROVIDER", "").lower()
SQLGEN_MODEL: str = os.getenv("SQLGEN_MODEL", "")


# ---------------------------------------------------------------------------
# Lane config (dual-provider race) — see module docstring
# ---------------------------------------------------------------------------
# A lane is a provider stack keyed by ROLE. Roles are the two kinds of LLM work
# this app does, and they have opposite requirements:
#   "sqlgen" — structured output, temperature 0, correctness is binary
#   "prose"  — free text for an analyst; hallucination is the failure mode
# The roles exist so a box CAN serve them from two different models, not because it
# must: by default both resolve to the same local model (see LOCAL_PROSE_* below).

LANE_CLOUD = "cloud"
LANE_LOCAL = "local"

# AQLight (SQL specialist). Separate vars from LOCAL_LLM_* so the two local models
# can live on different ports, but fall back to LOCAL_LLM_* so an existing
# single-model box keeps working with no new env.
LOCAL_SQL_BASE_URL: str = os.getenv("LOCAL_SQL_BASE_URL", "") or LOCAL_LLM_BASE_URL
LOCAL_SQL_MODEL: str = os.getenv("LOCAL_SQL_MODEL", "") or LOCAL_LLM_MODEL

# Prose model. Falls back to the SQL endpoint, which makes the local lane
# AQLight-for-everything by default: AQLight is the only local model that runs as a
# durable service (aqlight.service, Restart=always), so it is the only one a box
# has on hand with no new infra. Set LOCAL_PROSE_* to split the roles across two
# llama-servers.
#
# This fallback was deliberately absent until the 2026-08-04 measurement
# (temp/lane-bench-2026-08-04/RESULTS.md), on the theory that AQLight prose was
# dangerous enough that no-local-lane beat AQLight-prose. The bench does not
# support that: AQLight-everything scores 93.0% mean vs 95.8% for the
# AQLight-SQL + Foundation-Sec-prose split — a real but modest gap, not the
# categorical failure the earlier relevance number (0.464) implied. A working
# single-model lane is worth more than a two-model lane nobody has stood up.
#
# Foundation-Sec remains the better prose model (94.8% vs 86.5% summarize) and the
# better SQL model (97.5% vs 92.5%). If you are willing to serve a second GGUF,
# point BOTH vars at it rather than splitting the roles.
LOCAL_PROSE_BASE_URL: str = os.getenv("LOCAL_PROSE_BASE_URL", "") or LOCAL_SQL_BASE_URL
LOCAL_PROSE_MODEL: str = os.getenv("LOCAL_PROSE_MODEL", "") or LOCAL_SQL_MODEL

# "auto" (default): race only when a local prose endpoint is configured. This is
# what makes the same image safe on the CPU box (no local models -> single lane,
# zero failed calls) and on the GPU box (both configured -> race).
LANE_RACE: str = os.getenv("LANE_RACE", "auto").lower()


def local_lane_available() -> bool:
    """True if this box is actually configured to serve a local lane.

    Tests the RAW env, not the resolved LOCAL_SQL_BASE_URL / LOCAL_PROSE_BASE_URL:
    those fall back through LOCAL_LLM_BASE_URL, which itself defaults to a non-empty
    "http://localhost:8080/v1". Reading the resolved values would therefore report a
    local lane on every box, and "auto" would race the CPU-only box against a
    llama-server that is not running — one guaranteed-failed lane per query.
    """
    return any(
        os.getenv(var)
        for var in ("LOCAL_SQL_BASE_URL", "LOCAL_PROSE_BASE_URL", "LOCAL_LLM_BASE_URL")
    )


# ---------------------------------------------------------------------------
# Lane mode: runtime override of the env defaults
# ---------------------------------------------------------------------------

MODE_HYBRID = "hybrid"
MODE_CLOUD = "cloud"
MODE_LOCAL = "local"
LANE_MODES = (MODE_HYBRID, MODE_CLOUD, MODE_LOCAL)

# Plain module state, not a ContextVar: unlike _last_metrics and the base-url
# override, this is one setting for the whole process rather than per-request, and a
# ContextVar would not be visible to the request that reads it after the request
# that set it.
_lane_mode: str | None = None          # None = follow the env
_side_by_side: bool | None = None      # None = follow the env


def _env_lane_mode() -> str:
    """The mode the env asks for, before any runtime override.

    LANE_MODE, if set, wins outright. Otherwise it is derived from LANE_RACE so a box
    that predates this control keeps behaving exactly as it did: "off" on a box with
    no local endpoint is cloud-only, and "off" on a box that HAS one is still
    cloud-only, because that is what "off" already meant (the local lane existed but
    was not raced, and the cloud lane answered).
    """
    explicit = os.getenv("LANE_MODE", "").strip().lower()
    if explicit in LANE_MODES:
        return explicit
    if LANE_RACE == "off":
        return MODE_CLOUD
    if LANE_RACE == "on":
        return MODE_HYBRID
    return MODE_HYBRID if local_lane_available() else MODE_CLOUD


def _env_side_by_side() -> bool:
    """Whether hybrid keeps the loser and offers the swap. On unless told otherwise."""
    return os.getenv("LANE_SIDE_BY_SIDE", "true").strip().lower() not in (
        "false", "0", "no", "off",
    )


def lane_mode() -> str:
    """The mode in force right now: runtime override if set, else the env."""
    return _lane_mode if _lane_mode in LANE_MODES else _env_lane_mode()


def side_by_side_enabled() -> bool:
    """Whether a raced query should retain the loser for the UI swap control."""
    return _env_side_by_side() if _side_by_side is None else _side_by_side


def set_lane_mode(mode: str | None, *, side_by_side: bool | None = None) -> dict[str, Any]:
    """Override the mode for this process. Pass None to fall back to the env.

    Returns the resulting state so a caller does not have to re-read it and risk
    reporting something different from what it set.
    """
    global _lane_mode, _side_by_side
    if mode is not None and mode not in LANE_MODES:
        raise ValueError(f"unknown lane mode {mode!r}; expected one of {LANE_MODES}")
    _lane_mode = mode
    if side_by_side is not None:
        _side_by_side = bool(side_by_side)
    return lane_mode_state()


def reset_lane_mode() -> None:
    """Drop both overrides. Used by tests and by the admin reset control."""
    global _lane_mode, _side_by_side
    _lane_mode = None
    _side_by_side = None


def lane_mode_state() -> dict[str, Any]:
    """Everything the settings UI needs to render itself honestly."""
    mode = lane_mode()
    return {
        "mode": mode,
        "side_by_side": side_by_side_enabled(),
        "racing": lane_race_enabled(),
        "env_mode": _env_lane_mode(),
        "overridden": _lane_mode is not None or _side_by_side is not None,
        "local_configured": local_lane_available(),
        # Surfaced because the UI has to be able to explain a mode that cannot
        # actually answer, rather than leaving the operator to discover it per query.
        "local_missing": mode in (MODE_LOCAL, MODE_HYBRID) and not local_lane_available(),
        "modes": list(LANE_MODES),
        "roles": {
            "sqlgen": {"base_url": LOCAL_SQL_BASE_URL, "model": LOCAL_SQL_MODEL},
            "prose": {"base_url": LOCAL_PROSE_BASE_URL, "model": LOCAL_PROSE_MODEL},
        },
        "cloud_model": GEMINI_MODEL,
    }


def lane_race_enabled() -> bool:
    """Whether to run two lanes per query.

    Only hybrid races. cloud and local are single-lane by definition, so this is
    now a question about the mode rather than about LANE_RACE directly (LANE_RACE
    still feeds the mode default; see _env_lane_mode).

    Hybrid races even when the local endpoints look unconfigured, because "on" was
    always an operator override that let a misconfigured box fail loudly instead of
    silently serving one lane. A dead lane costs nothing: the race takes the first
    SUCCESS, not the first completion.
    """
    return lane_mode() == MODE_HYBRID


def mode_was_chosen() -> bool:
    """True if somebody explicitly picked a mode, rather than it being derived.

    The distinction matters for what single-lane means. A mode DERIVED from
    LANE_RACE=off has to keep meaning what "off" always meant: run one pipeline on
    the ambient LLM_PROVIDER. Pinning that to the cloud lane would force Gemini on a
    box running LLM_PROVIDER=openrouter, which is a silent provider switch nobody
    asked for.

    A mode somebody CHOSE, in the env or through the gear, is a different statement:
    they want that provider stack specifically, so pin it.
    """
    return _lane_mode is not None or os.getenv("LANE_MODE", "").strip().lower() in LANE_MODES


def single_lane() -> str | None:
    """The one lane to pin the pipeline to, or None to use the ambient provider.

    None means both "we are racing" and "we are single-lane by inheritance", because
    in both cases the caller should not override the provider: the racer passes real
    lane names itself, and the inherited case wants LLM_PROVIDER.
    """
    if not mode_was_chosen():
        return None
    mode = lane_mode()
    if mode == MODE_CLOUD:
        return LANE_CLOUD
    if mode == MODE_LOCAL:
        return LANE_LOCAL
    return None


def resolve_lane(lane: str | None, role: str) -> tuple[str | None, str | None]:
    """Map (lane, role) -> (provider, model) for llm_complete.

    Returns (None, None) for an unknown lane or the legacy lane=None path, which
    means "use the ambient LLM_PROVIDER config" — i.e. every pre-existing call
    site behaves exactly as it did before lanes existed.
    """
    if lane == LANE_CLOUD:
        # The cloud lane is Gemini for both roles. Explicit rather than inherited
        # so a box running LLM_PROVIDER=local still gets a genuine cloud lane to
        # race against, instead of racing local against local.
        return "gemini", GEMINI_MODEL
    if lane == LANE_LOCAL:
        if role == "sqlgen":
            return "local", LOCAL_SQL_MODEL
        # Every non-sqlgen role (prose, classify, hints, triage) is free text.
        return "local", LOCAL_PROSE_MODEL
    return None, None


# Per-role base URL override. The two local models are separate llama-server
# processes on separate ports, so provider+model is not enough to address them —
# the base URL has to vary per role too. Held in a ContextVar for the same reason
# as _last_metrics: two lanes run concurrently and a global would cross-wire them,
# sending prose to the SQL model.
_base_url_override: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bhnoc_local_base_url", default=None,
)


def resolve_lane_base_url(lane: str | None, role: str) -> str | None:
    """Base URL for a (lane, role), or None to use the ambient default."""
    if lane != LANE_LOCAL:
        return None
    return LOCAL_SQL_BASE_URL if role == "sqlgen" else LOCAL_PROSE_BASE_URL


# ---------------------------------------------------------------------------
# LangChain model factories
# ---------------------------------------------------------------------------

def _get_gemini_model(
    model: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    thinking_budget: int | None = None,
):
    """Create a LangChain ChatGoogleGenerativeAI instance."""
    from langchain_google_genai import ChatGoogleGenerativeAI

    model_name = model or GEMINI_MODEL
    kwargs: dict[str, Any] = {
        "model": model_name,
        "google_api_key": GEMINI_API_KEY,
        "max_output_tokens": max_tokens,
        "temperature": temperature,
        "timeout": 120,
        "max_retries": 1,
    }
    if thinking_budget is not None:
        # gemini-3.5-flash-lite (and the 3.x lite line generally) rejects
        # thinkingBudget=0 with 400 INVALID_ARGUMENT — it cannot fully disable
        # thinking the way 3.1-flash-lite-preview could. Use -1 (DYNAMIC: the model
        # decides how much to think) as the closest "don't think much" fallback.
        # Caveat: -1 is model-decided, NOT guaranteed minimal. Dynamic thinking can
        # be large and shares max_output_tokens, so callers needing bounded output
        # (e.g. athena-hunter SQL gen) must pass an explicit positive budget, not -1.
        if thinking_budget == 0 and "flash-lite" in model_name:
            thinking_budget = -1
        kwargs["thinking_budget"] = thinking_budget

    return ChatGoogleGenerativeAI(**kwargs)


def _get_openrouter_model(
    model: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.1,
):
    """Create a LangChain ChatOpenAI instance pointing at OpenRouter."""
    from langchain_openai import ChatOpenAI

    model_name = model or OPENROUTER_MODEL
    return ChatOpenAI(
        model=model_name,
        openai_api_key=OPENROUTER_API_KEY,
        openai_api_base="https://openrouter.ai/api/v1",
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=90,
        default_headers={
            "HTTP-Referer": "https://nocgentic.noc",
            "X-Title": "BH Asia NOC Agent",
        },
    )


def _get_local_model(
    model: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    base_url: str | None = None,
):
    """Create a LangChain ChatOpenAI instance pointing at a LOCAL OpenAI-compatible
    server (llama.cpp `llama-server`, Ollama, or vLLM on the GPU box). Same client
    shape as OpenRouter, just a different base URL and no real key required. Longer
    timeout than the cloud paths because a cold local model can be slow to first token.

    base_url selects WHICH local server: AQLight and Foundation-Sec are two
    llama-server processes on two ports (one process serves one GGUF). Falls back to
    the context override, then LOCAL_LLM_BASE_URL."""
    from langchain_openai import ChatOpenAI

    model_name = model or LOCAL_LLM_MODEL
    return ChatOpenAI(
        model=model_name,
        openai_api_key=LOCAL_LLM_API_KEY,
        openai_api_base=base_url or _base_url_override.get() or LOCAL_LLM_BASE_URL,
        max_tokens=max_tokens,
        temperature=temperature,
        timeout=180,
    )


def _extract_content(response) -> str:
    """Extract text content from LangChain response (handles both str and list)."""
    raw = response.content
    if isinstance(raw, str):
        return raw.strip()
    elif isinstance(raw, list):
        parts = []
        for block in raw:
            if isinstance(block, dict):
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "".join(parts).strip()
    return str(raw).strip()


# ---------------------------------------------------------------------------
# Unified public API
# ---------------------------------------------------------------------------

async def llm_complete(
    system_prompt: str,
    user_content: str,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    model: str | None = None,
    provider: str | None = None,
    thinking_budget: int | None = None,
    lane: str | None = None,
    role: str = "prose",
) -> str:
    """
    Send a completion request via LangChain.

    LangSmith OTEL integration automatically traces all LLM calls —
    prompts, completions, token usage, and model metadata are captured
    as OTEL spans and exported to Manifold via our TracerProvider.

    lane/role select a provider stack for the dual-lane race (see module
    docstring). lane=None is the legacy path: provider/model resolve from the
    ambient LLM_PROVIDER env exactly as before. An explicit provider= argument
    still wins over the lane, so SQLGEN_PROVIDER-style overrides keep working.
    """
    from langchain_core.messages import SystemMessage, HumanMessage

    # Lane resolution is a DEFAULT, not an override: an explicit provider=/model=
    # from the caller takes precedence. That keeps the pre-lane hybrid knob
    # (SQLGEN_PROVIDER) authoritative where it is already set.
    lane_base_url: str | None = None
    if lane:
        lane_provider, lane_model = resolve_lane(lane, role)
        provider = provider or lane_provider
        model = model or lane_model
        lane_base_url = resolve_lane_base_url(lane, role)

    active = (provider or LLM_PROVIDER).lower()

    # Resolve provider with fallback
    if active == "gemini":
        if not GEMINI_API_KEY:
            if OPENROUTER_API_KEY:
                logger.warning("GEMINI_API_KEY not set — falling back to OpenRouter")
                active = "openrouter"
            else:
                raise RuntimeError("No LLM API key configured")
    elif active == "openrouter":
        if not OPENROUTER_API_KEY:
            if GEMINI_API_KEY:
                logger.warning("OPENROUTER_API_KEY not set — falling back to Gemini")
                active = "gemini"
            else:
                raise RuntimeError("No LLM API key configured")
    elif active == "local":
        # Local server needs no API key; the only requirement is a base URL, which
        # always has a default. No fallback: if LLM_PROVIDER=local, the operator
        # explicitly wants the on-box model, so surface a clear error if it's down
        # rather than silently phoning home to a cloud provider.
        pass
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {active}")

    # Build LangChain model
    if active == "gemini":
        llm = _get_gemini_model(model, max_tokens, temperature, thinking_budget)
        provider_name = "google"
        model_name = model or GEMINI_MODEL
    elif active == "local":
        llm = _get_local_model(model, max_tokens, temperature, base_url=lane_base_url)
        provider_name = "local"
        model_name = model or LOCAL_LLM_MODEL
    else:
        llm = _get_openrouter_model(model, max_tokens, temperature)
        provider_name = "openrouter"
        model_name = model or OPENROUTER_MODEL

    # Build messages
    messages = []
    if system_prompt:
        messages.append(SystemMessage(content=system_prompt))
    messages.append(HumanMessage(content=user_content))

    # Invoke — LangSmith OTEL auto-traces this
    t0 = time.monotonic()
    response = await llm.ainvoke(messages)
    latency_ms = (time.monotonic() - t0) * 1000

    result = _extract_content(response)

    # Extract token usage from LangChain response metadata
    usage = getattr(response, "usage_metadata", None) or {}
    if isinstance(usage, dict):
        input_tok = usage.get("input_tokens", 0)
        output_tok = usage.get("output_tokens", 0)
    else:
        input_tok = getattr(usage, "input_tokens", 0)
        output_tok = getattr(usage, "output_tokens", 0)

    thinking_tok = 0
    resp_meta = getattr(response, "response_metadata", None) or {}
    if isinstance(resp_meta, dict):
        thinking_tok = resp_meta.get("thoughts_token_count", 0)

    finish_reason = "stop"
    if isinstance(resp_meta, dict):
        fr = resp_meta.get("finish_reason", "stop")
        if isinstance(fr, str):
            finish_reason = fr.lower()

    # A MAX_TOKENS / length finish means the model was cut off mid-answer and
    # `result` is silently truncated. Surface it in logs so callers/operators
    # can spot truncated completions (return type is unchanged).
    if finish_reason in ("max_tokens", "length"):
        logger.warning(
            "LLM response truncated (finish_reason=%s, max_tokens=%d, output_tokens=%s) model=%s",
            finish_reason, max_tokens, output_tok, model_name,
        )

    _record_metrics(
        provider=provider_name, model=model_name, latency_ms=latency_ms,
        input_tokens=input_tok, output_tokens=output_tok,
        thinking_tokens=thinking_tok, finish_reason=finish_reason,
        lane=lane, role=role if lane else None,
    )
    _record_otel_metrics(provider_name, model_name, latency_ms, input_tok, output_tok)

    return result
