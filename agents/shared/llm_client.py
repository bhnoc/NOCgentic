"""
llm_client.py — Unified LLM client using LangChain + OpenInference OTEL tracing.

The OpenInference LangChain instrumentor (wired up in telemetry.py via
LangChainInstrumentor().instrument()) hooks LangChain's callback manager, so
every ainvoke() below is auto-captured as an OpenInference LLM span (prompts,
completions, token usage, latency) and exported via the TracerProvider
configured in telemetry.py — no manual span creation needed here.

Spans include openinference.span.kind=LLM, llm.model_name, llm.token_count.*,
and input.value/output.value. (This replaced the LangSmith OTEL bridge, which
emitted no LLM spans in practice — see MANIFOLD_INTEGRATION.md §3.)

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
    LOCAL_LLM_API_KEY   placeholder key for local servers. Default "not-needed"

Provider selection is per-box: a CPU/no-GPU host runs LLM_PROVIDER=gemini (cloud),
the GPU box can run LLM_PROVIDER=local against an on-box llama.cpp server. Same image,
different env. OpenRouter is the cloud fallback / alternative.
"""

from __future__ import annotations

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

_last_metrics: dict[str, Any] = {}


def get_last_llm_metrics() -> dict[str, Any]:
    """Return metrics from the most recent llm_complete call."""
    return dict(_last_metrics)


def _record_metrics(
    provider: str, model: str, latency_ms: float,
    input_tokens: int, output_tokens: int,
    thinking_tokens: int, finish_reason: str,
) -> None:
    tok_per_sec = round(output_tokens / (latency_ms / 1000), 1) if latency_ms > 0 else 0
    _last_metrics.clear()
    _last_metrics.update({
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
# on the AING box via llama.cpp; see docs/llm/AQLight-integration.md). AQLight is a SQL
# SPECIALIST, great for athena-hunter's NL->SQL, but it does not do routing/classify,
# answer synthesis, or triage prose, so LLM_PROVIDER=local across ALL agents is not a
# drop-in for Gemini. Point only the SQL path at it, or run a general local model too.
LOCAL_LLM_BASE_URL: str = os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:8080/v1")
LOCAL_LLM_MODEL: str = os.getenv("LOCAL_LLM_MODEL", "AQLight")
LOCAL_LLM_API_KEY: str = os.getenv("LOCAL_LLM_API_KEY", "not-needed")


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
            "HTTP-Referer": "https://bhasia2026.noc",
            "X-Title": "BH Asia NOC Agent",
        },
    )


def _get_local_model(
    model: str | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.1,
):
    """Create a LangChain ChatOpenAI instance pointing at a LOCAL OpenAI-compatible
    server (llama.cpp `llama-server`, Ollama, or vLLM on the GPU box). Same client
    shape as OpenRouter, just a different base URL and no real key required. Longer
    timeout than the cloud paths because a cold local model can be slow to first token."""
    from langchain_openai import ChatOpenAI

    model_name = model or LOCAL_LLM_MODEL
    return ChatOpenAI(
        model=model_name,
        openai_api_key=LOCAL_LLM_API_KEY,
        openai_api_base=LOCAL_LLM_BASE_URL,
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
) -> str:
    """
    Send a completion request via LangChain.

    LangSmith OTEL integration automatically traces all LLM calls —
    prompts, completions, token usage, and model metadata are captured
    as OTEL spans and exported to Manifold via our TracerProvider.
    """
    from langchain_core.messages import SystemMessage, HumanMessage

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
        llm = _get_local_model(model, max_tokens, temperature)
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
    )
    _record_otel_metrics(provider_name, model_name, latency_ms, input_tok, output_tok)

    return result
