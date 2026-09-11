"""
AI service classifier: cluster -> (service, behaviour, confidence, evidence).

Vendored from research-pipeline `classifier.py` (APE-86). Changes for production:

  * The three LangGraph tools are plain functions (`lookup_service_indicators`,
    `classify_behavior`, `score_confidence`) that return dicts. The `@tool`
    wrappers are built inside `build_classifier_agent`, so `langchain_*` and
    `langgraph` are imported only when the LLM mode is actually used. The rules
    mode and the test-suite need no LLM dependency at all.
  * `rules` mode: the same three tools called in the order the system prompt
    asks the model to call them. Deterministic, no network, no key. It is also
    the per-cluster fallback when the LLM call fails, so a Claude outage or a
    malformed model answer degrades to a labelled finding instead of an
    "Unknown (classification error)" record.
  * Every LLM answer is validated field by field against the rules baseline:
    an out-of-range confidence or an unknown severity string falls back to the
    deterministic value rather than being stored as-is.
  * Model defaults to `claude-opus-5`; `temperature` is no longer passed
    (Opus 5 rejects sampling parameters with a 400).
  * `print` replaced by logging.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

log = logging.getLogger("zeek-detector.classifier")

DEFAULT_MODEL = "claude-opus-5"

MODE_AUTO = "auto"
MODE_LLM = "llm"
MODE_RULES = "rules"
MODES = (MODE_AUTO, MODE_LLM, MODE_RULES)

SERVICE_IDS = (
    "openai", "anthropic", "google_ai", "huggingface", "azure_openai",
    "langsmith", "local_llm", "crewai", "cohere", "mistral", "unknown",
)
BEHAVIORS = ("agentic-orchestration", "data-retrieval", "unknown")
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCE_LEVELS = ("high", "medium", "low", "insufficient")


# ── Known AI service indicators ───────────────────────────────────────────────

AI_SERVICE_CATALOG: dict[str, dict] = {
    "openai": {
        "display_name": "OpenAI (ChatGPT / API)",
        "hostname_patterns": [
            "api.openai.com",
            "chat.openai.com",
            "openai.com",
            r".*\.openai\.com$",
            r".*\.openai\.azure\.com$",
        ],
        "behaviors": ["agentic_loop", "context_reset", "data-retrieval"],
        "typical_ports": [443],
    },
    "anthropic": {
        "display_name": "Anthropic (Claude API)",
        "hostname_patterns": [
            "api.anthropic.com",
            "claude.ai",
            "anthropic.com",
            r".*\.anthropic\.com$",
        ],
        "behaviors": ["agentic_loop", "context_reset", "data-retrieval"],
        "typical_ports": [443],
    },
    "google_ai": {
        "display_name": "Google AI (Gemini / Vertex AI)",
        "hostname_patterns": [
            "generativelanguage.googleapis.com",
            r".*aiplatform\.googleapis\.com$",
            r".*ml\.googleapis\.com$",
        ],
        "behaviors": ["data-retrieval", "agentic_loop"],
        "typical_ports": [443],
    },
    "huggingface": {
        "display_name": "HuggingFace Inference API",
        "hostname_patterns": [
            "api-inference.huggingface.co",
            "huggingface.co",
            r".*\.huggingface\.co$",
        ],
        "behaviors": ["data-retrieval"],
        "typical_ports": [443],
    },
    "azure_openai": {
        "display_name": "Azure OpenAI Service",
        "hostname_patterns": [
            r".*\.openai\.azure\.com$",
            r".*cognitiveservices\.azure\.com$",
        ],
        "behaviors": ["agentic_loop", "context_reset"],
        "typical_ports": [443],
    },
    "langsmith": {
        "display_name": "LangSmith / LangChain (orchestration tracing)",
        "hostname_patterns": [
            "api.smith.langchain.com",
            r".*\.langchain\.com$",
        ],
        "behaviors": ["agentic-orchestration"],
        "typical_ports": [443],
    },
    "local_llm": {
        "display_name": "Local LLM (Ollama / LMStudio / LangGraph)",
        "hostname_patterns": [
            "localhost",
            "127.0.0.1",
            r"^10\.\d+\.\d+\.\d+$",
            r"^192\.168\.\d+\.\d+$",
            r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",
        ],
        "behaviors": ["agentic-orchestration", "agentic_loop"],
        "typical_ports": [11434, 1234, 8080, 8000, 7860],
    },
    "crewai": {
        "display_name": "CrewAI (multi-agent orchestration)",
        "hostname_patterns": [
            r".*crewai\.com$",
        ],
        "behaviors": ["agentic-orchestration", "agentic_loop"],
        "typical_ports": [443],
    },
    "cohere": {
        "display_name": "Cohere API",
        "hostname_patterns": [
            "api.cohere.ai",
            r".*\.cohere\.ai$",
            r".*\.cohere\.com$",
        ],
        "behaviors": ["data-retrieval"],
        "typical_ports": [443],
    },
    "mistral": {
        "display_name": "Mistral AI API",
        "hostname_patterns": [
            "api.mistral.ai",
            r".*\.mistral\.ai$",
        ],
        "behaviors": ["data-retrieval", "agentic_loop"],
        "typical_ports": [443],
    },
}

# ── Behavior classification map ───────────────────────────────────────────────

BEHAVIOR_MAP = {
    "context_reset": {
        "classification": "agentic-orchestration",
        "description": "Repeated context resets indicate an agent resetting its context window — "
                       "consistent with LLM orchestration frameworks (LangChain, CrewAI, AutoGPT).",
        "severity": "medium",
    },
    "agentic_loop": {
        "classification": "agentic-orchestration",
        "description": "Near-constant repetitive request timing indicates a tight tool-call loop — "
                       "consistent with an agentic system iteratively calling an LLM or tool.",
        "severity": "medium",
    },
    "agentic_loop+context_reset": {
        "classification": "agentic-orchestration",
        "description": "Both context resets and agentic loop detected — strongly indicates a "
                       "multi-step AI agent actively orchestrating tasks.",
        "severity": "high",
    },
    "none": {
        "classification": "data-retrieval",
        "description": "No distinctive agentic timing patterns. Traffic is consistent with "
                       "standard API queries or browser-based AI tool usage.",
        "severity": "low",
    },
}


# ── The three tools (plain functions) ─────────────────────────────────────────

def lookup_service_indicators(hostname: str, dst_port: int) -> dict:
    """Match a hostname (SNI) and port against the AI service catalogue."""
    if not hostname:
        # No SNI: only the local-LLM port hints can say anything.
        for svc_id, svc in AI_SERVICE_CATALOG.items():
            if dst_port in svc.get("typical_ports", []) and svc_id == "local_llm":
                return {
                    "matched_service": svc_id,
                    "display_name": svc["display_name"],
                    "match_type": "port_match",
                    "confidence_hint": 0.55,
                    "typical_behaviors": svc["behaviors"],
                }
        return {"matched_service": "unknown", "confidence_hint": 0.0}

    hostname = hostname.lower().strip()
    matches = []

    for svc_id, svc in AI_SERVICE_CATALOG.items():
        for pattern in svc["hostname_patterns"]:
            if pattern.startswith(r".*") or pattern.startswith(r"^"):
                if re.match(pattern, hostname):
                    matches.append((svc_id, svc, "regex_match", 0.90))
                    break
            else:
                if hostname == pattern or hostname.endswith("." + pattern):
                    matches.append((svc_id, svc, "exact_match", 0.95))
                    break
                if pattern in hostname:
                    matches.append((svc_id, svc, "substring_match", 0.75))
                    break

    if not matches:
        return {
            "matched_service": "unknown",
            "hostname": hostname,
            "confidence_hint": 0.0,
            "note": "No known AI service pattern matched this hostname.",
        }

    best_svc_id, best_svc, match_type, conf = sorted(matches, key=lambda x: -x[3])[0]
    return {
        "matched_service": best_svc_id,
        "display_name": best_svc["display_name"],
        "match_type": match_type,
        "confidence_hint": conf,
        "typical_behaviors": best_svc["behaviors"],
        "hostname": hostname,
    }


def classify_behavior(patterns: list[str], sawtooth_score: float, loop_score: float) -> dict:
    """Map detected timing patterns and their scores to a behaviour + severity."""
    pattern_key = "+".join(sorted(patterns)) if patterns else "none"
    behavior_info = BEHAVIOR_MAP.get(pattern_key, BEHAVIOR_MAP["none"])

    severity = behavior_info["severity"]
    combined_score = max(sawtooth_score, loop_score)
    if combined_score > 0.7 and severity == "medium":
        severity = "high"
    elif combined_score > 0.9:
        severity = "critical"

    return {
        "behavior_classification": behavior_info["classification"],
        "description": behavior_info["description"],
        "severity": severity,
        "combined_pattern_score": round(combined_score, 4),
        "detected_patterns": list(patterns),
    }


def score_confidence(service_confidence_hint: float, pattern_score: float,
                     request_count: int, has_server_name: bool) -> dict:
    """Weighted confidence: hostname 60%, timing 25%, volume 10%, SNI present 5%."""
    count_score = min(request_count / 20.0, 1.0)
    sni_bonus = 0.05 if has_server_name else 0.0

    confidence = (
        0.60 * service_confidence_hint +
        0.25 * pattern_score +
        0.10 * count_score +
        sni_bonus
    )
    confidence = round(min(confidence, 1.0), 4)

    if confidence >= 0.85:
        level = "high"
    elif confidence >= 0.65:
        level = "medium"
    elif confidence >= 0.40:
        level = "low"
    else:
        level = "insufficient"

    explanation = (
        f"Hostname match: {service_confidence_hint:.0%} weight×0.60, "
        f"timing patterns: {pattern_score:.0%} weight×0.25, "
        f"request volume: {count_score:.0%} weight×0.10, "
        f"SNI available: {has_server_name}"
    )
    return {"confidence": confidence, "confidence_level": level, "explanation": explanation}


# ── Cluster helpers ───────────────────────────────────────────────────────────

def _cluster_fields(cluster: dict) -> dict:
    """Flatten the two cluster shapes (nested `metrics` or flat) into one dict."""
    metrics = cluster.get("metrics", cluster)
    return {
        "src_host": cluster.get("src_host", "unknown"),
        "dst_host": cluster.get("dst_host", "unknown"),
        "dst_port": cluster.get("dst_port", 443),
        "patterns": list(cluster.get("patterns", [])),
        "request_count": int(metrics.get("request_count", cluster.get("request_count", 0)) or 0),
        "sawtooth_score": float(metrics.get("sawtooth_score", cluster.get("sawtooth_score", 0.0)) or 0.0),
        "loop_score": float(metrics.get("loop_score", cluster.get("loop_score", 0.0)) or 0.0),
        "session_duration": float(metrics.get("session_duration", cluster.get("session_duration", 0.0)) or 0.0),
        "timing_entropy": float(metrics.get("timing_entropy", cluster.get("timing_entropy", 0.0)) or 0.0),
    }


def _unique_snis(server_names: list[str]) -> list[str]:
    seen: list[str] = []
    for sn in server_names:
        if sn and sn not in seen:
            seen.append(sn)
    return seen


def _recommendation(service_id: str, severity: str, display_name: str) -> str:
    if service_id == "unknown":
        return "No AI service matched; monitor the destination and re-check if the timing signature recurs."
    if severity in ("critical", "high"):
        return (f"Investigate: confirm the {display_name} workload on this host is sanctioned "
                f"and review what data it is sending.")
    if severity == "medium":
        return f"Review: verify the {display_name} usage on this host is expected and policy-compliant."
    return f"Monitor: {display_name} usage looks like ordinary API/browser traffic."


# ── Rules mode ────────────────────────────────────────────────────────────────

def classify_cluster_rules(cluster: dict, server_names: list[str]) -> dict:
    """Deterministic classification: the three tools, in the prompt's order."""
    f = _cluster_fields(cluster)
    snis = _unique_snis(server_names)
    primary_sni = snis[0] if snis else ""

    svc = lookup_service_indicators(primary_sni, f["dst_port"])
    beh = classify_behavior(f["patterns"], f["sawtooth_score"], f["loop_score"])
    conf = score_confidence(
        svc.get("confidence_hint", 0.0),
        beh["combined_pattern_score"],
        f["request_count"],
        bool(snis),
    )

    service_id = svc.get("matched_service", "unknown")
    display_name = svc.get("display_name", "Unknown Service")

    where = primary_sni or f"port {f['dst_port']}"
    evidence = []
    if service_id != "unknown":
        evidence.append(f"Service indicator: {svc.get('match_type')} on {where} → {display_name}")
    else:
        evidence.append("Service indicator: no catalogue match for "
                        f"{primary_sni or 'destination without SNI'}")
    evidence.append(beh["description"])
    evidence.append(conf["explanation"])

    return {
        "src_host": f["src_host"],
        "dst_host": f["dst_host"],
        "dst_port": f["dst_port"],
        "service_id": service_id,
        "service_name": display_name,
        "behavior_classification": beh["behavior_classification"],
        "confidence": conf["confidence"],
        "confidence_level": conf["confidence_level"],
        "evidence": evidence,
        "severity": beh["severity"],
        "recommendation": _recommendation(service_id, beh["severity"], display_name),
        "patterns": f["patterns"],
        "request_count": f["request_count"],
        "server_names": snis,
        "classifier_mode": MODE_RULES,
    }


# ── LLM mode ──────────────────────────────────────────────────────────────────

CLASSIFIER_SYSTEM_PROMPT = """You are a network security analyst specializing in AI service identification.

Your task: Classify each network traffic cluster as an AI service and behavior type using the tools provided.

For each cluster:
1. Call `lookup_service_indicators` with the server_name and dst_port.
2. Call `classify_behavior` with the detected patterns and scores.
3. Call `score_confidence` with the results to compute overall confidence.
4. Summarize your findings as JSON.

Output format for each cluster (return a single JSON object):
{
  "service_id": "openai|anthropic|google_ai|huggingface|azure_openai|langsmith|local_llm|crewai|cohere|mistral|unknown",
  "service_name": "Human-readable service name",
  "behavior_classification": "agentic-orchestration|data-retrieval|unknown",
  "confidence": 0.0-1.0,
  "confidence_level": "high|medium|low|insufficient",
  "evidence": ["list of evidence strings"],
  "severity": "low|medium|high|critical",
  "recommendation": "Brief security recommendation"
}

Be precise. Use only the tools to gather evidence, then produce the final JSON."""


def _tool_lookup_service_indicators(hostname: str, dst_port: int) -> str:
    """Look up known AI service indicators for a hostname (SNI) and port.
    Returns a JSON string with the matching service info, or matched_service "unknown".
    """
    return json.dumps(lookup_service_indicators(hostname, dst_port))


def _tool_classify_behavior(patterns: list[str], sawtooth_score: float, loop_score: float) -> str:
    """Classify the behavioral pattern of a traffic cluster into an AI behavior category.
    Returns a JSON string with behavior classification and severity.
    """
    return json.dumps(classify_behavior(patterns, sawtooth_score, loop_score))


def _tool_score_confidence(service_confidence_hint: float, pattern_score: float,
                           request_count: int, has_server_name: bool) -> str:
    """Compute an overall confidence score for a service classification.

    Args:
        service_confidence_hint: Base confidence from hostname matching (0-1).
        pattern_score: Timing pattern score (0-1).
        request_count: Number of requests in the cluster.
        has_server_name: Whether SNI/server_name was available.
    """
    return json.dumps(score_confidence(service_confidence_hint, pattern_score,
                                       request_count, has_server_name))


def build_classifier_agent(model_name: str | None = None, timeout: float = 60.0) -> Any:
    """Build the LangGraph ReAct classifier agent. Imports LangChain lazily."""
    from langchain_anthropic import ChatAnthropic
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    llm = ChatAnthropic(
        model=model_name or DEFAULT_MODEL,
        max_tokens=4096,
        timeout=timeout,
        max_retries=2,
    )
    # Named explicitly: the system prompt tells the model which tool to call by
    # name, so the wrapper function names must not leak through.
    tools = [
        tool("lookup_service_indicators")(_tool_lookup_service_indicators),
        tool("classify_behavior")(_tool_classify_behavior),
        tool("score_confidence")(_tool_score_confidence),
    ]
    return create_react_agent(llm, tools, prompt=CLASSIFIER_SYSTEM_PROMPT)


def _build_cluster_prompt(cluster: dict, server_names: list[str]) -> str:
    f = _cluster_fields(cluster)
    snis = _unique_snis(server_names)
    primary_sni = snis[0] if snis else None
    return f"""Classify this network traffic cluster:

Cluster: {f['src_host']} → {f['dst_host']}:{f['dst_port']}
Server Name (SNI): {primary_sni or 'not available'}
All observed SNI values: {snis}
Detected patterns: {f['patterns']}
Request count: {f['request_count']}
Session duration: {f['session_duration']:.1f}s
Timing entropy: {f['timing_entropy']:.4f} bits
Sawtooth score: {f['sawtooth_score']:.4f}
Loop score: {f['loop_score']:.4f}

Use the tools to classify this cluster, then return the final JSON classification."""


def _extract_json(text: str) -> dict:
    """Extract the first JSON object from a model response."""
    for pattern in (
        r"```json\s*([\s\S]+?)\s*```",
        r"```\s*([\s\S]+?)\s*```",
        r"(\{[\s\S]+\})",
    ):
        m = re.search(pattern, text)
        if m:
            try:
                parsed = json.loads(m.group(1))
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, IndexError):
                continue
    try:
        parsed = json.loads(text.strip())
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _message_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, list):
        # Anthropic content blocks: keep the text parts.
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts)
    return str(content)


def _merge_llm_over_rules(llm: dict, baseline: dict) -> dict:
    """Take the model's answer where it is well-formed, the rules value otherwise."""
    out = dict(baseline)

    service_id = llm.get("service_id")
    if service_id in SERVICE_IDS:
        out["service_id"] = service_id
    service_name = llm.get("service_name")
    if isinstance(service_name, str) and service_name.strip():
        out["service_name"] = service_name.strip()
    behavior = llm.get("behavior_classification")
    if behavior in BEHAVIORS:
        out["behavior_classification"] = behavior
    try:
        conf = float(llm.get("confidence"))
        if 0.0 <= conf <= 1.0:
            out["confidence"] = round(conf, 4)
    except (TypeError, ValueError):
        pass
    level = llm.get("confidence_level")
    if level in CONFIDENCE_LEVELS:
        out["confidence_level"] = level
    severity = llm.get("severity")
    if severity in SEVERITIES:
        out["severity"] = severity
    evidence = llm.get("evidence")
    if isinstance(evidence, list) and evidence:
        out["evidence"] = [str(e) for e in evidence if str(e).strip()]
    recommendation = llm.get("recommendation")
    if isinstance(recommendation, str) and recommendation.strip():
        out["recommendation"] = recommendation.strip()

    out["classifier_mode"] = MODE_LLM
    return out


def classify_cluster_llm(agent: Any, cluster: dict, server_names: list[str],
                         baseline: dict) -> dict:
    """Run the agent on one cluster and merge its answer over the rules baseline.

    Raises if the model returns no JSON object at all; the caller decides how to
    fall back.
    """
    result = agent.invoke({"messages": [{"role": "user",
                                          "content": _build_cluster_prompt(cluster, server_names)}]})
    final = result["messages"][-1]
    parsed = _extract_json(_message_text(final))
    if not parsed:
        raise ValueError("model response contained no JSON object")
    return _merge_llm_over_rules(parsed, baseline)


# ── Public API ────────────────────────────────────────────────────────────────

def resolve_mode(requested: str, api_key_present: bool | None = None) -> str:
    """`auto` means LLM when a key is configured, rules otherwise."""
    if requested not in MODES:
        raise ValueError(f"unknown classifier mode {requested!r}; expected one of {MODES}")
    if requested != MODE_AUTO:
        return requested
    if api_key_present is None:
        api_key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
    return MODE_LLM if api_key_present else MODE_RULES


def classify_all_clusters(
    report: dict,
    mode: str = MODE_AUTO,
    model_name: str | None = None,
    llm_max_clusters: int = 200,
    llm_timeout: float = 60.0,
    agent: Any = None,
) -> tuple[list[dict], str]:
    """Classify every cluster in a Week-1 style report.

    Returns (classifications, effective_mode). Each classification carries
    `classifier_mode`: `rules`, `llm`, or `rules-fallback` (LLM attempted and
    failed for that cluster). Clusters past `llm_max_clusters` are classified by
    rules only, which bounds the spend of a single upload.
    """
    cluster_reports = report.get("cluster_reports", [])
    if not cluster_reports:
        return [], resolve_mode(mode)

    sni_index: dict[tuple, list[str]] = {}
    for ev in report.get("events", []):
        key = (ev.get("src_host"), ev.get("dst_host"), ev.get("dst_port"))
        sni_index.setdefault(key, [])
        if ev.get("server_name"):
            sni_index[key].append(ev["server_name"])

    effective = resolve_mode(mode)
    if effective == MODE_LLM and agent is None:
        agent = build_classifier_agent(model_name, timeout=llm_timeout)

    classifications: list[dict] = []
    llm_used = 0
    for idx, cluster in enumerate(cluster_reports):
        key = (cluster.get("src_host"), cluster.get("dst_host"), cluster.get("dst_port"))
        server_names = sni_index.get(key, [])
        baseline = classify_cluster_rules(cluster, server_names)

        if effective == MODE_LLM and idx < llm_max_clusters:
            try:
                classification = classify_cluster_llm(agent, cluster, server_names, baseline)
                llm_used += 1
            except Exception as exc:  # noqa: BLE001 - any model/transport failure degrades to rules
                log.warning("llm classification failed for %s → %s:%s (%s); using rules",
                            key[0], key[1], key[2], exc)
                classification = dict(baseline, classifier_mode="rules-fallback")
        else:
            classification = baseline

        classifications.append(classification)

    if effective == MODE_LLM and len(cluster_reports) > llm_max_clusters:
        log.info("llm cap: %d of %d clusters sent to the model", llm_used, len(cluster_reports))
    return classifications, effective
