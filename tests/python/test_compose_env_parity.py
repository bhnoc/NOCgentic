"""Tests that docker-compose.agents.yml explicitly passes required environment
variables to containers.

In Docker Compose, `environment:` is an explicit allowlist, not a passthrough of
.env files. If a required environment variable is added to code or .env.s3 but
omitted from docker-compose.agents.yml, it will be silently absent inside the
running container (as caught in fix(compose): pass MANIFOLD_WEBHOOK_TOKEN and
QUARANTINE_TTL_SECONDS to the containers).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _parse_compose_service_envs(compose_path: Path) -> dict[str, set[str]]:
    content = compose_path.read_text("utf-8")
    services: dict[str, set[str]] = {}
    current_service: str | None = None
    in_env = False

    for line in content.splitlines():
        # Match service declaration under services: e.g. "  orchestrator:"
        m_service = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if m_service:
            current_service = m_service.group(1)
            services[current_service] = set()
            in_env = False
            continue

        if current_service:
            # Check if entering environment block
            if re.match(r"^    environment:\s*$", line):
                in_env = True
                continue
            # Check if leaving environment block (any other top-level service key indented 4 spaces)
            if in_env and re.match(r"^    [a-zA-Z0-9_-]+:\s*", line):
                in_env = False
                continue

            if in_env:
                m_var = re.match(r"^\s+-\s+([A-Za-z0-9_]+)(?:=.*)?$", line)
                if m_var:
                    services[current_service].add(m_var.group(1))

    return services


def test_compose_agents_env_parity():
    compose_path = ROOT / "docker-compose.agents.yml"
    envs = _parse_compose_service_envs(compose_path)

    # 1) Orchestrator critical envs
    orch_envs = envs.get("orchestrator", set())
    for req in [
        "OPENROUTER_API_KEY",
        "GEMINI_API_KEY",
        "LLM_PROVIDER",
        "ADMIN_BEARER_TOKEN",
        "QUARANTINE_TTL_SECONDS",
        "ALERT_TRIAGE_URL",
        "THOUSANDEYES_ANALYST_URL",
        "ATHENA_HUNTER_URL",
        # Without DETER_URL the orchestrator falls back to its localhost default,
        # every contained session's deter call fails to connect, and the whole
        # feature degrades to the canned cover — silently, because the fallback
        # is designed to be invisible. Exactly the failure this file exists for.
        "DETER_URL",
        "DETER_ENABLED",
        # Absent, these fall back to the code defaults rather than failing, so a
        # missing pacing window is invisible until someone times the deter path
        # against a real answer and finds it 3s early.
        "DETER_PACE_MIN_SECONDS",
        "DETER_PACE_MAX_SECONDS",
        "OTEL_ENABLED",
        "EVENT_EDITION",
    ]:
        assert req in orch_envs, f"orchestrator service in docker-compose.agents.yml missing {req}"

    # 2) Web server critical envs
    web_envs = envs.get("web-server", set())
    for req in [
        "ORCHESTRATOR_URL",
        "ATHENA_HUNTER_URL",
        "ADMIN_BEARER_TOKEN",
        "MANIFOLD_WEBHOOK_TOKEN",
        "ALLOWED_ORIGIN",
        "EVENT_EDITION",
    ]:
        assert req in web_envs, f"web-server service in docker-compose.agents.yml missing {req}"

    # 3) Thousandeyes analyst critical envs
    te_envs = envs.get("thousandeyes-analyst", set())
    for req in [
        "THOUSANDEYES_BEARER_TOKEN",
        "LLM_PROVIDER",
        "OTEL_ENABLED",
        "EVENT_EDITION",
    ]:
        assert req in te_envs, f"thousandeyes-analyst service in docker-compose.agents.yml missing {req}"

    # 4) Deter agent critical envs. It needs an LLM to write the answer and the
    # Athena config only when the pool reads live; DETER_ATHENA_ENABLED must be
    # present either way, because its absence silently means "static", which is a
    # working-but-different feature rather than a visible failure.
    deter_envs = envs.get("deter", set())
    for req in [
        "GEMINI_API_KEY",
        "LLM_PROVIDER",
        "DETER_ATHENA_ENABLED",
        "ATHENA_DATABASE",
        "ATHENA_REGION",
        "OTEL_ENABLED",
        "EVENT_EDITION",
    ]:
        assert req in deter_envs, f"deter service in docker-compose.agents.yml missing {req}"


def test_deter_agent_is_not_published_to_the_host():
    """Every agent is expose-only; the deter agent especially so. A published
    port would let anyone reach the containment path directly and read back
    exactly which facets the safe pool is built from."""
    content = (ROOT / "docker-compose.agents.yml").read_text("utf-8")
    deter_block = content.split("\n  deter:\n", 1)[1].split("\n  thousandeyes-analyst:", 1)[0]
    assert "expose:" in deter_block
    assert "ports:" not in deter_block
