"""Discovery and control of the local llama-server processes.

Two jobs, and they answer different questions:

  DISCOVERY (`inventory`) asks each configured llama-server what it is serving, via
  the OpenAI-compatible /v1/models. This is deliberately live rather than read from
  the env: the env says what the box was TOLD to serve, and the gap between that and
  what is actually loaded is exactly the thing an operator opens the settings panel
  to find out. A role whose endpoint does not answer shows as unreachable, which is
  more useful than a config echo.

  CONTROL (`start` / `stop`) asks a host-side supervisor to load or unload a model.

WHY CONTROL GOES THROUGH A SUPERVISOR
-------------------------------------
The orchestrator runs in a container. It cannot start a process on the GPU host, and
the ways of letting it (mounting the docker socket, host PID namespace, an SSH key to
the host) all end with "the container that talks to an external LLM can run arbitrary
commands as root on the box holding the conference's traffic". That trade is not
worth a settings modal.

So the host runs a tiny supervisor (ops/model-supervisor/) that owns the systemd
units, and this module speaks to it over the loopback-bound port. The important part
is where the allowlist lives: the supervisor decides which GGUFs exist and what
arguments they get. This module can only name a KEY. A compromised orchestrator can
ask for "foundation-sec"; it cannot ask for a path, a flag, or a command.

That split is the whole security design here. Keep it: any change that lets this
module pass through a path, a port or an argument hands process execution on the GPU
box to whatever can reach /admin.

FAILURE BEHAVIOUR
-----------------
Discovery never raises; an unreachable endpoint is reported as unreachable. Control
DOES raise ModelControlError, because an operator who clicked "start" needs to be
told it did not happen rather than watching a spinner settle back into the old state.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import httpx

import llm_client

logger = logging.getLogger(__name__)

# Where the host supervisor listens. Bound to the host's docker bridge address, not
# published: reachable from the compose network, not from the internet.
SUPERVISOR_URL: str = os.getenv("MODEL_SUPERVISOR_URL", "").rstrip("/")

# Shared secret for the supervisor. Separate from ADMIN_BEARER_TOKEN on purpose: this
# one authorises process control on the host, and it should not be the same string
# that a browser session's admin calls carry around.
SUPERVISOR_TOKEN: str = os.getenv("MODEL_SUPERVISOR_TOKEN", "")

# Discovery has to be quick. The settings panel opens on it, and a hung llama-server
# must not hold the panel: report unreachable and move on.
_DISCOVER_TIMEOUT = 2.0

# Loading a 7B GGUF off disk into VRAM is tens of seconds. The supervisor returns as
# soon as the unit is started, so this covers the handshake, not the load.
_CONTROL_TIMEOUT = 15.0

ROLES = ("sqlgen", "prose")


class ModelControlError(RuntimeError):
    """A start/stop request could not be carried out. Carries an HTTP status."""

    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def _role_endpoints() -> dict[str, str]:
    """Base URL per role, read at call time so a mode change is reflected."""
    return {
        "sqlgen": llm_client.LOCAL_SQL_BASE_URL,
        "prose": llm_client.LOCAL_PROSE_BASE_URL,
    }


async def _probe(base_url: str) -> dict[str, Any]:
    """Ask one llama-server what it is serving. Never raises."""
    if not base_url:
        return {"reachable": False, "error": "no endpoint configured", "models": []}
    url = f"{base_url.rstrip('/')}/models"
    try:
        async with httpx.AsyncClient(timeout=_DISCOVER_TIMEOUT) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            body = resp.json()
    except Exception as exc:
        # Expected often enough to be debug rather than warning: on the CPU box there
        # is no llama-server at all, and this is the code path that discovers that.
        logger.debug("model discovery failed for %s: %s", url, exc)
        return {"reachable": False, "error": f"{type(exc).__name__}: {exc}", "models": []}
    served = [
        m.get("id") for m in (body.get("data") or [])
        if isinstance(m, dict) and m.get("id")
    ]
    return {"reachable": True, "models": served}


async def inventory() -> dict[str, Any]:
    """What each role's endpoint is serving, plus what the supervisor could start.

    Probes the roles concurrently, because on a box where one llama-server is down
    the timeouts would otherwise add up in front of the operator.

    Two endpoints pointing at the same URL (the default, AQLight for both roles) are
    probed once each rather than deduplicated. It is one cheap local request and it
    keeps the per-role reporting honest if somebody splits the roles mid-session.
    """
    endpoints = _role_endpoints()
    probes = await asyncio.gather(*(_probe(endpoints[r]) for r in ROLES))

    roles: dict[str, Any] = {}
    for role, probe in zip(ROLES, probes):
        configured = (llm_client.LOCAL_SQL_MODEL if role == "sqlgen"
                      else llm_client.LOCAL_PROSE_MODEL)
        roles[role] = {
            "base_url": endpoints[role],
            # What the env/config asks for, versus what the server actually has
            # loaded. When these disagree the lane is calling a model that is not
            # there, which is a real and otherwise silent misconfiguration.
            "configured_model": configured,
            "serving": probe["models"],
            "reachable": probe["reachable"],
            "healthy": probe["reachable"] and configured in probe["models"],
            "error": probe.get("error"),
        }

    return {
        "roles": roles,
        "cloud_model": llm_client.GEMINI_MODEL,
        "supervisor": await _supervisor_state(),
    }


async def _supervisor_state() -> dict[str, Any]:
    """The supervisor's allowlist and unit status, or why we cannot see it.

    Never raises: a box with no supervisor is the normal case (the CPU box, any dev
    machine), and the panel should render read-only there rather than error.
    """
    if not SUPERVISOR_URL:
        return {"available": False, "reason": "MODEL_SUPERVISOR_URL not set",
                "allowlist": [], "units": {}}
    try:
        async with httpx.AsyncClient(timeout=_DISCOVER_TIMEOUT) as client:
            resp = await client.get(f"{SUPERVISOR_URL}/models", headers=_headers())
            resp.raise_for_status()
            body = resp.json()
    except Exception as exc:
        logger.debug("model supervisor unreachable: %s", exc)
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}",
                "allowlist": [], "units": {}}
    return {
        "available": True,
        "allowlist": body.get("allowlist", []),
        "units": body.get("units", {}),
    }


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SUPERVISOR_TOKEN}"} if SUPERVISOR_TOKEN else {}


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise ModelControlError(f"unknown role {role!r}; expected one of {ROLES}", status=400)


async def _control(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST to the supervisor and surface its refusal verbatim.

    The supervisor's 400 (not on the allowlist) is passed through as a 400 rather than
    collapsed into 502, so the operator reads "that model is not allowlisted" instead
    of a generic failure they would try again.
    """
    if not SUPERVISOR_URL:
        raise ModelControlError(
            "model control is not available on this box (MODEL_SUPERVISOR_URL unset)",
            status=501,
        )
    try:
        async with httpx.AsyncClient(timeout=_CONTROL_TIMEOUT) as client:
            resp = await client.post(f"{SUPERVISOR_URL}{path}", json=payload,
                                     headers=_headers())
    except Exception as exc:
        raise ModelControlError(f"model supervisor unreachable: {exc}") from exc
    if resp.status_code >= 400:
        detail = ""
        try:
            detail = str(resp.json().get("detail") or resp.text)
        except Exception:
            detail = resp.text
        raise ModelControlError(
            detail or f"supervisor returned {resp.status_code}",
            status=resp.status_code if resp.status_code < 500 else 502,
        )
    return resp.json()


async def start(role: str, model: str) -> dict[str, Any]:
    """Serve `model` for `role`. `model` is an allowlist key, never a path."""
    _check_role(role)
    if not model or "/" in model or "\\" in model:
        # Belt and braces. The supervisor enforces the allowlist and is the real
        # boundary, but a key containing a separator is never legitimate and should
        # not travel to the host at all.
        raise ModelControlError(f"invalid model key {model!r}", status=400)
    result = await _control("/start", {"role": role, "model": model})
    logger.warning("ADMIN model start: role=%s model=%s -> %s", role, model, result)
    return result


async def stop(role: str) -> dict[str, Any]:
    """Stop the llama-server serving `role`.

    Worth doing rather than just switching: the T4 has 15GB and two 7B models at
    useful context do not both fit, so serving a different model means unloading the
    current one first.
    """
    _check_role(role)
    result = await _control("/stop", {"role": role})
    logger.warning("ADMIN model stop: role=%s -> %s", role, result)
    return result
