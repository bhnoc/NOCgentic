#!/usr/bin/env python3
"""Host-side supervisor for the local llama-server units.

WHY THIS EXISTS AS A SEPARATE PROCESS ON THE HOST
-------------------------------------------------
The settings gear needs to start and stop llama-server so an operator can change
which local model a lane uses. The orchestrator that serves that gear runs in a
container, and every way of letting a container start host processes is worse than
this file: mounting the docker socket, host PID namespace, or an SSH key to the host
all end with "the container that posts conference traffic to an external LLM can run
arbitrary commands as root on the box".

So the capability lives here, on the host, and it is deliberately tiny. It accepts
three verbs, and the only free parameter is a KEY into an allowlist defined in this
file. No paths, no ports, no flags, no command strings cross the boundary. A fully
compromised orchestrator can start and stop models that were already vetted; it
cannot execute anything else.

If you extend this, the rule to hold is: the caller names an intent, this file
decides the command. The moment a caller-supplied string reaches a subprocess
argument, this stops being a supervisor and becomes a remote shell.

TRUST BOUNDARY
--------------
  * Binds loopback + the docker bridge address only. Never 0.0.0.0. There is no path
    from the internet to this port, and nginx has no location for it.
  * Requires MODEL_SUPERVISOR_TOKEN as a bearer, compared with compare_digest. Fails
    CLOSED: no token configured means every request is refused, because an
    unauthenticated process-control endpoint is worse than a broken settings panel.
  * Runs as a user with exactly one sudoers entry: systemctl start/stop/is-active on
    the llama-* units. Not root. See README.md in this directory.

DEPLOYMENT
----------
Not part of docker-compose: it exists precisely because it must NOT be in a
container. Installed as its own systemd unit on the GPU box. See README.md.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import shutil
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("model-supervisor")

TOKEN = os.getenv("MODEL_SUPERVISOR_TOKEN", "")
HOST = os.getenv("MODEL_SUPERVISOR_HOST", "127.0.0.1")
PORT = int(os.getenv("MODEL_SUPERVISOR_PORT", "8790"))

# systemctl is called by absolute path resolved once at import. Not because PATH is
# expected to be hostile, but because a supervisor should not depend on the
# environment of whatever started it.
SYSTEMCTL = shutil.which("systemctl") or "/usr/bin/systemctl"

_CMD_TIMEOUT = 20.0


# ---------------------------------------------------------------------------
# The allowlist. This is the security boundary.
# ---------------------------------------------------------------------------
# key -> the systemd unit that serves it and the port it listens on. Adding an entry
# is a deliberate act performed on the host by someone with shell access, which is
# the point: it is not something the API can do.
#
# The unit files themselves hold the GGUF path, context size and GPU layer count. A
# caller cannot influence any of that, only choose between units that already exist.
MODELS: dict[str, dict[str, Any]] = {
    "aqlight": {
        "unit": "aqlight.service",
        "port": 8080,
        "label": "AQLight",
        "note": "SQL specialist. The durable default: Restart=always.",
    },
    "foundation-sec": {
        "unit": "foundation-sec.service",
        "port": 8081,
        "label": "Foundation-Sec",
        "note": "Better prose and (measured) better SQL. Needs its own port.",
    },
}

# Which unit currently backs which role. Roles are named by job, not by port, because
# that is what the operator is choosing between.
ROLES = ("sqlgen", "prose")

app = FastAPI(title="NOCgentic model supervisor", docs_url=None, redoc_url=None)


def _require_token(authorization: str | None) -> None:
    """Bearer check, failing closed on an unset token."""
    if not TOKEN:
        # Deny rather than allow. An unauthenticated process-control endpoint on the
        # box holding conference traffic is not an acceptable degraded mode.
        raise HTTPException(status_code=503, detail="supervisor has no token configured")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="bearer token required")
    presented = authorization.split(" ", 1)[1].strip()
    if not secrets.compare_digest(presented, TOKEN):
        raise HTTPException(status_code=401, detail="invalid token")


async def _systemctl(*args: str) -> tuple[int, str]:
    """Run systemctl with fixed arguments. Returns (rc, combined output).

    Every argument is a literal from this module or a value looked up out of MODELS.
    Nothing here is ever built from a request body.
    """
    proc = await asyncio.create_subprocess_exec(
        "sudo", "-n", SYSTEMCTL, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=_CMD_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "systemctl timed out"
    return proc.returncode or 0, (out or b"").decode("utf-8", "replace").strip()


async def _unit_active(unit: str) -> bool:
    rc, _ = await _systemctl("is-active", "--quiet", unit)
    return rc == 0


class RoleBody(BaseModel):
    role: str


class StartBody(BaseModel):
    role: str
    model: str


def _check_role(role: str) -> None:
    if role not in ROLES:
        raise HTTPException(status_code=400, detail=f"unknown role {role!r}")


def _lookup(model: str) -> dict[str, Any]:
    """Resolve an allowlist key to its unit. The only place a caller string is used.

    A miss is a 400 with the valid keys, not a 404: the caller asked for something
    that is not offered, and an operator staring at the panel should be told what is.
    """
    entry = MODELS.get(model.strip().lower())
    if entry is None:
        raise HTTPException(
            status_code=400,
            detail=f"model {model!r} is not allowlisted; available: {sorted(MODELS)}",
        )
    return entry


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Unauthenticated, deliberately. Says nothing except that the process is up."""
    return {"status": "ok"}


@app.get("/models")
async def list_models(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """The allowlist and each unit's current state.

    `units` is live systemd state rather than a cached view, so a model somebody
    started by hand on the box shows up here too.
    """
    _require_token(authorization)
    units = {}
    for key, entry in MODELS.items():
        units[key] = {
            "unit": entry["unit"],
            "port": entry["port"],
            "label": entry["label"],
            "note": entry.get("note", ""),
            "active": await _unit_active(entry["unit"]),
        }
    return {"allowlist": sorted(MODELS), "units": units, "roles": list(ROLES)}


@app.post("/start")
async def start(body: StartBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Start the unit that serves `body.model`.

    Does not stop anything else. Two 7B models at useful context do not both fit in
    the T4's 15GB, so the caller decides whether to stop the other one first: an
    implicit stop here would kill a model somebody else's demo was mid-query on.
    """
    _require_token(authorization)
    _check_role(body.role)
    entry = _lookup(body.model)
    if await _unit_active(entry["unit"]):
        return {"ok": True, "unit": entry["unit"], "already_active": True,
                "port": entry["port"]}
    rc, out = await _systemctl("start", entry["unit"])
    if rc != 0:
        logger.error("start %s failed rc=%s: %s", entry["unit"], rc, out)
        raise HTTPException(status_code=502, detail=f"systemctl start failed: {out}")
    logger.warning("started %s for role=%s", entry["unit"], body.role)
    # The unit being started is not the same as the model being loaded: llama-server
    # takes tens of seconds to map a GGUF into VRAM. Say so rather than implying the
    # model is ready, so the UI can poll /models instead of assuming.
    return {"ok": True, "unit": entry["unit"], "port": entry["port"],
            "loading": True,
            "note": "unit started; the model is still mapping into VRAM"}


@app.post("/stop")
async def stop(body: RoleBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """Stop whichever allowlisted unit is currently active.

    Takes a role rather than a model because that is how the caller thinks about it,
    but stops every active unit: with one GPU there is at most one meaningful answer,
    and leaving a stray llama-server holding VRAM is the failure this is for.

    aqlight.service is Restart=always, so systemd brings it straight back. That is
    correct (it is the durable default and the box should not end up with no local
    model at all) but it does mean stopping it is not how you free VRAM for long.
    """
    _require_token(authorization)
    _check_role(body.role)
    stopped = []
    for key, entry in MODELS.items():
        if await _unit_active(entry["unit"]):
            rc, out = await _systemctl("stop", entry["unit"])
            if rc != 0:
                logger.error("stop %s failed rc=%s: %s", entry["unit"], rc, out)
                raise HTTPException(status_code=502, detail=f"systemctl stop failed: {out}")
            stopped.append(key)
            logger.warning("stopped %s for role=%s", entry["unit"], body.role)
    return {"ok": True, "stopped": stopped}


def main() -> None:
    # Config checks BEFORE importing the server, so a refusal is a refusal on any box
    # rather than depending on uvicorn being installed to reach the check.
    if not TOKEN:
        # Refuse to start rather than listen and reject everything: a supervisor that
        # is up but useless looks healthy to the operator and to any monitoring.
        raise SystemExit("MODEL_SUPERVISOR_TOKEN is required")
    if HOST in ("0.0.0.0", "::"):
        raise SystemExit("refusing to bind all interfaces; set MODEL_SUPERVISOR_HOST")

    import uvicorn

    logger.info("model supervisor on %s:%s, allowlist=%s", HOST, PORT, sorted(MODELS))
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
