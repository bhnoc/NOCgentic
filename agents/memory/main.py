"""
Memory Agent — port 8009

Persistent operational-context memory store for NOCgentic. Exposes CRUD +
lifecycle management for agent_memory rows, and a /memory/context endpoint
that returns a sanitized, ranked prompt block for injection into agent prompts.

Port: 8009
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# sys.path bootstrap — mirror triage pattern exactly
# ---------------------------------------------------------------------------
_SHARED = str(Path(__file__).resolve().parents[2] / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)

import store  # noqa: E402
import drift_stats  # noqa: E402
from memory_prompt import build_memory_block  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("memory")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="BHNOCgentic Memory", version="0.1.0")


@app.on_event("startup")
async def _startup() -> None:
    """Initialise the Postgres schema on startup (idempotent; logs if PG absent)."""
    try:
        store.init_schema()
        logger.info("memory: schema initialised")
    except Exception as exc:  # noqa: BLE001
        logger.warning("memory: could not init schema (PG unavailable?): %s", exc)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MemoryIn(BaseModel):
    agent_slug: str
    key: str
    value: object
    category: str = "fact"
    context: str | None = None
    rationale: str | None = None
    confidence_pct: int | None = Field(default=None, ge=0, le=100)


class TransitionIn(BaseModel):
    to_status: str
    actor: str = "api"


class OutcomeIn(BaseModel):
    run_id: str | None = None
    failed: bool


class SweepIn(BaseModel):
    mode: str


# ---------------------------------------------------------------------------
# Promotion helpers
# ---------------------------------------------------------------------------

_PROMOTE_CHAIN: dict[str, str] = {
    "draft": "candidate",
    "candidate": "active",
}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "memory"}


@app.post("/memory")
async def upsert_memory_endpoint(body: MemoryIn) -> dict:
    """Upsert a memory (creates version 1 or version N+1 for same agent_slug+key).

    Returns {id, agent_slug, key, version, memory_status}.
    """
    try:
        result = store.upsert_memory(
            agent_slug=body.agent_slug,
            key=body.key,
            value=body.value,
            category=body.category,
            context=body.context,
            rationale=body.rationale,
            confidence_pct=body.confidence_pct,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return result


@app.get("/memory")
async def list_memories_endpoint(
    agent_slug: str | None = None,
    status: str | None = None,
    category: str | None = None,
) -> dict:
    """List memories with optional filters.

    Returns {count, memories: [...]}.
    """
    memories = store.list_memories(
        agent_slug=agent_slug,
        status=status,
        category=category,
    )
    return {"count": len(memories), "memories": memories}


@app.get("/memory/context")
async def memory_context(agent_slug: str) -> dict:
    """Return active memories for agent_slug as a sanitized prompt block.

    Also bumps usage_count for all returned memories.
    Returns {block: str, count: int}.
    """
    ms = store.active_memories(agent_slug)
    block = build_memory_block(ms)
    store.bump_memory_usage([m["id"] for m in ms])
    return {"block": block, "count": len(ms)}


@app.get("/memory/{memory_id}")
async def get_memory_endpoint(memory_id: str) -> dict:
    """Return a single memory by id, or 404 if not found."""
    mem = store.get_memory(memory_id)
    if mem is None:
        raise HTTPException(status_code=404, detail=f"memory not found: {memory_id}")
    return mem


@app.post("/memory/{memory_id}/promote")
async def promote_memory(memory_id: str) -> dict:
    """Promote a memory one step forward in the draft->candidate->active chain.

    Returns {memory_id, from_status, to_status}.
    409 if already active or retired (no further promotion possible).
    """
    mem = store.get_memory(memory_id)
    if mem is None:
        raise HTTPException(status_code=404, detail=f"memory not found: {memory_id}")

    current = mem["memory_status"]
    next_status = _PROMOTE_CHAIN.get(current)
    if next_status is None:
        raise HTTPException(
            status_code=409,
            detail=f"cannot promote from status '{current}': already at {current}",
        )

    try:
        result = store.transition_memory(memory_id, next_status, actor="api")
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("unknown status"):
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=409, detail=msg)
    return result


@app.post("/memory/{memory_id}/retire")
async def retire_memory(memory_id: str) -> dict:
    """Retire a memory.

    Returns {memory_id, from_status, to_status}.
    """
    mem = store.get_memory(memory_id)
    if mem is None:
        raise HTTPException(status_code=404, detail=f"memory not found: {memory_id}")

    try:
        result = store.transition_memory(memory_id, "retired", actor="api")
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("unknown status"):
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=409, detail=msg)
    return result


@app.post("/memory/{memory_id}/transition")
async def transition_memory_endpoint(memory_id: str, body: TransitionIn) -> dict:
    """Transition a memory to an arbitrary status with guard.

    ValueError on unknown status -> 400.
    ValueError on illegal transition -> 409.
    """
    mem = store.get_memory(memory_id)
    if mem is None:
        raise HTTPException(status_code=404, detail=f"memory not found: {memory_id}")

    try:
        result = store.transition_memory(
            memory_id,
            body.to_status,
            actor=body.actor,
        )
    except ValueError as exc:
        msg = str(exc)
        if msg.startswith("unknown status"):
            raise HTTPException(status_code=400, detail=msg)
        raise HTTPException(status_code=409, detail=msg)
    return result


# ---------------------------------------------------------------------------
# Drift / self-improving memory endpoints
# ---------------------------------------------------------------------------

_VALID_SWEEP_MODES = {"off", "shadow", "live"}


@app.post("/memory/{memory_id}/outcome")
async def record_outcome(memory_id: str, body: OutcomeIn) -> dict:
    """Record a run outcome (pass/fail) for a memory.

    Returns {id, memory_id, run_id, failed}.
    404 if memory not found.
    """
    mem = store.get_memory(memory_id)
    if mem is None:
        raise HTTPException(status_code=404, detail=f"memory not found: {memory_id}")
    outcome_id = store.record_memory_outcome(memory_id, body.run_id, body.failed)
    return {"id": outcome_id, "memory_id": memory_id, "run_id": body.run_id, "failed": body.failed}


@app.get("/memory/proposals")
async def list_proposals(status: str = "open") -> dict:
    """Return memory proposals filtered by status.

    Returns {count, proposals: [...]}.
    """
    proposals = store.list_memory_proposals(status)
    return {"count": len(proposals), "proposals": proposals}


@app.post("/memory/sweep")
async def run_sweep(body: SweepIn) -> dict:
    """Run the drift sweep over all active/candidate memories.

    mode:
      off    — measure only; update drift_score_pct; no state changes.
      shadow — create proposal rows for any actionable memories; no state changes.
      live   — apply retire/promote transitions directly; write memory_events.

    Returns {mode, assessed, actions: [{memory_id, level, action}...]}.
    """
    mode = body.mode
    if mode not in _VALID_SWEEP_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown mode '{mode}'; must be one of {sorted(_VALID_SWEEP_MODES)}",
        )

    memories = store.active_or_candidate_memories()
    actions: list[dict] = []
    proposals: list[dict] = []

    for mem in memories:
        memory_id = mem["id"]
        memory_status = mem["memory_status"]

        # Assess drift
        try:
            drift = store.assess_memory_drift(memory_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sweep: assess_memory_drift failed for %s: %s", memory_id, exc)
            continue

        # Always update drift score
        store.update_drift_score(memory_id, drift["drift_score_pct"])

        # Plan action
        plan = drift_stats.plan_action(memory_status, drift["level"])
        action = plan["action"]

        actions.append({
            "memory_id": memory_id,
            "level": drift["level"],
            "action": action,
        })

        if mode == "off":
            # Measure only — no proposals, no transitions.
            continue

        if mode == "shadow":
            if action is not None:
                proposal_id = store.create_memory_proposal(
                    memory_id,
                    action,
                    drift["reason"],
                    drift["drift_score_pct"],
                )
                proposals.append({
                    "proposal_id": proposal_id,
                    "memory_id": memory_id,
                    "action": action,
                    "reason": drift["reason"],
                })
            continue

        # mode == "live"
        if action == "retire":
            try:
                store.transition_memory(memory_id, "retired", actor="self-improve")
            except (ValueError, KeyError) as exc:
                logger.warning("sweep live: retire failed for %s: %s", memory_id, exc)
        elif action == "promote":
            try:
                store.transition_memory(memory_id, "active", actor="self-improve")
            except (ValueError, KeyError) as exc:
                logger.warning("sweep live: promote failed for %s: %s", memory_id, exc)
        elif action == "adjust_confidence":
            # Nudge confidence based on drift direction; keep minimal — just record.
            cur = mem.get("confidence_pct") or 50
            if drift["level"] in {"alert", "watch"}:
                target = max(0, cur - 10)
            else:
                target = min(100, cur + 10)
            if target != cur:
                import psycopg as _psycopg  # noqa: PLC0415
                pool = store._get_pool()
                with pool.connection() as conn:
                    conn.execute(
                        "UPDATE agent_memory SET confidence_pct = %s, updated_at = now() WHERE id = %s",
                        (target, memory_id),
                    )
                    conn.commit()

    result: dict = {"mode": mode, "assessed": len(memories), "actions": actions}
    if mode == "shadow":
        result["proposals"] = proposals
    return result


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8009, log_level="info")
