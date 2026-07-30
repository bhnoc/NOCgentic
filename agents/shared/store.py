"""
store.py — Postgres/pgvector persistence layer for NOCgentic recall + agentic trace.

Tables (defined in agents/shared/migrations/0000_recall.sql):
    log_templates   — drain-clustered event templates with 768-dim embeddings
    incidents       — resolved incidents with embeddings for recall
    deploy_markers  — code-push / config-change events for correlation
    agent_runs      — one row per agentic investigation run
    agent_events    — append-only reasoning trace (event sourced)

Environment:
    PG_DSN  — e.g. postgresql://nocgentic:pw@postgres:5432/nocgentic

Postgres creds are STATIC (unlike Athena/IMDS), so a module-level connection pool
is correct here. The pool is created lazily on first use.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import psycopg
import psycopg_pool
from psycopg.types.json import Jsonb
from pgvector.psycopg import register_vector

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Migration file path resolution.
# The repo layout (agents/shared + agents/root-cause) and the container layout
# (/app/shared + /app/agents/root-cause, per the Dockerfile COPY) put the
# migration in different places relative to this file. Resolve robustly: an
# explicit RECALL_MIGRATION_PATH env wins, else try the known candidates.
# ---------------------------------------------------------------------------
def _resolve_migration_path() -> Path:
    override = os.environ.get("RECALL_MIGRATION_PATH")
    if override:
        return Path(override)
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "migrations" / "0000_recall.sql",                    # canonical: beside store.py (shipped with agents/shared/)
        here.parents[1] / "root-cause" / "migrations" / "0000_recall.sql", # legacy repo layout (pre-move)
        Path("/app/shared/migrations/0000_recall.sql"),                    # container absolute fallback
    ]
    for c in candidates:
        if c.exists():
            return c
    # Nothing found — return the first candidate so the error names a sensible path.
    return candidates[0]


_MIGRATION_PATH: Path = _resolve_migration_path()

# ---------------------------------------------------------------------------
# Connection pool (module-level, lazy)
# ---------------------------------------------------------------------------

_pool: psycopg_pool.ConnectionPool | None = None


def _configure_conn(conn: psycopg.Connection) -> None:
    """Called by the pool for each new connection — ensure vector extension and register type."""
    # Ensure the extension exists on this database before registering the type.
    # This is idempotent and handles the bootstrap case where init_schema() has
    # not yet been called (e.g. fresh database, first pool connection).
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    conn.commit()
    register_vector(conn)


def _get_pool() -> psycopg_pool.ConnectionPool:
    """Return (creating if necessary) the module-level connection pool."""
    global _pool  # noqa: PLW0603
    if _pool is None:
        dsn = os.environ.get("PG_DSN", "postgresql://nocgentic:nocgentic@localhost:5432/nocgentic")
        _pool = psycopg_pool.ConnectionPool(
            conninfo=dsn,
            min_size=1,
            max_size=10,
            configure=_configure_conn,
            open=True,
        )
        logger.info("store: connection pool created")
    return _pool


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_schema() -> None:
    """Idempotent schema initialisation.

    Reads agents/shared/migrations/0000_recall.sql and executes it.
    Safe to call multiple times (all DDL is IF NOT EXISTS).
    """
    sql = _MIGRATION_PATH.read_text()
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(sql)
        conn.commit()
    logger.info("store: schema initialised from %s", _MIGRATION_PATH)


# ---------------------------------------------------------------------------
# log_templates
# ---------------------------------------------------------------------------

def upsert_template(
    template: str,
    sample: str,
    mask_keys: dict,
    source: str,
    embedding: list[float],
) -> str:
    """Insert or increment a log template.

    id = sha1(template)[:16] — stable across restarts.
    ON CONFLICT increments count and refreshes last_seen + embedding.
    Returns the template id.
    """
    template_id = hashlib.sha1(template.encode()).hexdigest()[:16]
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO log_templates (id, template, sample, mask_keys, source, embedding)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (template) DO UPDATE SET
                count     = log_templates.count + 1,
                last_seen = now(),
                embedding = EXCLUDED.embedding
            RETURNING id
            """,
            (template_id, template, sample, Jsonb(mask_keys), source, embedding),
        ).fetchone()
        conn.commit()
    assert row is not None
    return row[0]


def similar_templates(embedding: list[float], k: int = 5) -> list[dict]:
    """Return up to k nearest templates ordered by cosine distance (ascending).

    Each dict: {id, template, distance, count, source, last_seen}
    """
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, template, embedding <=> %s::vector AS distance, count, source, last_seen
            FROM log_templates
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> %s::vector
            LIMIT %s
            """,
            (embedding, embedding, k),
        ).fetchall()
    return [
        {
            "id": r[0],
            "template": r[1],
            "distance": float(r[2]),
            "count": r[3],
            "source": r[4],
            "last_seen": r[5],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# incidents
# ---------------------------------------------------------------------------

def record_incident(
    title: str,
    summary: str,
    root_cause: str,
    resolution: str,
    embedding: list[float],
    template_id: str | None = None,
    deploy_marker: str | None = None,
    commit_sha: str | None = None,
) -> str:
    """Insert a resolved incident. Returns the new incident id (uuid4 hex)."""
    incident_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO incidents
                (id, title, summary, root_cause, resolution, embedding,
                 template_id, deploy_marker, commit_sha)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                incident_id, title, summary, root_cause, resolution, embedding,
                template_id, deploy_marker, commit_sha,
            ),
        )
        conn.commit()
    return incident_id


def similar_incidents(embedding: list[float], k: int = 5) -> list[dict]:
    """Return up to k nearest incidents ordered by cosine distance (ascending).

    Each dict: {id, title, summary, root_cause, distance, commit_sha, deploy_marker}
    """
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, title, summary, root_cause,
                   embedding <=> %s::vector AS distance,
                   commit_sha, deploy_marker
            FROM incidents
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> %s::vector
            LIMIT %s
            """,
            (embedding, embedding, k),
        ).fetchall()
    return [
        {
            "id": r[0],
            "title": r[1],
            "summary": r[2],
            "root_cause": r[3],
            "distance": float(r[4]),
            "commit_sha": r[5],
            "deploy_marker": r[6],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# deploy_markers
# ---------------------------------------------------------------------------

def add_deploy_marker(
    ts: datetime,
    kind: str,
    ref: str,
    commit_sha: str | None = None,
    note: str | None = None,
) -> str:
    """Insert a deploy marker. Returns the new id (uuid4 hex)."""
    marker_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO deploy_markers (id, ts, kind, ref, commit_sha, note)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (marker_id, ts, kind, ref, commit_sha, note),
        )
        conn.commit()
    return marker_id


def markers_near(ts_start: datetime, ts_end: datetime) -> list[dict]:
    """Return deploy markers with ts BETWEEN ts_start AND ts_end, ordered by ts."""
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, ts, kind, ref, commit_sha, note
            FROM deploy_markers
            WHERE ts BETWEEN %s AND %s
            ORDER BY ts
            """,
            (ts_start, ts_end),
        ).fetchall()
    return [
        {
            "id": r[0],
            "ts": r[1],
            "kind": r[2],
            "ref": r[3],
            "commit_sha": r[4],
            "note": r[5],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# agent_runs + agent_events
# ---------------------------------------------------------------------------

def start_run(kind: str, input: Any) -> str:  # noqa: A002  (shadows builtin intentionally)
    """Create a new agent run record. Returns the run id (uuid4 hex)."""
    run_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO agent_runs (id, kind, input, status)
            VALUES (%s, %s, %s, 'running')
            """,
            (run_id, kind, Jsonb(input)),
        )
        conn.commit()
    return run_id


def emit(run_id: str, event_type: str, data: Any) -> None:
    """Append an event to the agent_events trace.

    seq is auto-computed as max(seq)+1 for this run, so events are ordered
    by insertion within a run regardless of wall-clock time.
    """
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO agent_events (run_id, seq, event_type, data)
            VALUES (
                %s,
                (SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_events WHERE run_id = %s),
                %s,
                %s
            )
            """,
            (run_id, run_id, event_type, Jsonb(data)),
        )
        conn.commit()


def finish_run(run_id: str, status: str, output: Any) -> None:
    """Mark a run as finished with a final status and output."""
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            UPDATE agent_runs
            SET status      = %s,
                output      = %s,
                finished_at = now()
            WHERE id = %s
            """,
            (status, Jsonb(output), run_id),
        )
        conn.commit()


def get_run(run_id: str) -> dict:
    """Return the full run record plus all events ordered by seq.

    Returns: {"run": {...}, "events": [...]}
    """
    pool = _get_pool()
    with pool.connection() as conn:
        run_row = conn.execute(
            """
            SELECT id, kind, input, output, status, started_at, finished_at, token_usage
            FROM agent_runs
            WHERE id = %s
            """,
            (run_id,),
        ).fetchone()

        if run_row is None:
            raise KeyError(f"run not found: {run_id}")

        event_rows = conn.execute(
            """
            SELECT id, run_id, seq, ts, event_type, data
            FROM agent_events
            WHERE run_id = %s
            ORDER BY seq
            """,
            (run_id,),
        ).fetchall()

    run = {
        "id": run_row[0],
        "kind": run_row[1],
        "input": run_row[2],
        "output": run_row[3],
        "status": run_row[4],
        "started_at": run_row[5],
        "finished_at": run_row[6],
        "token_usage": run_row[7],
    }
    events = [
        {
            "id": r[0],
            "run_id": r[1],
            "seq": r[2],
            "ts": r[3],
            "event_type": r[4],
            "data": r[5],
        }
        for r in event_rows
    ]
    return {"run": run, "events": events}
