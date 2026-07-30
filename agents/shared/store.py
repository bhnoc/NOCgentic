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

    Runs every agents/shared/migrations/*.sql in sorted (lexical) order, so
    numbered migrations (0000_recall.sql, 0001_triage.sql, ...) apply in sequence.
    Safe to call multiple times (all DDL is IF NOT EXISTS / additive).
    """
    migrations_dir = _MIGRATION_PATH.parent
    files = sorted(migrations_dir.glob("*.sql"))
    if not files:
        # Fall back to the single resolved path so the error names a sensible file.
        files = [_MIGRATION_PATH]
    pool = _get_pool()
    with pool.connection() as conn:
        for f in files:
            conn.execute(f.read_text())
        conn.commit()
    logger.info("store: schema initialised from %s (%d migration(s))",
                migrations_dir, len(files))


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


# ---------------------------------------------------------------------------
# Triage: alert bucket state machine
# ---------------------------------------------------------------------------

BUCKETS: set[str] = {
    "alerts",
    "validating",
    "validated_true_positive",
    "validated_false_positive",
    "validated_bad_hygiene",
    "tuning_queue",
    "dismissed",
}

LEGAL_EDGES: dict[str, set[str]] = {
    "alerts": {"validating", "dismissed"},
    "validating": {"validated_true_positive", "validated_false_positive", "validated_bad_hygiene", "alerts"},
    "validated_false_positive": {"tuning_queue", "dismissed"},
    "validated_true_positive": {"dismissed"},
    "validated_bad_hygiene": {"dismissed", "tuning_queue"},
    "tuning_queue": {"dismissed"},
    "dismissed": set(),
}


def upsert_alert(
    dedup_key: str,
    severity: int,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    alert_type: str | None = None,
    signature: str | None = None,
    raw_data: Any = None,
    connector_source: str | None = None,
) -> str:
    """Insert or increment an alert by dedup_key.

    ON CONFLICT increments count, keeps highest severity, refreshes last_seen.
    Returns the alert id (uuid4 hex).
    """
    alert_id = uuid4().hex
    pool = _get_pool()
    raw_jsonb = Jsonb(raw_data) if raw_data is not None else None
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO alerts
                (id, dedup_key, severity, source_ip, dest_ip, alert_type,
                 signature, raw_data, connector_source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (dedup_key) DO UPDATE SET
                count      = alerts.count + 1,
                last_seen  = now(),
                severity   = GREATEST(alerts.severity, EXCLUDED.severity),
                updated_at = now()
            RETURNING id
            """,
            (
                alert_id, dedup_key, severity, source_ip, dest_ip,
                alert_type, signature, raw_jsonb, connector_source,
            ),
        ).fetchone()
        conn.commit()
    assert row is not None
    return row[0]


def get_alert(alert_id: str) -> dict | None:
    """Return all columns for an alert, or None if not found."""
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            SELECT id, dedup_key, bucket, severity, source_ip, dest_ip,
                   alert_type, signature, count, raw_data, first_seen,
                   last_seen, connector_source, created_at, updated_at
            FROM alerts
            WHERE id = %s
            """,
            (alert_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "dedup_key": row[1],
        "bucket": row[2],
        "severity": row[3],
        "source_ip": row[4],
        "dest_ip": row[5],
        "alert_type": row[6],
        "signature": row[7],
        "count": row[8],
        "raw_data": row[9],
        "first_seen": row[10],
        "last_seen": row[11],
        "connector_source": row[12],
        "created_at": row[13],
        "updated_at": row[14],
    }


def list_alerts(bucket: str | None = None, severity_min: int | None = None) -> list[dict]:
    """Return alerts, optionally filtered by bucket and/or minimum severity.

    Ordered by severity DESC, last_seen DESC.
    """
    pool = _get_pool()
    conditions: list[str] = []
    params: list[Any] = []

    if bucket is not None:
        conditions.append("bucket = %s")
        params.append(bucket)
    if severity_min is not None:
        conditions.append("severity >= %s")
        params.append(severity_min)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with pool.connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id, dedup_key, bucket, severity, source_ip, dest_ip,
                   alert_type, signature, count, raw_data, first_seen,
                   last_seen, connector_source, created_at, updated_at
            FROM alerts
            {where_clause}
            ORDER BY severity DESC, last_seen DESC
            """,
            params,
        ).fetchall()
    return [
        {
            "id": r[0],
            "dedup_key": r[1],
            "bucket": r[2],
            "severity": r[3],
            "source_ip": r[4],
            "dest_ip": r[5],
            "alert_type": r[6],
            "signature": r[7],
            "count": r[8],
            "raw_data": r[9],
            "first_seen": r[10],
            "last_seen": r[11],
            "connector_source": r[12],
            "created_at": r[13],
            "updated_at": r[14],
        }
        for r in rows
    ]


def transition_alert(
    alert_id: str,
    to_bucket: str,
    reason: str | None = None,
    investigation_run_id: str | None = None,
    force: bool = False,
) -> dict:
    """Move an alert to a new bucket, writing an audit row in bucket_transitions.

    Validates the edge against LEGAL_EDGES unless force=True.
    Raises ValueError for unknown bucket or illegal edge (without force).
    Returns {alert_id, from_bucket, to_bucket, forced}.
    """
    if to_bucket not in BUCKETS:
        raise ValueError(f"unknown bucket: {to_bucket}")

    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT bucket FROM alerts WHERE id = %s",
            (alert_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"alert not found: {alert_id}")

        from_bucket = row[0]

        if not force and to_bucket not in LEGAL_EDGES.get(from_bucket, set()):
            raise ValueError(f"illegal transition {from_bucket}->{to_bucket}")

        transition_id = uuid4().hex
        conn.execute(
            """
            INSERT INTO bucket_transitions
                (id, alert_id, from_bucket, to_bucket, reason, investigation_run_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (transition_id, alert_id, from_bucket, to_bucket, reason, investigation_run_id),
        )
        conn.execute(
            """
            UPDATE alerts
            SET bucket = %s, updated_at = now()
            WHERE id = %s
            """,
            (to_bucket, alert_id),
        )
        conn.commit()

    return {
        "alert_id": alert_id,
        "from_bucket": from_bucket,
        "to_bucket": to_bucket,
        "forced": force,
    }


def alert_transitions(alert_id: str) -> list[dict]:
    """Return all bucket_transitions for an alert, ordered by transitioned_at."""
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, alert_id, from_bucket, to_bucket, reason,
                   investigation_run_id, transitioned_at
            FROM bucket_transitions
            WHERE alert_id = %s
            ORDER BY transitioned_at
            """,
            (alert_id,),
        ).fetchall()
    return [
        {
            "id": r[0],
            "alert_id": r[1],
            "from_bucket": r[2],
            "to_bucket": r[3],
            "reason": r[4],
            "investigation_run_id": r[5],
            "transitioned_at": r[6],
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Memory: operational-context memory store
# ---------------------------------------------------------------------------

MEMORY_STATUSES: set[str] = {"draft", "candidate", "active", "retired"}

MEMORY_CATEGORIES: set[str] = {"fact", "prompt_refinement", "preference", "lesson_learned"}

MEMORY_LIFECYCLE: dict[str, set[str]] = {
    "draft":     {"candidate", "retired"},
    "candidate": {"active", "retired", "draft"},
    "active":    {"retired", "candidate"},
    "retired":   set(),
}


def upsert_memory(
    agent_slug: str,
    key: str,
    value: Any,
    category: str = "fact",
    context: str | None = None,
    rationale: str | None = None,
    confidence_pct: int | None = None,
    run_id: str | None = None,
) -> dict:
    """Insert a new memory or create a new version for an existing (agent_slug, key).

    If (agent_slug, key) already exists, inserts a new row with version = max(version)+1
    and status 'draft'. Otherwise inserts version 1.

    Raises ValueError if category is not in MEMORY_CATEGORIES.
    Returns {id, agent_slug, key, version, memory_status}.
    """
    if category not in MEMORY_CATEGORIES:
        raise ValueError(f"unknown category: {category}")

    memory_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO agent_memory
                (id, agent_slug, key, value, context, category, memory_status,
                 version, rationale, confidence_pct, run_id)
            VALUES (
                %s, %s, %s, %s, %s, %s, 'draft',
                COALESCE(
                    (SELECT MAX(version) + 1 FROM agent_memory
                     WHERE agent_slug = %s AND key = %s),
                    1
                ),
                %s, %s, %s
            )
            RETURNING id, agent_slug, key, version, memory_status
            """,
            (
                memory_id, agent_slug, key, Jsonb(value), context, category,
                agent_slug, key,
                rationale, confidence_pct, run_id,
            ),
        ).fetchone()
        conn.commit()
    assert row is not None
    return {
        "id": row[0],
        "agent_slug": row[1],
        "key": row[2],
        "version": row[3],
        "memory_status": row[4],
    }


def get_memory(memory_id: str) -> dict | None:
    """Return all columns for a memory row, or None if not found."""
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            SELECT id, agent_slug, key, value, context, category, memory_status,
                   version, rationale, confidence_pct, run_id, usage_count,
                   drift_score_pct, promoted_at, retired_at, created_at, updated_at
            FROM agent_memory
            WHERE id = %s
            """,
            (memory_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0],
        "agent_slug": row[1],
        "key": row[2],
        "value": row[3],
        "context": row[4],
        "category": row[5],
        "memory_status": row[6],
        "version": row[7],
        "rationale": row[8],
        "confidence_pct": row[9],
        "run_id": row[10],
        "usage_count": row[11],
        "drift_score_pct": row[12],
        "promoted_at": row[13],
        "retired_at": row[14],
        "created_at": row[15],
        "updated_at": row[16],
    }


def list_memories(
    agent_slug: str | None = None,
    status: str | None = None,
    category: str | None = None,
) -> list[dict]:
    """Return memories, optionally filtered by agent_slug, status, and/or category.

    Ordered by confidence_pct DESC NULLS LAST, usage_count DESC, updated_at DESC.
    """
    pool = _get_pool()
    conditions: list[str] = []
    params: list[Any] = []

    if agent_slug is not None:
        conditions.append("agent_slug = %s")
        params.append(agent_slug)
    if status is not None:
        conditions.append("memory_status = %s")
        params.append(status)
    if category is not None:
        conditions.append("category = %s")
        params.append(category)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with pool.connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id, agent_slug, key, value, context, category, memory_status,
                   version, rationale, confidence_pct, run_id, usage_count,
                   drift_score_pct, promoted_at, retired_at, created_at, updated_at
            FROM agent_memory
            {where_clause}
            ORDER BY confidence_pct DESC NULLS LAST, usage_count DESC, updated_at DESC
            """,
            params,
        ).fetchall()
    return [
        {
            "id": r[0],
            "agent_slug": r[1],
            "key": r[2],
            "value": r[3],
            "context": r[4],
            "category": r[5],
            "memory_status": r[6],
            "version": r[7],
            "rationale": r[8],
            "confidence_pct": r[9],
            "run_id": r[10],
            "usage_count": r[11],
            "drift_score_pct": r[12],
            "promoted_at": r[13],
            "retired_at": r[14],
            "created_at": r[15],
            "updated_at": r[16],
        }
        for r in rows
    ]


def transition_memory(
    memory_id: str,
    to_status: str,
    actor: str = "api",
) -> dict:
    """Move a memory to a new status, writing an audit row in memory_events.

    Validates the edge against MEMORY_LIFECYCLE.
    Raises ValueError for unknown status or illegal edge.
    Returns {memory_id, from_status, to_status}.
    """
    if to_status not in MEMORY_STATUSES:
        raise ValueError(f"unknown status: {to_status}")

    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT memory_status FROM agent_memory WHERE id = %s",
            (memory_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"memory not found: {memory_id}")

        from_status = row[0]

        if to_status not in MEMORY_LIFECYCLE.get(from_status, set()):
            raise ValueError(f"illegal memory transition {from_status}->{to_status}")

        event_id = uuid4().hex

        # Timestamps for terminal/promoted states
        extra_sets = ["memory_status = %s", "updated_at = now()"]
        extra_params: list[Any] = [to_status]
        if to_status == "active":
            extra_sets.append("promoted_at = now()")
        elif to_status == "retired":
            extra_sets.append("retired_at = now()")

        conn.execute(
            f"UPDATE agent_memory SET {', '.join(extra_sets)} WHERE id = %s",
            extra_params + [memory_id],
        )
        conn.execute(
            """
            INSERT INTO memory_events (id, memory_id, from_status, to_status, actor)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (event_id, memory_id, from_status, to_status, actor),
        )
        conn.commit()

    return {
        "memory_id": memory_id,
        "from_status": from_status,
        "to_status": to_status,
    }


def active_memories(agent_slug: str, limit: int = 40) -> list[dict]:
    """Return active memories for an agent, ranked by confidence, usage, recency.

    Returns rows with at least {id, key, value, context, category, confidence_pct, usage_count}.
    """
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, key, value, context, category, confidence_pct, usage_count,
                   agent_slug, memory_status, version, rationale, run_id,
                   drift_score_pct, promoted_at, retired_at, created_at, updated_at
            FROM agent_memory
            WHERE agent_slug = %s AND memory_status = 'active'
            ORDER BY confidence_pct DESC NULLS LAST, usage_count DESC, updated_at DESC
            LIMIT %s
            """,
            (agent_slug, limit),
        ).fetchall()
    return [
        {
            "id": r[0],
            "key": r[1],
            "value": r[2],
            "context": r[3],
            "category": r[4],
            "confidence_pct": r[5],
            "usage_count": r[6],
            "agent_slug": r[7],
            "memory_status": r[8],
            "version": r[9],
            "rationale": r[10],
            "run_id": r[11],
            "drift_score_pct": r[12],
            "promoted_at": r[13],
            "retired_at": r[14],
            "created_at": r[15],
            "updated_at": r[16],
        }
        for r in rows
    ]


def bump_memory_usage(ids: list[str]) -> None:
    """Increment usage_count for a list of memory ids. No-op on empty list."""
    if not ids:
        return
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            "UPDATE agent_memory SET usage_count = usage_count + 1 WHERE id = ANY(%s)",
            (ids,),
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Hunter: threat-hunt registry + scheduler state
# ---------------------------------------------------------------------------

def register_hunts(templates: list[dict]) -> None:
    """Idempotent upsert of hunt templates by stable id.

    On conflict, updates name/mitre_*/hypothesis/hunt_query/interval_hours
    from the template but preserves the operator-controlled enabled flag and
    last_run_at so scheduled state and toggles are not clobbered.
    """
    pool = _get_pool()
    with pool.connection() as conn:
        for t in templates:
            conn.execute(
                """
                INSERT INTO hunts
                    (id, name, mitre_tactic, mitre_technique, hypothesis,
                     hunt_query, enabled, interval_hours)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name            = EXCLUDED.name,
                    mitre_tactic    = EXCLUDED.mitre_tactic,
                    mitre_technique = EXCLUDED.mitre_technique,
                    hypothesis      = EXCLUDED.hypothesis,
                    hunt_query      = EXCLUDED.hunt_query,
                    interval_hours  = EXCLUDED.interval_hours
                    -- enabled and last_run_at intentionally not updated on conflict
                """,
                (
                    t["id"],
                    t["name"],
                    t["mitre_tactic"],
                    t["mitre_technique"],
                    t.get("hypothesis"),
                    t["hunt_query"],
                    t.get("enabled", True),
                    t.get("interval_hours", 24),
                ),
            )
        conn.commit()
    logger.info("store: registered %d hunt template(s)", len(templates))


def list_hunts() -> list[dict]:
    """Return all hunt rows ordered by id."""
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, name, mitre_tactic, mitre_technique, hypothesis,
                   hunt_query, enabled, interval_hours, last_run_at, created_at
            FROM hunts
            ORDER BY id
            """,
        ).fetchall()
    return [_hunt_row(r) for r in rows]


def get_hunt(hunt_id: str) -> dict | None:
    """Return a single hunt row, or None if not found."""
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            SELECT id, name, mitre_tactic, mitre_technique, hypothesis,
                   hunt_query, enabled, interval_hours, last_run_at, created_at
            FROM hunts
            WHERE id = %s
            """,
            (hunt_id,),
        ).fetchone()
    return _hunt_row(row) if row is not None else None


def set_hunt_enabled(hunt_id: str, enabled: bool) -> dict | None:
    """Toggle the enabled flag for a hunt. Returns updated row or None if not found."""
    pool = _get_pool()
    with pool.connection() as conn:
        row = conn.execute(
            """
            UPDATE hunts
            SET enabled = %s
            WHERE id = %s
            RETURNING id, name, mitre_tactic, mitre_technique, hypothesis,
                      hunt_query, enabled, interval_hours, last_run_at, created_at
            """,
            (enabled, hunt_id),
        ).fetchone()
        conn.commit()
    return _hunt_row(row) if row is not None else None


def mark_hunt_ran(hunt_id: str, ts: datetime) -> None:
    """Set last_run_at to the supplied ts (caller-injected, not DB now())."""
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            "UPDATE hunts SET last_run_at = %s WHERE id = %s",
            (ts, hunt_id),
        )
        conn.commit()


def due_hunts(now: datetime) -> list[dict]:
    """Return enabled hunts that are due to run.

    A hunt is due if:
      - enabled is True, AND
      - last_run_at IS NULL  (never run), OR
      - last_run_at + interval_hours <= now

    Pure function over the stored hunt rows — no wall-clock calls inside.
    `now` is injected by the caller so tests can pass a fixed datetime.
    """
    from datetime import timedelta

    all_hunts = list_hunts()
    result: list[dict] = []
    for hunt in all_hunts:
        if not hunt["enabled"]:
            continue
        last = hunt["last_run_at"]
        if last is None:
            result.append(hunt)
        else:
            # Ensure both sides are offset-aware for comparison
            last_aware: datetime = last
            if last_aware.tzinfo is None:
                last_aware = last_aware.replace(tzinfo=timezone.utc)
            now_aware: datetime = now
            if now_aware.tzinfo is None:
                now_aware = now_aware.replace(tzinfo=timezone.utc)
            deadline = last_aware + timedelta(hours=hunt["interval_hours"])
            if now_aware >= deadline:
                result.append(hunt)
    return result


def record_hunt_run(
    hunt_id: str,
    investigation_run_id: str | None,
    verdict: str | None,
    severity: str | None,
    mitre_technique: str | None,
    summary: str | None,
) -> str:
    """Insert a hunt_run row and return its id (uuid4 hex)."""
    run_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO hunt_runs
                (id, hunt_id, investigation_run_id, verdict, severity,
                 mitre_technique, summary)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (run_id, hunt_id, investigation_run_id, verdict, severity,
             mitre_technique, summary),
        )
        conn.commit()
    return run_id


def list_hunt_runs(
    hunt_id: str | None = None,
    since: datetime | None = None,
) -> list[dict]:
    """Return hunt_run rows, optionally filtered by hunt_id and/or since.

    Ordered by created_at DESC.
    """
    pool = _get_pool()
    conditions: list[str] = []
    params: list[Any] = []

    if hunt_id is not None:
        conditions.append("hunt_id = %s")
        params.append(hunt_id)
    if since is not None:
        conditions.append("created_at >= %s")
        params.append(since)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    with pool.connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id, hunt_id, investigation_run_id, verdict, severity,
                   mitre_technique, summary, created_at
            FROM hunt_runs
            {where_clause}
            ORDER BY created_at DESC
            """,
            params,
        ).fetchall()
    return [
        {
            "id": r[0],
            "hunt_id": r[1],
            "investigation_run_id": r[2],
            "verdict": r[3],
            "severity": r[4],
            "mitre_technique": r[5],
            "summary": r[6],
            "created_at": r[7],
        }
        for r in rows
    ]


def _hunt_row(row: tuple) -> dict:
    """Convert a DB tuple (10 columns) to a hunt dict."""
    return {
        "id": row[0],
        "name": row[1],
        "mitre_tactic": row[2],
        "mitre_technique": row[3],
        "hypothesis": row[4],
        "hunt_query": row[5],
        "enabled": row[6],
        "interval_hours": row[7],
        "last_run_at": row[8],
        "created_at": row[9],
    }


# ---------------------------------------------------------------------------
# Self-improving memory: drift stats outcome recording + sweep support
# ---------------------------------------------------------------------------

def record_memory_outcome(memory_id: str, run_id: str | None, failed: bool) -> str:
    """Record a single run outcome for a memory.

    Returns the new outcome id (uuid4 hex).
    """
    outcome_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO memory_outcomes (id, memory_id, run_id, failed)
            VALUES (%s, %s, %s, %s)
            """,
            (outcome_id, memory_id, run_id, failed),
        )
        conn.commit()
    return outcome_id


def memory_outcomes_split(
    memory_id: str,
    split_at: datetime,
) -> tuple[int, int, int, int, list[bool]]:
    """Split memory outcomes into before/after the split_at timestamp.

    Returns (fails_before, n_before, fails_after, n_after, ordered_after_outcomes).
    ordered_after_outcomes = the 'failed' bools of the after set ordered by at ASC.
    before = outcomes with at < split_at; after = outcomes with at >= split_at.
    """
    pool = _get_pool()
    with pool.connection() as conn:
        before_rows = conn.execute(
            """
            SELECT failed FROM memory_outcomes
            WHERE memory_id = %s AND at < %s
            ORDER BY at
            """,
            (memory_id, split_at),
        ).fetchall()
        after_rows = conn.execute(
            """
            SELECT failed FROM memory_outcomes
            WHERE memory_id = %s AND at >= %s
            ORDER BY at
            """,
            (memory_id, split_at),
        ).fetchall()

    before_bools = [r[0] for r in before_rows]
    after_bools = [r[0] for r in after_rows]

    fails_before = sum(1 for b in before_bools if b)
    n_before = len(before_bools)
    fails_after = sum(1 for b in after_bools if b)
    n_after = len(after_bools)

    return (fails_before, n_before, fails_after, n_after, after_bools)


def assess_memory_drift(memory_id: str) -> dict:
    """Assess drift for a single memory.

    Loads the memory, determines the split point (promoted_at or created_at),
    splits outcomes, runs drift_stats.assess_drift, and returns the drift dict
    augmented with memory_status.
    """
    import drift_stats  # noqa: PLC0415 — lazy import, avoid circular at module level

    mem = get_memory(memory_id)
    if mem is None:
        raise KeyError(f"memory not found: {memory_id}")

    split_at: datetime = mem["promoted_at"] or mem["created_at"]
    # Ensure timezone-aware
    if split_at.tzinfo is None:
        split_at = split_at.replace(tzinfo=timezone.utc)

    fails_before, n_before, fails_after, n_after, ordered_after = memory_outcomes_split(
        memory_id, split_at
    )

    drift = drift_stats.assess_drift(
        fails_before,
        n_before,
        fails_after,
        n_after,
        ordered_after,
    )
    drift["memory_status"] = mem["memory_status"]
    return drift


def update_drift_score(memory_id: str, pct: int) -> None:
    """Update the drift_score_pct for a memory."""
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            "UPDATE agent_memory SET drift_score_pct = %s, updated_at = now() WHERE id = %s",
            (pct, memory_id),
        )
        conn.commit()


def create_memory_proposal(
    memory_id: str,
    action: str,
    reason: str | None,
    drift_score_pct: int,
) -> str:
    """Create a memory proposal row. Returns new proposal id (uuid4 hex)."""
    proposal_id = uuid4().hex
    pool = _get_pool()
    with pool.connection() as conn:
        conn.execute(
            """
            INSERT INTO memory_proposals (id, memory_id, action, reason, drift_score_pct)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (proposal_id, memory_id, action, reason, drift_score_pct),
        )
        conn.commit()
    return proposal_id


def list_memory_proposals(status: str = "open") -> list[dict]:
    """Return memory proposals filtered by status, ordered by created_at DESC."""
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, memory_id, action, reason, drift_score_pct, status, created_at
            FROM memory_proposals
            WHERE status = %s
            ORDER BY created_at DESC
            """,
            (status,),
        ).fetchall()
    return [
        {
            "id": r[0],
            "memory_id": r[1],
            "action": r[2],
            "reason": r[3],
            "drift_score_pct": r[4],
            "status": r[5],
            "created_at": r[6],
        }
        for r in rows
    ]


def active_or_candidate_memories() -> list[dict]:
    """Return all memories with status 'active' or 'candidate' (the sweep set).

    Excludes retired and draft memories so the sweep is convergent.
    Ordered by updated_at DESC.
    """
    pool = _get_pool()
    with pool.connection() as conn:
        rows = conn.execute(
            """
            SELECT id, agent_slug, key, value, context, category, memory_status,
                   version, rationale, confidence_pct, run_id, usage_count,
                   drift_score_pct, promoted_at, retired_at, created_at, updated_at
            FROM agent_memory
            WHERE memory_status IN ('active', 'candidate')
            ORDER BY updated_at DESC
            """,
        ).fetchall()
    return [
        {
            "id": r[0],
            "agent_slug": r[1],
            "key": r[2],
            "value": r[3],
            "context": r[4],
            "category": r[5],
            "memory_status": r[6],
            "version": r[7],
            "rationale": r[8],
            "confidence_pct": r[9],
            "run_id": r[10],
            "usage_count": r[11],
            "drift_score_pct": r[12],
            "promoted_at": r[13],
            "retired_at": r[14],
            "created_at": r[15],
            "updated_at": r[16],
        }
        for r in rows
    ]
