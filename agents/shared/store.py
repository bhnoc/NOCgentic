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
