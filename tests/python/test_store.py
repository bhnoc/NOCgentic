"""
test_store.py — Integration tests for agents/shared/store.py.

Requires a live Postgres+pgvector. The whole module is skipped cleanly if
PG_DSN is unreachable. Set PG_DSN (or rely on the default):
    postgresql://nocgentic:nocgentic@localhost:5432/nocgentic
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module-level skip if Postgres is unreachable
# ---------------------------------------------------------------------------

_PG_DSN = os.environ.get("PG_DSN", "postgresql://nocgentic:nocgentic@localhost:5432/nocgentic")

try:
    import psycopg
    conn_test = psycopg.connect(_PG_DSN, connect_timeout=3)
    conn_test.close()
except Exception as exc:
    pytest.skip(f"no postgres: {exc}", allow_module_level=True)

# Only import store AFTER we know PG is up (so the pool creation succeeds)
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))
os.environ.setdefault("PG_DSN", _PG_DSN)

import store  # noqa: E402  (must be after env set + sys.path update)

# ---------------------------------------------------------------------------
# Session-scoped fixture: init schema once, truncate between each test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_tables():
    """Ensure schema exists and wipe all tables before each test."""
    store.init_schema()
    import psycopg as _psycopg
    with _psycopg.connect(_PG_DSN) as conn:
        conn.execute(
            """
            TRUNCATE agent_events, agent_runs, incidents,
                     log_templates, deploy_markers RESTART IDENTITY CASCADE
            """
        )
        conn.commit()
    yield


# ---------------------------------------------------------------------------
# Helper: build a 768-dim unit vector with a 1.0 at position `idx`
# ---------------------------------------------------------------------------

def _unit_vec(idx: int, dim: int = 768) -> list[float]:
    v = [0.0] * dim
    v[idx] = 1.0
    return v


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInitSchema:
    def test_idempotent(self):
        """Running init_schema twice should not raise."""
        store.init_schema()
        store.init_schema()  # second call must be a no-op


class TestUpsertTemplate:
    def test_basic_insert(self):
        tid = store.upsert_template(
            template="Connection from <IP> on port <PORT>",
            sample="Connection from 10.0.0.1 on port 443",
            mask_keys={"IP": ["10.0.0.1"], "PORT": ["443"]},
            source="zeek",
            embedding=_unit_vec(0),
        )
        assert isinstance(tid, str)
        assert len(tid) == 16

    def test_dedup_same_id_and_increments_count(self):
        """Inserting the same template twice returns the same id and count==2."""
        template = "DNS query for <DOMAIN>"
        emb = _unit_vec(1)
        id1 = store.upsert_template(template, "dns q for evil.com", {}, "dns", emb)
        id2 = store.upsert_template(template, "dns q for other.com", {}, "dns", emb)
        assert id1 == id2

        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            row = conn.execute(
                "SELECT count FROM log_templates WHERE id = %s", (id1,)
            ).fetchone()
        assert row is not None
        assert row[0] == 2


class TestSimilarTemplates:
    def test_nearest_neighbor(self):
        """Insert 3 templates at orthogonal positions; query near position 2 → it wins."""
        store.upsert_template("tmpl-A", "s", {}, "src", _unit_vec(0))
        store.upsert_template("tmpl-B", "s", {}, "src", _unit_vec(100))
        store.upsert_template("tmpl-C", "s", {}, "src", _unit_vec(200))

        # Query vector very close to position 100 (B)
        query = _unit_vec(100)
        results = store.similar_templates(query, k=3)

        assert len(results) >= 1
        assert results[0]["template"] == "tmpl-B"
        assert results[0]["distance"] == pytest.approx(0.0, abs=1e-5)

        # Keys present
        for r in results:
            assert "id" in r
            assert "template" in r
            assert "distance" in r
            assert "count" in r
            assert "source" in r
            assert "last_seen" in r

    def test_distances_ascending(self):
        store.upsert_template("t1", "s", {}, "s", _unit_vec(0))
        store.upsert_template("t2", "s", {}, "s", _unit_vec(50))
        store.upsert_template("t3", "s", {}, "s", _unit_vec(300))
        results = store.similar_templates(_unit_vec(0), k=3)
        distances = [r["distance"] for r in results]
        assert distances == sorted(distances)


class TestIncidents:
    def test_record_and_recall(self):
        """Record an incident, then find it via similar_incidents."""
        emb = _unit_vec(42)
        inc_id = store.record_incident(
            title="Port scan detected",
            summary="Mass SYN to multiple targets",
            root_cause="Lateral movement attempt",
            resolution="Blocked at FW",
            embedding=emb,
            template_id=None,
            deploy_marker="deploy-123",
            commit_sha="abc123",
        )
        assert isinstance(inc_id, str)
        assert len(inc_id) == 32  # uuid4 hex

        results = store.similar_incidents(emb, k=5)
        assert len(results) == 1
        assert results[0]["id"] == inc_id
        assert results[0]["distance"] == pytest.approx(0.0, abs=1e-5)
        assert results[0]["commit_sha"] == "abc123"
        assert results[0]["deploy_marker"] == "deploy-123"

    def test_nearest_incident(self):
        store.record_incident("inc-A", "s", "rc", "res", _unit_vec(10))
        store.record_incident("inc-B", "s", "rc", "res", _unit_vec(20))
        results = store.similar_incidents(_unit_vec(20), k=2)
        assert results[0]["title"] == "inc-B"


class TestDeployMarkers:
    def test_add_and_markers_near(self):
        now = datetime.now(timezone.utc)
        m1_id = store.add_deploy_marker(now - timedelta(hours=1), "deploy", "v1.2.3", "abc")
        m2_id = store.add_deploy_marker(now - timedelta(minutes=30), "rollback", "v1.2.2")
        # Outside the window
        store.add_deploy_marker(now - timedelta(hours=5), "deploy", "v1.1.0")

        markers = store.markers_near(now - timedelta(hours=2), now)
        ids = [m["id"] for m in markers]
        assert m1_id in ids
        assert m2_id in ids
        # Should be ordered by ts
        tss = [m["ts"] for m in markers]
        assert tss == sorted(tss)

    def test_outside_window_excluded(self):
        now = datetime.now(timezone.utc)
        store.add_deploy_marker(now - timedelta(hours=10), "deploy", "old")
        markers = store.markers_near(now - timedelta(hours=1), now)
        assert markers == []


class TestAgentRunTrace:
    def test_round_trip(self):
        """start_run → emit×3 → finish_run → get_run returns events in seq order 1,2,3."""
        run_id = store.start_run("root-cause", {"query": "why is traffic spiking"})
        assert isinstance(run_id, str)
        assert len(run_id) == 32

        store.emit(run_id, "plan", {"steps": ["detect", "cluster", "recall"]})
        store.emit(run_id, "detect_anomaly", {"spike": True, "count": 5000})
        store.emit(run_id, "verdict", {"severity": "high", "root_cause": "deploy"})

        store.finish_run(run_id, "success", {"finding": "deploy at -30min caused spike"})

        result = store.get_run(run_id)

        assert "run" in result
        assert "events" in result

        run = result["run"]
        assert run["id"] == run_id
        assert run["status"] == "success"
        assert run["output"]["finding"] == "deploy at -30min caused spike"
        assert run["finished_at"] is not None

        events = result["events"]
        assert len(events) == 3
        seqs = [e["seq"] for e in events]
        assert seqs == [1, 2, 3], f"expected [1,2,3], got {seqs}"

        event_types = [e["event_type"] for e in events]
        assert event_types == ["plan", "detect_anomaly", "verdict"]

    def test_get_run_missing_raises(self):
        with pytest.raises(KeyError):
            store.get_run("nonexistent-run-id-00000000")


class TestEmitUniqueSeq:
    """st-2: UNIQUE(run_id, seq) constraint — two emits get distinct seq 1,2."""

    def test_two_emits_get_distinct_seq(self):
        """Two sequential emits on one run produce seq 1 and 2 with no duplicates."""
        run_id = store.start_run("test-run", {"x": 1})
        store.emit(run_id, "event_a", {"n": 1})
        store.emit(run_id, "event_b", {"n": 2})

        result = store.get_run(run_id)
        seqs = [e["seq"] for e in result["events"]]
        assert seqs == [1, 2], f"expected [1, 2], got {seqs}"

    def test_three_sequential_emits_get_123(self):
        """s2-03 gate: three sequential emits produce seq 1, 2, 3."""
        run_id = store.start_run("seq-test", {})
        store.emit(run_id, "e1", {"n": 1})
        store.emit(run_id, "e2", {"n": 2})
        store.emit(run_id, "e3", {"n": 3})
        result = store.get_run(run_id)
        seqs = [e["seq"] for e in result["events"]]
        assert seqs == [1, 2, 3], f"expected [1, 2, 3], got {seqs}"

    def test_forced_duplicate_seq_handled_by_retry(self):
        """s2-03 gate: manually inserting a duplicate seq then calling emit does not raise.

        Simulates the concurrent-emit collision by pre-inserting seq=1, then
        calling emit() which will try seq=1 again, hit UniqueViolation, retry,
        and succeed with seq=2.
        """
        import psycopg as _pg
        from psycopg.types.json import Jsonb

        run_id = store.start_run("retry-test", {})
        # Manually insert seq=1 to simulate one half of a concurrent pair
        with _pg.connect(_PG_DSN) as conn:
            conn.execute(
                "INSERT INTO agent_events (run_id, seq, event_type, data) VALUES (%s, %s, %s, %s)",
                (run_id, 1, "pre_inserted", Jsonb({"x": "pre"})),
            )
            conn.commit()

        # emit() will compute MAX(seq)=1 -> try seq=1 -> UniqueViolation -> retry -> seq=2
        # This should NOT raise.
        store.emit(run_id, "after_conflict", {"x": "retry"})

        result = store.get_run(run_id)
        seqs = sorted(e["seq"] for e in result["events"])
        assert 1 in seqs, "pre-inserted seq=1 must still be present"
        assert 2 in seqs, "retried emit must have landed at seq=2"

    def test_emit_retry_code_exists(self):
        """s2-03 gate: emit() source contains retry logic for UniqueViolation."""
        import inspect
        source = inspect.getsource(store.emit)
        assert "UniqueViolation" in source, "emit must handle psycopg.errors.UniqueViolation"
        assert "retry" in source.lower() or "attempt" in source.lower(), (
            "emit must contain a retry loop"
        )

    def test_unique_index_exists_on_agent_events(self):
        """agent_events_run_seq_uniq UNIQUE index exists in the schema."""
        import psycopg as _pg
        with _pg.connect(_PG_DSN) as conn:
            row = conn.execute(
                """
                SELECT indexname, indisunique
                FROM pg_indexes
                JOIN pg_class ON pg_class.relname = pg_indexes.indexname
                JOIN pg_index ON pg_index.indexrelid = pg_class.oid
                WHERE pg_indexes.tablename = 'agent_events'
                  AND pg_indexes.indexname = 'agent_events_run_seq_uniq'
                """
            ).fetchone()
        assert row is not None, "agent_events_run_seq_uniq index not found"
        # indisunique should be True
        assert row[1] is True, "agent_events_run_seq_uniq is not a unique index"
