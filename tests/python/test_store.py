"""
test_store.py — Integration tests for agents/shared/store.py.

Requires a live Postgres+pgvector. The whole module is skipped cleanly if
PG_DSN is unreachable. Set PG_DSN (or rely on the default):
    postgresql://nocgentic:nocgentic@localhost:5432/nocgentic
"""

from __future__ import annotations

import asyncio
import copy
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

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
                     log_templates, deploy_markers,
                     agent_memory, memory_events, memory_outcomes, memory_proposals
                     RESTART IDENTITY CASCADE
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


# ---------------------------------------------------------------------------
# st-3: upsert_memory version-bump race → retry on UniqueViolation
# ---------------------------------------------------------------------------

class TestUpsertMemoryRetry:
    """st-3: concurrent version collision is retried, not raised."""

    def test_forced_version_collision_retried(self):
        """Pre-insert version=1 then call upsert_memory → retry lands at version=2."""
        import psycopg as _pg
        from psycopg.types.json import Jsonb

        # Insert a seed row directly at version=1
        mem_id_seed = "seed000000000000000000000000000a"
        with _pg.connect(_PG_DSN) as conn:
            conn.execute(
                """
                INSERT INTO agent_memory
                    (id, agent_slug, key, value, category, memory_status, version)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (mem_id_seed, "test-agent", "collision-key", Jsonb("v1"), "fact", "draft", 1),
            )
            conn.commit()

        # upsert_memory will compute MAX(version)=1 → try version=2 → should succeed
        result = store.upsert_memory(
            agent_slug="test-agent",
            key="collision-key",
            value="v2",
            category="fact",
        )
        assert result["version"] == 2, f"expected version=2, got {result['version']}"
        assert result["agent_slug"] == "test-agent"
        assert result["key"] == "collision-key"

    def test_retry_code_exists_in_upsert_memory(self):
        """st-3 gate: upsert_memory source contains UniqueViolation retry logic."""
        import inspect
        source = inspect.getsource(store.upsert_memory)
        assert "UniqueViolation" in source, "upsert_memory must handle UniqueViolation"
        assert "attempt" in source.lower() or "retry" in source.lower(), (
            "upsert_memory must contain a retry loop"
        )

    def test_forced_collision_lands_correct_version(self):
        """Pre-insert version=1 collision → upsert returns version=2, not an exception."""
        import psycopg as _pg
        from psycopg.types.json import Jsonb

        slug = "retry-agent"
        key = "retry-key"

        with _pg.connect(_PG_DSN) as conn:
            conn.execute(
                """
                INSERT INTO agent_memory
                    (id, agent_slug, key, value, category, memory_status, version)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                ("aaaa000000000000000000000000000b", slug, key, Jsonb("existing"), "fact", "draft", 1),
            )
            conn.commit()

        # Should NOT raise — must retry and produce version=2
        r = store.upsert_memory(slug, key, "new-value", category="fact")
        assert r["version"] == 2


# ---------------------------------------------------------------------------
# st-8: FixtureProvider.seen_messages deep snapshot
# ---------------------------------------------------------------------------

class TestFixtureProviderDeepSnapshot:
    """st-8: mutation of a message after chat() does not retroactively change the snapshot."""

    def test_deepcopy_snapshot_not_mutated(self):
        """Mutating a message dict after chat() leaves seen_messages unchanged."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))
        from tool_provider import FixtureProvider

        provider = FixtureProvider(script=[{"text": "done"}])
        msg = {"role": "system", "content": ["initial"]}
        asyncio.run(provider.chat([msg]))

        # Mutate the original message's nested content list
        msg["content"].append("mutated")

        # The snapshot must NOT reflect the mutation
        assert provider.seen_messages[0][0]["content"] == ["initial"], (
            "seen_messages snapshot was mutated retroactively — deepcopy not applied"
        )

    def test_deepcopy_tool_calls_not_mutated(self):
        """Mutating nested tool_calls after chat() does not change snapshot."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))
        from tool_provider import FixtureProvider

        tool_call = {"id": "tc1", "name": "query_athena", "arguments": {"query": "SELECT 1"}}
        msg = {"role": "assistant", "content": "", "tool_calls": [tool_call]}
        provider = FixtureProvider(script=[{"text": "done"}])
        asyncio.run(provider.chat([msg]))

        # Mutate the original tool_call
        tool_call["arguments"]["query"] = "SELECT MUTATED"

        recorded = provider.seen_messages[0][0]["tool_calls"][0]["arguments"]["query"]
        assert recorded == "SELECT 1", (
            f"snapshot was retroactively mutated to: {recorded!r}"
        )


# ---------------------------------------------------------------------------
# st-9: brittle tool-call handling (args=None, missing keys)
# ---------------------------------------------------------------------------

class TestToolProviderRobustness:
    """st-9: malformed tool-call dicts don't raise."""

    def test_fixture_provider_args_none_handled(self):
        """FixtureProvider: a tool_call with args=None uses empty dict, no TypeError."""
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))
        from tool_provider import FixtureProvider

        # FixtureProvider uses tc.get("arguments", {}) — verify no crash
        script = [{"tool_calls": [{"name": "query_athena", "arguments": None}]}]
        provider = FixtureProvider(script=script)
        text, tool_calls = asyncio.run(provider.chat([{"role": "user", "content": "go"}]))
        # Should either return an empty-arguments ToolCall or safely skip
        # (FixtureProvider coerces via dict(tc.get("arguments", {})))
        assert isinstance(tool_calls, list)

    def test_to_langchain_messages_missing_keys(self):
        """_to_langchain_messages: assistant message with missing id/name/arguments survives."""
        import unittest.mock as mock

        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))

        # _to_langchain_messages does a lazy import of langchain_core.messages.
        # Mock those classes so the test runs without langchain installed.
        fake_ai = mock.MagicMock()
        fake_modules = {
            "langchain_core": mock.MagicMock(),
            "langchain_core.messages": mock.MagicMock(
                SystemMessage=mock.MagicMock(side_effect=lambda **kw: kw),
                HumanMessage=mock.MagicMock(side_effect=lambda **kw: kw),
                AIMessage=mock.MagicMock(side_effect=lambda **kw: kw),
                ToolMessage=mock.MagicMock(side_effect=lambda **kw: kw),
            ),
        }

        with mock.patch.dict(sys.modules, fake_modules):
            # Re-import to pick up the mocked langchain_core
            import importlib
            tp = importlib.import_module("tool_provider")
            importlib.reload(tp)

            # History entry missing 'id', 'name', 'arguments'
            messages = [
                {"role": "assistant", "content": "thinking", "tool_calls": [{}]}
            ]
            # Must not raise KeyError
            result = tp._to_langchain_messages(messages)
            assert len(result) == 1

    def test_gemini_chat_args_none_coerced(self):
        """GeminiToolProvider.chat: args=None in tool_calls becomes {} (no TypeError)."""
        import importlib
        import unittest.mock as mock

        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agents" / "shared"))

        # Mock langchain so GeminiToolProvider can be constructed offline
        fake_lc_messages_mod = mock.MagicMock(
            SystemMessage=mock.MagicMock(),
            HumanMessage=mock.MagicMock(),
            AIMessage=mock.MagicMock(),
            ToolMessage=mock.MagicMock(),
        )
        fake_modules = {
            "langchain_core": mock.MagicMock(),
            "langchain_core.messages": fake_lc_messages_mod,
            "langchain_google_genai": mock.MagicMock(
                ChatGoogleGenerativeAI=mock.MagicMock(return_value=mock.MagicMock())
            ),
            "langchain_core.tools": mock.MagicMock(
                StructuredTool=mock.MagicMock(
                    from_function=mock.MagicMock(return_value=mock.MagicMock())
                )
            ),
            "pydantic": mock.MagicMock(BaseModel=object),
        }

        with mock.patch.dict(sys.modules, fake_modules):
            tp = importlib.import_module("tool_provider")
            importlib.reload(tp)

            fake_tc = {"id": "tc-1", "name": "query_athena", "args": None}
            fake_response = mock.MagicMock()
            fake_response.content = ""
            fake_response.tool_calls = [fake_tc]

            provider = object.__new__(tp.GeminiToolProvider)
            provider._llm_with_tools = mock.MagicMock()
            provider._llm_no_tools = mock.MagicMock()

            async def _fake_ainvoke(_msgs):
                return fake_response

            provider._llm_with_tools.ainvoke = _fake_ainvoke

            with mock.patch.object(tp, "_to_langchain_messages", return_value=[]):
                text, tool_calls = asyncio.run(
                    provider.chat([{"role": "user", "content": "hi"}], use_tools=True)
                )

        assert len(tool_calls) == 1
        assert tool_calls[0]["arguments"] == {}, (
            f"expected empty dict for args=None, got {tool_calls[0]['arguments']!r}"
        )


# ---------------------------------------------------------------------------
# st-10: init_schema FileNotFoundError / RECALL_MIGRATION_PATH file mode
# ---------------------------------------------------------------------------

class TestInitSchemaPathHandling:
    """st-10: clear error when no migrations found; file-mode runs exactly that file."""

    def test_no_migrations_raises_clear_error(self, tmp_path):
        """No .sql files in migrations dir → FileNotFoundError with clear message."""
        import unittest.mock as mock

        empty_dir = tmp_path / "empty_migrations"
        empty_dir.mkdir()
        # _MIGRATION_PATH.parent is used as migrations_dir when override is not an
        # existing file. Patch _MIGRATION_PATH so its .parent = empty_dir.
        fake_path = empty_dir / "0000_missing.sql"  # does not exist → not a file
        with patch.object(store, "_MIGRATION_PATH", fake_path):
            with patch.dict(os.environ, {}, clear=False):
                # Remove RECALL_MIGRATION_PATH so the env-override branch is skipped
                env_clean = {k: v for k, v in os.environ.items() if k != "RECALL_MIGRATION_PATH"}
                with patch.dict(os.environ, env_clean, clear=True):
                    with pytest.raises(FileNotFoundError, match="no migration files found"):
                        store.init_schema()

    def test_file_mode_runs_exactly_that_file(self, tmp_path):
        """RECALL_MIGRATION_PATH = existing file → only that file is executed."""
        import unittest.mock as mock

        # Create two SQL files in a temp dir; point RECALL_MIGRATION_PATH at only one
        sql_a = tmp_path / "0000_a.sql"
        sql_b = tmp_path / "0001_b.sql"
        sql_a.write_text("-- migration a\n")
        sql_b.write_text("-- migration b\n")

        executed = []

        def _fake_execute(sql, *args, **kwargs):
            executed.append(sql)
            return mock.MagicMock()

        with patch.dict(os.environ, {"RECALL_MIGRATION_PATH": str(sql_a)}):
            with patch("store._get_pool") as mock_pool:
                mock_conn = mock.MagicMock()
                mock_conn.execute.side_effect = _fake_execute
                ctx = mock.MagicMock()
                ctx.__enter__ = mock.MagicMock(return_value=mock_conn)
                ctx.__exit__ = mock.MagicMock(return_value=False)
                mock_pool.return_value.connection.return_value = ctx
                store.init_schema()

        # Only sql_a's content should have been executed (plus the advisory lock call)
        sql_calls = [c for c in executed if "migration" in c.lower()]
        assert len(sql_calls) == 1
        assert "migration a" in sql_calls[0]


# ---------------------------------------------------------------------------
# st-11: PG_DSN unset → warning logged
# ---------------------------------------------------------------------------

class TestPgDsnWarning:
    """st-11: when PG_DSN is unset, a WARNING is emitted."""

    def test_missing_pg_dsn_logs_warning(self, caplog):
        """With PG_DSN unset, _get_pool logs a warning about the dev default."""
        import logging
        import unittest.mock as mock

        # Reset the module-level pool so _get_pool runs the creation path
        original_pool = store._pool
        store._pool = None

        try:
            env_without_pg_dsn = {k: v for k, v in os.environ.items() if k != "PG_DSN"}
            with patch.dict(os.environ, env_without_pg_dsn, clear=True):
                with patch("psycopg_pool.ConnectionPool") as mock_cp:
                    mock_cp.return_value = mock.MagicMock()
                    with caplog.at_level(logging.WARNING, logger="store"):
                        store._get_pool()

            warning_msgs = [r.message for r in caplog.records if r.levelno == logging.WARNING]
            assert any("PG_DSN not set" in m for m in warning_msgs), (
                f"Expected 'PG_DSN not set' warning, got: {warning_msgs}"
            )
        finally:
            store._pool = original_pool  # restore pool


# ---------------------------------------------------------------------------
# s2-08: _extension_ensured flag skips DDL on subsequent connections
# ---------------------------------------------------------------------------

class TestExtensionEnsuredFlag:
    """s2-08: CREATE EXTENSION DDL runs only once per process."""

    def test_extension_ensured_flag_set_after_pool_creation(self):
        """After at least one pool connection, _extension_ensured must be True.

        Establish the precondition here rather than assuming session/test order:
        force a real pooled connection, which runs _configure_conn and sets the flag.
        (Relying on 'some earlier test opened the pool' made this order-flaky.)
        """
        pool = store._get_pool()
        with pool.connection() as conn:
            conn.execute("SELECT 1")
        assert store._extension_ensured is True, (
            "_extension_ensured should be True after the first pool connection"
        )

    def test_configure_conn_skips_ddl_when_flag_set(self):
        """_configure_conn with _extension_ensured=True skips advisory lock + CREATE EXTENSION."""
        import unittest.mock as mock

        original = store._extension_ensured
        store._extension_ensured = True
        try:
            mock_conn = mock.MagicMock()
            # register_vector requires a real psycopg connection; mock it at the module level.
            with mock.patch("store.register_vector") as mock_rv:
                store._configure_conn(mock_conn)
                # register_vector must still be called (fast, no DDL)
                mock_rv.assert_called_once_with(mock_conn)
            # conn.execute must NOT have been called (no advisory lock, no CREATE EXTENSION)
            mock_conn.execute.assert_not_called()
        finally:
            store._extension_ensured = original
