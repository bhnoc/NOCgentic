"""
test_memory.py — Integration tests for memory store functions in agents/shared/store.py.

Requires a live Postgres+pgvector. The whole module is skipped cleanly if
PG_DSN is unreachable. Set PG_DSN (or rely on the default):
    postgresql://nocgentic:nocgentic@localhost:5432/nocgentic

Covers:
  - upsert_memory: new key -> version 1; same key -> version 2 (both rows exist)
  - lifecycle: promote draft->candidate->active (2 steps), promoted_at set, 2 memory_events
  - retire from active, retired_at set
  - illegal draft->active direct -> ValueError
  - unknown status -> ValueError
  - list_memories ordering (confidence desc)
  - active_memories: returns only active, capped
  - bump_memory_usage: increments usage_count
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module-level skip if Postgres is unreachable
# ---------------------------------------------------------------------------

_PG_DSN = os.environ.get("PG_DSN", "postgresql://nocgentic:nocgentic@localhost:5432/nocgentic")

try:
    import psycopg as _psycopg_check
    _conn_check = _psycopg_check.connect(_PG_DSN, connect_timeout=3)
    _conn_check.close()
except Exception as _pg_exc:
    pytest.skip(f"no postgres: {_pg_exc}", allow_module_level=True)

# Only import store AFTER we know PG is up
_SHARED = str(Path(__file__).resolve().parents[2] / "agents" / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)
os.environ.setdefault("PG_DSN", _PG_DSN)

import store  # noqa: E402

# ---------------------------------------------------------------------------
# Session-scoped fixture: init schema once, truncate between each test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_tables():
    """Ensure schema exists and wipe memory tables before each test."""
    store.init_schema()
    import psycopg as _psycopg
    with _psycopg.connect(_PG_DSN) as conn:
        conn.execute("TRUNCATE memory_events, agent_memory RESTART IDENTITY CASCADE")
        conn.commit()
    yield


# ---------------------------------------------------------------------------
# upsert_memory — versioning
# ---------------------------------------------------------------------------


class TestUpsertMemory:
    def test_new_key_creates_version_1(self):
        result = store.upsert_memory("investigator", "test-key", {"x": 1})
        assert result["version"] == 1
        assert result["memory_status"] == "draft"
        assert result["agent_slug"] == "investigator"
        assert result["key"] == "test-key"
        assert result["id"]

    def test_same_key_creates_version_2(self):
        r1 = store.upsert_memory("investigator", "my-key", "value1")
        r2 = store.upsert_memory("investigator", "my-key", "value2")
        assert r1["version"] == 1
        assert r2["version"] == 2
        # Both rows must exist
        m1 = store.get_memory(r1["id"])
        m2 = store.get_memory(r2["id"])
        assert m1 is not None
        assert m2 is not None
        assert m1["version"] == 1
        assert m2["version"] == 2

    def test_different_keys_independent(self):
        r1 = store.upsert_memory("investigator", "key-a", "v1")
        r2 = store.upsert_memory("investigator", "key-b", "v1")
        assert r1["version"] == 1
        assert r2["version"] == 1

    def test_different_agent_slugs_independent(self):
        r1 = store.upsert_memory("agent-a", "shared-key", "v")
        r2 = store.upsert_memory("agent-b", "shared-key", "v")
        assert r1["version"] == 1
        assert r2["version"] == 1

    def test_invalid_category_raises(self):
        with pytest.raises(ValueError, match="unknown category"):
            store.upsert_memory("investigator", "k", "v", category="invalid_cat")

    def test_valid_categories_accepted(self):
        for cat in ("fact", "prompt_refinement", "preference", "lesson_learned"):
            r = store.upsert_memory("investigator", f"key-{cat}", "v", category=cat)
            assert r["memory_status"] == "draft"

    def test_returns_dict_with_expected_keys(self):
        r = store.upsert_memory("investigator", "k", "v")
        assert set(r.keys()) >= {"id", "agent_slug", "key", "version", "memory_status"}


# ---------------------------------------------------------------------------
# get_memory
# ---------------------------------------------------------------------------


class TestGetMemory:
    def test_get_returns_all_cols(self):
        r = store.upsert_memory("inv", "k", {"data": 1}, context="ctx", confidence_pct=80)
        mem = store.get_memory(r["id"])
        assert mem is not None
        assert mem["id"] == r["id"]
        assert mem["context"] == "ctx"
        assert mem["confidence_pct"] == 80
        assert mem["usage_count"] == 0
        assert mem["memory_status"] == "draft"

    def test_get_nonexistent_returns_none(self):
        assert store.get_memory("nonexistent-id-xyz") is None


# ---------------------------------------------------------------------------
# lifecycle transitions
# ---------------------------------------------------------------------------


class TestTransitionMemory:
    def _upsert(self, key: str = "k", **kw) -> str:
        return store.upsert_memory("investigator", key, "v", **kw)["id"]

    def test_draft_to_candidate(self):
        mid = self._upsert()
        result = store.transition_memory(mid, "candidate")
        assert result["from_status"] == "draft"
        assert result["to_status"] == "candidate"

    def test_candidate_to_active_sets_promoted_at(self):
        mid = self._upsert()
        store.transition_memory(mid, "candidate")
        store.transition_memory(mid, "active")
        mem = store.get_memory(mid)
        assert mem["memory_status"] == "active"
        assert mem["promoted_at"] is not None

    def test_two_step_promotion_creates_two_events(self):
        mid = self._upsert()
        store.transition_memory(mid, "candidate")
        store.transition_memory(mid, "active")
        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            rows = conn.execute(
                "SELECT from_status, to_status FROM memory_events WHERE memory_id = %s ORDER BY at",
                (mid,),
            ).fetchall()
        assert len(rows) == 2
        assert rows[0][0] == "draft"
        assert rows[0][1] == "candidate"
        assert rows[1][0] == "candidate"
        assert rows[1][1] == "active"

    def test_retire_from_active_sets_retired_at(self):
        mid = self._upsert()
        store.transition_memory(mid, "candidate")
        store.transition_memory(mid, "active")
        store.transition_memory(mid, "retired")
        mem = store.get_memory(mid)
        assert mem["memory_status"] == "retired"
        assert mem["retired_at"] is not None

    def test_illegal_draft_to_active_raises(self):
        mid = self._upsert()
        with pytest.raises(ValueError, match="illegal memory transition draft->active"):
            store.transition_memory(mid, "active")

    def test_unknown_status_raises(self):
        mid = self._upsert()
        with pytest.raises(ValueError, match="unknown status"):
            store.transition_memory(mid, "nonexistent_status")

    def test_retired_is_terminal(self):
        mid = self._upsert()
        store.transition_memory(mid, "retired")
        with pytest.raises(ValueError, match="illegal memory transition retired->"):
            store.transition_memory(mid, "candidate")

    def test_actor_recorded_in_event(self):
        mid = self._upsert()
        store.transition_memory(mid, "candidate", actor="test-runner")
        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            row = conn.execute(
                "SELECT actor FROM memory_events WHERE memory_id = %s",
                (mid,),
            ).fetchone()
        assert row[0] == "test-runner"

    def test_candidate_can_go_back_to_draft(self):
        mid = self._upsert()
        store.transition_memory(mid, "candidate")
        result = store.transition_memory(mid, "draft")
        assert result["to_status"] == "draft"


# ---------------------------------------------------------------------------
# list_memories ordering
# ---------------------------------------------------------------------------


class TestListMemories:
    def test_ordered_by_confidence_desc(self):
        store.upsert_memory("inv", "low", "v", confidence_pct=20)
        store.upsert_memory("inv", "high", "v", confidence_pct=80)
        store.upsert_memory("inv", "mid", "v", confidence_pct=50)
        mems = store.list_memories(agent_slug="inv")
        confidences = [m["confidence_pct"] for m in mems]
        assert confidences == sorted(confidences, reverse=True)

    def test_nulls_last_in_ordering(self):
        store.upsert_memory("inv", "no-conf", "v")  # confidence_pct = None
        store.upsert_memory("inv", "has-conf", "v", confidence_pct=50)
        mems = store.list_memories(agent_slug="inv")
        # First row should have a confidence value, null should be last
        assert mems[0]["confidence_pct"] == 50
        assert mems[-1]["confidence_pct"] is None

    def test_filter_by_status(self):
        r1 = store.upsert_memory("inv", "k1", "v")
        store.transition_memory(r1["id"], "candidate")
        store.upsert_memory("inv", "k2", "v")  # stays draft
        drafts = store.list_memories(agent_slug="inv", status="draft")
        candidates = store.list_memories(agent_slug="inv", status="candidate")
        assert all(m["memory_status"] == "draft" for m in drafts)
        assert all(m["memory_status"] == "candidate" for m in candidates)

    def test_filter_by_category(self):
        store.upsert_memory("inv", "k1", "v", category="fact")
        store.upsert_memory("inv", "k2", "v", category="prompt_refinement")
        facts = store.list_memories(category="fact")
        assert all(m["category"] == "fact" for m in facts)


# ---------------------------------------------------------------------------
# active_memories
# ---------------------------------------------------------------------------


class TestActiveMemories:
    def _make_active(self, key: str, agent: str = "investigator", **kw) -> str:
        r = store.upsert_memory(agent, key, "v", **kw)
        store.transition_memory(r["id"], "candidate")
        store.transition_memory(r["id"], "active")
        return r["id"]

    def test_returns_only_active(self):
        mid_active = self._make_active("active-key")
        store.upsert_memory("investigator", "draft-key", "v")  # stays draft
        mems = store.active_memories("investigator")
        ids = [m["id"] for m in mems]
        assert mid_active in ids
        assert all(m["memory_status"] == "active" for m in mems)

    def test_capped_at_limit(self):
        for i in range(10):
            self._make_active(f"key-{i}")
        mems = store.active_memories("investigator", limit=5)
        assert len(mems) <= 5

    def test_returns_required_fields(self):
        self._make_active("scanner-range", confidence_pct=75)
        mems = store.active_memories("investigator")
        assert mems
        m = mems[0]
        for field in ("id", "key", "value", "context", "category", "confidence_pct", "usage_count"):
            assert field in m

    def test_different_agents_isolated(self):
        self._make_active("k1", agent="agent-a")
        self._make_active("k2", agent="agent-b")
        a_mems = store.active_memories("agent-a")
        assert all(m["agent_slug"] == "agent-a" for m in a_mems)


# ---------------------------------------------------------------------------
# bump_memory_usage
# ---------------------------------------------------------------------------


class TestBumpMemoryUsage:
    def test_increments_usage_count(self):
        r = store.upsert_memory("inv", "k", "v")
        mid = r["id"]
        store.bump_memory_usage([mid])
        mem = store.get_memory(mid)
        assert mem["usage_count"] == 1

    def test_multiple_bumps_accumulate(self):
        r = store.upsert_memory("inv", "k", "v")
        mid = r["id"]
        store.bump_memory_usage([mid])
        store.bump_memory_usage([mid])
        store.bump_memory_usage([mid])
        mem = store.get_memory(mid)
        assert mem["usage_count"] == 3

    def test_empty_list_is_noop(self):
        # Should not raise
        store.bump_memory_usage([])

    def test_bumps_multiple_ids(self):
        r1 = store.upsert_memory("inv", "k1", "v")
        r2 = store.upsert_memory("inv", "k2", "v")
        store.bump_memory_usage([r1["id"], r2["id"]])
        assert store.get_memory(r1["id"])["usage_count"] == 1
        assert store.get_memory(r2["id"])["usage_count"] == 1
