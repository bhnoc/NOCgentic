"""
test_memory_selfimprove.py — PG-backed integration tests for self-improving memory.

Requires a live Postgres+pgvector. Entire module is skipped if PG_DSN unreachable.
Covers:
  - record_memory_outcome + memory_outcomes_split partitioning
  - assess_memory_drift with seeded degradation → 'alert'
  - sweep off: drift_score updated, no proposals, no status change
  - sweep shadow: proposals written, status UNCHANGED
  - sweep live: alerting active memory gets retired; retired excluded from next sweep
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone, timedelta
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

_SHARED = str(Path(__file__).resolve().parents[2] / "agents" / "shared")
if _SHARED not in sys.path:
    sys.path.insert(0, _SHARED)
os.environ.setdefault("PG_DSN", _PG_DSN)

import store  # noqa: E402
import drift_stats  # noqa: E402

# Load the memory agent main for endpoint tests
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("OTEL_CONSOLE_TRACES", "false")
from conftest import load_agent_main  # noqa: E402
_memory_main = load_agent_main("memory", "memory_main")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_tables():
    """Ensure schema exists and wipe relevant tables before each test."""
    store.init_schema()
    import psycopg as _psycopg
    with _psycopg.connect(_PG_DSN) as conn:
        conn.execute(
            "TRUNCATE memory_proposals, memory_outcomes, memory_events, agent_memory RESTART IDENTITY CASCADE"
        )
        conn.commit()
    yield


def _make_memory(key: str = "test-key", agent: str = "investigator", **kw) -> str:
    """Helper: create a draft memory and return its id."""
    return store.upsert_memory(agent, key, {"test": True}, **kw)["id"]


def _make_candidate(key: str = "cand-key", agent: str = "investigator", **kw) -> str:
    """Helper: create a candidate memory."""
    mid = _make_memory(key, agent, **kw)
    store.transition_memory(mid, "candidate")
    return mid


def _make_active(key: str = "active-key", agent: str = "investigator", **kw) -> str:
    """Helper: create an active memory."""
    mid = _make_candidate(key, agent, **kw)
    store.transition_memory(mid, "active")
    return mid


# ---------------------------------------------------------------------------
# record_memory_outcome + memory_outcomes_split
# ---------------------------------------------------------------------------


class TestOutcomeRecording:
    def test_record_returns_id(self):
        mid = _make_active()
        outcome_id = store.record_memory_outcome(mid, "run-001", failed=True)
        assert outcome_id
        assert len(outcome_id) == 32  # uuid4 hex

    def test_split_partitions_by_split_at(self):
        mid = _make_active()

        # Record 3 outcomes "before" (well in the past)
        past = datetime(2020, 1, 1, tzinfo=timezone.utc)
        future = datetime(2030, 1, 1, tzinfo=timezone.utc)
        split_at = datetime(2025, 1, 1, tzinfo=timezone.utc)

        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            # Insert 3 "before" outcomes at 2020-01-01
            for i in range(3):
                conn.execute(
                    "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                    (f"before-{i}", mid, f"run-before-{i}", i % 2 == 0, past),
                )
            # Insert 2 "after" outcomes at 2030-01-01
            for i in range(2):
                conn.execute(
                    "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                    (f"after-{i}", mid, f"run-after-{i}", True, future),
                )
            conn.commit()

        fails_before, n_before, fails_after, n_after, ordered_after = store.memory_outcomes_split(mid, split_at)

        assert n_before == 3
        assert n_after == 2
        assert fails_before == 2  # indices 0,2 → True (i%2==0 means failed=True)
        assert fails_after == 2
        assert ordered_after == [True, True]

    def test_split_at_boundary_inclusive_after(self):
        """Outcomes at exactly split_at go to the 'after' bucket (at >= split_at)."""
        mid = _make_active()
        split_at = datetime(2025, 6, 1, tzinfo=timezone.utc)

        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            # Exactly at split_at → should be "after"
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                ("exact", mid, "run-exact", True, split_at),
            )
            # One microsecond before → "before"
            before_ts = split_at - timedelta(microseconds=1)
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                ("just-before", mid, "run-before", False, before_ts),
            )
            conn.commit()

        _, n_before, _, n_after, _ = store.memory_outcomes_split(mid, split_at)
        assert n_before == 1
        assert n_after == 1

    def test_no_outcomes_returns_zeros(self):
        mid = _make_active()
        split_at = datetime.now(tz=timezone.utc)
        fb, nb, fa, na, ordered = store.memory_outcomes_split(mid, split_at)
        assert nb == 0
        assert na == 0
        assert fa == 0
        assert fb == 0
        assert ordered == []


# ---------------------------------------------------------------------------
# assess_memory_drift
# ---------------------------------------------------------------------------


def _seed_outcomes_around_promotion(memory_id: str, n_before: int, fails_before: int,
                                     n_after: int, fails_after: int) -> None:
    """Inject outcomes into memory_outcomes around the memory's promoted_at."""
    import psycopg as _psycopg
    mem = store.get_memory(memory_id)
    promoted_at = mem["promoted_at"] or mem["created_at"]
    if promoted_at.tzinfo is None:
        promoted_at = promoted_at.replace(tzinfo=timezone.utc)

    before_ts = promoted_at - timedelta(hours=1)
    after_ts = promoted_at + timedelta(hours=1)

    with _psycopg.connect(_PG_DSN) as conn:
        for i in range(n_before):
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                (f"b{i}-{memory_id[:8]}", memory_id, f"run-b{i}", i < fails_before, before_ts),
            )
        for i in range(n_after):
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                (f"a{i}-{memory_id[:8]}", memory_id, f"run-a{i}", i < fails_after, after_ts),
            )
        conn.commit()


class TestAssessMemoryDrift:
    def test_degradation_gives_alert(self):
        """5/100 before, 40/100 after → level 'alert'."""
        mid = _make_active()
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)
        drift = store.assess_memory_drift(mid)
        assert drift["level"] == "alert"
        assert drift["memory_status"] == "active"
        assert drift["z"] > drift_stats.Z_99

    def test_no_outcomes_insufficient_data(self):
        """No outcomes → insufficient_data."""
        mid = _make_active()
        drift = store.assess_memory_drift(mid)
        assert drift["level"] == "insufficient_data"

    def test_missing_memory_raises_key_error(self):
        with pytest.raises(KeyError):
            store.assess_memory_drift("nonexistent-id-xyz")

    def test_drift_contains_expected_keys(self):
        mid = _make_active()
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)
        drift = store.assess_memory_drift(mid)
        for key in ("level", "z", "delta_pct", "drift_score_pct", "reason", "ci_after_pct", "memory_status"):
            assert key in drift


# ---------------------------------------------------------------------------
# Sweep: off mode
# ---------------------------------------------------------------------------


class TestSweepOff:
    def test_off_no_proposals_no_status_change(self):
        """Sweep off: drift_score updated, no proposals, no status change."""
        mid = _make_active("off-test")
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)  # alert-level degradation

        # Call sweep logic directly via store functions (same path as main.py)
        memories = store.active_or_candidate_memories()
        for mem in memories:
            drift = store.assess_memory_drift(mem["id"])
            store.update_drift_score(mem["id"], drift["drift_score_pct"])
            # off mode: do nothing else

        # Status unchanged
        updated = store.get_memory(mid)
        assert updated["memory_status"] == "active"

        # No proposals
        proposals = store.list_memory_proposals("open")
        assert len(proposals) == 0

        # drift_score_pct updated
        assert updated["drift_score_pct"] is not None
        assert updated["drift_score_pct"] > 0

    def test_off_retired_not_in_sweep(self):
        """Retired memory is excluded from active_or_candidate_memories."""
        mid = _make_active("retire-test")
        store.transition_memory(mid, "retired")
        memories = store.active_or_candidate_memories()
        ids = [m["id"] for m in memories]
        assert mid not in ids


# ---------------------------------------------------------------------------
# Sweep: shadow mode
# ---------------------------------------------------------------------------


class TestSweepShadow:
    def test_shadow_writes_proposals_no_status_change(self):
        """Shadow: proposal row written, memory status unchanged."""
        mid = _make_active("shadow-test")
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)  # alert-level

        memories = store.active_or_candidate_memories()
        for mem in memories:
            if mem["id"] != mid:
                continue
            drift = store.assess_memory_drift(mem["id"])
            store.update_drift_score(mem["id"], drift["drift_score_pct"])
            plan = drift_stats.plan_action(mem["memory_status"], drift["level"])
            action = plan["action"]
            if action is not None:
                store.create_memory_proposal(mem["id"], action, drift["reason"], drift["drift_score_pct"])

        # Status unchanged
        updated = store.get_memory(mid)
        assert updated["memory_status"] == "active"

        # Proposal written
        proposals = store.list_memory_proposals("open")
        assert len(proposals) == 1
        p = proposals[0]
        assert p["memory_id"] == mid
        assert p["action"] == "retire"
        assert p["drift_score_pct"] > 0

    def test_shadow_candidate_improvement_proposes_promote(self):
        """Candidate + improving → shadow proposes 'promote'."""
        mid = _make_candidate("cand-improve")
        _seed_outcomes_around_promotion(mid, 100, 40, 100, 5)  # improving

        drift = store.assess_memory_drift(mid)
        assert drift["level"] == "improving"

        plan = drift_stats.plan_action("candidate", drift["level"])
        assert plan["action"] == "promote"

        store.create_memory_proposal(mid, plan["action"], drift["reason"], drift["drift_score_pct"])

        proposals = store.list_memory_proposals("open")
        assert len(proposals) == 1
        assert proposals[0]["action"] == "promote"

        # Status still candidate
        updated = store.get_memory(mid)
        assert updated["memory_status"] == "candidate"


# ---------------------------------------------------------------------------
# Sweep: live mode
# ---------------------------------------------------------------------------


class TestSweepLive:
    def test_live_retires_alerting_active_memory(self):
        """Live mode: active memory with alert → retired, memory_events row written."""
        mid = _make_active("live-retire")
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)

        drift = store.assess_memory_drift(mid)
        assert drift["level"] == "alert"
        plan = drift_stats.plan_action("active", drift["level"])
        assert plan["action"] == "retire"

        store.update_drift_score(mid, drift["drift_score_pct"])
        store.transition_memory(mid, "retired", actor="self-improve")

        updated = store.get_memory(mid)
        assert updated["memory_status"] == "retired"
        assert updated["retired_at"] is not None

        # Check memory_events
        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            rows = conn.execute(
                "SELECT from_status, to_status, actor FROM memory_events WHERE memory_id = %s",
                (mid,),
            ).fetchall()
        # There should be events including the retirement
        retirement_events = [r for r in rows if r[1] == "retired"]
        assert len(retirement_events) >= 1
        # Check actor
        retire_event = retirement_events[-1]
        assert retire_event[2] == "self-improve"

    def test_live_promotes_improving_candidate(self):
        """Live mode: candidate + improving → active."""
        mid = _make_candidate("live-promote")
        _seed_outcomes_around_promotion(mid, 100, 40, 100, 5)

        drift = store.assess_memory_drift(mid)
        assert drift["level"] == "improving"
        plan = drift_stats.plan_action("candidate", drift["level"])
        assert plan["action"] == "promote"

        store.update_drift_score(mid, drift["drift_score_pct"])
        store.transition_memory(mid, "active", actor="self-improve")

        updated = store.get_memory(mid)
        assert updated["memory_status"] == "active"
        assert updated["promoted_at"] is not None

    def test_live_retired_excluded_from_next_sweep(self):
        """After live retirement, retired memory not in sweep set (idempotent/convergent)."""
        mid = _make_active("convergence-test")
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)

        # First sweep: retire it
        drift = store.assess_memory_drift(mid)
        store.update_drift_score(mid, drift["drift_score_pct"])
        store.transition_memory(mid, "retired", actor="self-improve")

        # Second sweep: retired memory must not appear
        memories_second_sweep = store.active_or_candidate_memories()
        assert all(m["id"] != mid for m in memories_second_sweep)

    def test_live_sweep_is_idempotent_for_retired(self):
        """Running sweep twice doesn't raise on already-retired memory."""
        mid = _make_active("idempotent-test")
        _seed_outcomes_around_promotion(mid, 100, 5, 100, 40)

        # Retire
        store.transition_memory(mid, "retired", actor="self-improve")

        # Second sweep: memory not in sweep set, no error
        memories = store.active_or_candidate_memories()
        ids_in_sweep = [m["id"] for m in memories]
        assert mid not in ids_in_sweep

    def test_sweep_set_excludes_draft(self):
        """Draft memories are never in the sweep set."""
        mid = _make_memory("draft-test")  # stays draft
        memories = store.active_or_candidate_memories()
        assert all(m["id"] != mid for m in memories)


# ---------------------------------------------------------------------------
# update_drift_score
# ---------------------------------------------------------------------------


class TestUpdateDriftScore:
    def test_updates_drift_score(self):
        mid = _make_active("drift-score-test")
        store.update_drift_score(mid, 42)
        updated = store.get_memory(mid)
        assert updated["drift_score_pct"] == 42

    def test_overwrites_previous(self):
        mid = _make_active("drift-score-overwrite")
        store.update_drift_score(mid, 10)
        store.update_drift_score(mid, 75)
        updated = store.get_memory(mid)
        assert updated["drift_score_pct"] == 75


# ---------------------------------------------------------------------------
# create_memory_proposal + list_memory_proposals
# ---------------------------------------------------------------------------


class TestMemoryProposals:
    def test_create_and_list(self):
        mid = _make_active("proposal-test")
        proposal_id = store.create_memory_proposal(mid, "retire", "test reason", 30)
        assert proposal_id

        proposals = store.list_memory_proposals("open")
        assert len(proposals) == 1
        p = proposals[0]
        assert p["id"] == proposal_id
        assert p["memory_id"] == mid
        assert p["action"] == "retire"
        assert p["reason"] == "test reason"
        assert p["drift_score_pct"] == 30
        assert p["status"] == "open"

    def test_filter_by_status(self):
        mid = _make_active("proposal-filter")
        pid = store.create_memory_proposal(mid, "retire", "r", 10)

        # Mark as closed
        import psycopg as _psycopg
        with _psycopg.connect(_PG_DSN) as conn:
            conn.execute("UPDATE memory_proposals SET status = 'closed' WHERE id = %s", (pid,))
            conn.commit()

        open_proposals = store.list_memory_proposals("open")
        closed_proposals = store.list_memory_proposals("closed")
        assert len(open_proposals) == 0
        assert len(closed_proposals) == 1


# ---------------------------------------------------------------------------
# active_or_candidate_memories
# ---------------------------------------------------------------------------


class TestActiveOrCandidateMemories:
    def test_includes_active_and_candidate(self):
        mid_active = _make_active("act-1")
        mid_candidate = _make_candidate("cand-1")
        mid_draft = _make_memory("draft-1")

        memories = store.active_or_candidate_memories()
        ids = [m["id"] for m in memories]
        assert mid_active in ids
        assert mid_candidate in ids
        assert mid_draft not in ids

    def test_excludes_retired(self):
        mid = _make_active("will-retire")
        store.transition_memory(mid, "retired")
        memories = store.active_or_candidate_memories()
        assert all(m["id"] != mid for m in memories)

    def test_empty_when_no_active_or_candidate(self):
        _make_memory("just-draft")
        memories = store.active_or_candidate_memories()
        assert len(memories) == 0


# ---------------------------------------------------------------------------
# mem-5: candidate with strong post-candidacy improvement must auto-promote
# ---------------------------------------------------------------------------

def _seed_outcomes_around_candidacy(memory_id: str, n_before: int, fails_before: int,
                                     n_after: int, fails_after: int) -> None:
    """Insert outcomes split around the candidacy-transition event timestamp."""
    import psycopg as _psycopg
    with _psycopg.connect(_PG_DSN) as conn:
        # Find the candidacy event timestamp
        row = conn.execute(
            "SELECT at FROM memory_events WHERE memory_id = %s AND to_status = 'candidate' ORDER BY at DESC LIMIT 1",
            (memory_id,),
        ).fetchone()
        assert row is not None, "no candidacy event found"
        candidate_ts = row[0]
        if candidate_ts.tzinfo is None:
            from datetime import timezone
            candidate_ts = candidate_ts.replace(tzinfo=timezone.utc)

        before_ts = candidate_ts - timedelta(hours=1)
        after_ts = candidate_ts + timedelta(hours=1)

        for i in range(n_before):
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                (f"cb{i}-{memory_id[:8]}", memory_id, f"run-cb{i}", i < fails_before, before_ts),
            )
        for i in range(n_after):
            conn.execute(
                "INSERT INTO memory_outcomes (id, memory_id, run_id, failed, at) VALUES (%s, %s, %s, %s, %s)",
                (f"ca{i}-{memory_id[:8]}", memory_id, f"run-ca{i}", i < fails_after, after_ts),
            )
        conn.commit()


class TestMem5CandidateAutoPromote:
    """mem-5: a candidate with strong post-candidacy improvement must auto-promote
    (previously stuck at insufficient_data because promoted_at is NULL)."""

    def test_candidate_improving_yields_promote_action(self):
        """Strong improvement after candidacy → assess returns 'improving' → plan 'promote'."""
        mid = _make_candidate("mem5-improve")
        # 40% failure before, 5% after candidacy → strongly improving
        _seed_outcomes_around_candidacy(mid, 100, 40, 100, 5)

        # Import the helper from main.py
        import sys
        from pathlib import Path
        _MEMORY_AGENT = str(Path(__file__).resolve().parents[2] / "agents" / "memory")
        if _MEMORY_AGENT not in sys.path:
            sys.path.insert(0, _MEMORY_AGENT)
        from main import _assess_candidate_drift

        mem = store.get_memory(mid)
        drift = _assess_candidate_drift(mid, mem)

        assert drift["level"] == "improving", (
            f"Expected 'improving' for candidate but got {drift['level']!r} "
            f"(mem-5 regression: candidacy split point not used). "
            f"z={drift.get('z')}, delta_pct={drift.get('delta_pct')}"
        )

        plan = drift_stats.plan_action("candidate", drift["level"])
        assert plan["action"] == "promote"

    def test_candidate_improving_live_sweep_promotes(self):
        """End-to-end: live sweep auto-promotes a strongly-improving candidate."""
        mid = _make_candidate("mem5-live-promote")
        _seed_outcomes_around_candidacy(mid, 100, 40, 100, 5)

        # Run the same sweep logic as main.py POST /memory/sweep (live mode)
        import sys
        from pathlib import Path
        _MEMORY_AGENT = str(Path(__file__).resolve().parents[2] / "agents" / "memory")
        if _MEMORY_AGENT not in sys.path:
            sys.path.insert(0, _MEMORY_AGENT)
        from main import _assess_candidate_drift

        memories = store.active_or_candidate_memories()
        for mem in memories:
            if mem["id"] != mid:
                continue
            drift = _assess_candidate_drift(mid, mem)
            store.update_drift_score(mid, drift["drift_score_pct"])
            plan = drift_stats.plan_action(mem["memory_status"], drift["level"])
            if plan["action"] == "promote":
                store.transition_memory(mid, "active", actor="self-improve")

        updated = store.get_memory(mid)
        assert updated["memory_status"] == "active", (
            f"Expected 'active' after live sweep but got {updated['memory_status']!r} "
            "(mem-5 regression: candidate not promoted)"
        )

    def test_candidate_no_outcomes_still_insufficient_data(self):
        """Candidate with zero outcomes → insufficient_data (not regression)."""
        mid = _make_candidate("mem5-no-outcomes")

        import sys
        from pathlib import Path
        _MEMORY_AGENT = str(Path(__file__).resolve().parents[2] / "agents" / "memory")
        if _MEMORY_AGENT not in sys.path:
            sys.path.insert(0, _MEMORY_AGENT)
        from main import _assess_candidate_drift

        mem = store.get_memory(mid)
        drift = _assess_candidate_drift(mid, mem)
        assert drift["level"] == "insufficient_data"


# ---------------------------------------------------------------------------
# mem-6: confidence adjustment must converge (not keep decrementing each sweep)
# ---------------------------------------------------------------------------

class TestMem6ConfidenceConverges:
    """mem-6: running the live sweep 5x on unchanged outcomes must NOT keep
    decrementing confidence — it must converge to a stable target."""

    def _run_sweep_once(self, memories):
        """Mirror the live adjust_confidence branch from main.py."""
        import sys
        from pathlib import Path
        _MEMORY_AGENT = str(Path(__file__).resolve().parents[2] / "agents" / "memory")
        if _MEMORY_AGENT not in sys.path:
            sys.path.insert(0, _MEMORY_AGENT)

        for mem in memories:
            memory_id = mem["id"]
            memory_status = mem["memory_status"]

            try:
                drift = store.assess_memory_drift(memory_id)
            except Exception:
                continue

            store.update_drift_score(memory_id, drift["drift_score_pct"])
            plan = drift_stats.plan_action(memory_status, drift["level"])
            action = plan["action"]

            if action == "adjust_confidence":
                cur = mem.get("confidence_pct")
                if cur is None:
                    cur = 50
                if drift["level"] == "watch":
                    target = 40
                elif drift["level"] == "improving":
                    target = 80
                else:
                    target = cur

                if target != cur:
                    import psycopg as _psycopg
                    with _psycopg.connect(_PG_DSN) as conn:
                        conn.execute(
                            "UPDATE agent_memory SET confidence_pct = %s, updated_at = now() WHERE id = %s",
                            (target, memory_id),
                        )
                        conn.commit()

    def test_watch_memory_confidence_converges_not_decrements(self):
        """A 'watch'-level active memory's confidence should converge to 40, not
        keep decrementing toward 0 on each sweep."""
        mid = _make_active("mem6-watch-converge", confidence_pct=70)
        # Seed borderline-watch outcomes: 10/100 before, 20/100 after
        _seed_outcomes_around_promotion(mid, 100, 10, 100, 20)

        # Run 5 sweeps
        confidences = []
        for _ in range(5):
            memories = store.active_or_candidate_memories()
            self._run_sweep_once(memories)
            updated = store.get_memory(mid)
            confidences.append(updated["confidence_pct"])

        # After the first adjustment the value must stabilize — not keep dropping
        final = confidences[-1]
        # All sweeps after the first should have the same value (idempotent)
        assert confidences[-1] == confidences[-2] == confidences[-3], (
            f"Confidence should converge but kept changing: {confidences} "
            "(mem-6 regression: confidence not idempotent under repeated sweep)"
        )
        # The final value must be positive (not driven to 0)
        assert final > 0, f"Confidence was driven to 0: {confidences}"

    def test_sweep_idempotent_no_outcomes_no_change(self):
        """An active memory with no outcomes gets insufficient_data → action=None → confidence unchanged."""
        mid = _make_active("mem6-no-outcomes", confidence_pct=60)
        initial = store.get_memory(mid)["confidence_pct"]

        memories = store.active_or_candidate_memories()
        for _ in range(3):
            self._run_sweep_once(memories)

        final = store.get_memory(mid)["confidence_pct"]
        assert final == initial, f"Confidence changed on no-outcomes memory: {initial} → {final}"


# ---------------------------------------------------------------------------
# mem-8: POST /memory catches UniqueViolation / IntegrityError → 409, not 500
# ---------------------------------------------------------------------------

class TestMem8UniqueViolation409:
    """mem-8: version-bump race (UniqueViolation) at the endpoint returns 409 Conflict,
    not an unhandled 500, as defense-in-depth around the store-layer retry."""

    def test_unique_violation_returns_409(self, monkeypatch):
        """Monkeypatching store.upsert_memory to raise UniqueViolation → endpoint returns 409."""
        import psycopg.errors as _pe

        def _raise_unique(*args, **kwargs):
            # psycopg.errors.UniqueViolation needs a pgcode; construct via base class
            exc = _pe.UniqueViolation()
            raise exc

        monkeypatch.setattr(store, "upsert_memory", _raise_unique)

        from fastapi.testclient import TestClient
        client = TestClient(_memory_main.app)

        resp = client.post("/memory", json={
            "agent_slug": "test-agent",
            "key": "test-key",
            "value": "test-value",
        })
        assert resp.status_code == 409, (
            f"Expected 409 for UniqueViolation, got {resp.status_code}: {resp.text}. "
            "mem-8: endpoint must catch psycopg UniqueViolation as 409."
        )
        assert "retry" in resp.json().get("detail", "").lower(), (
            f"Expected 'retry' in detail, got: {resp.json()}"
        )

    def test_integrity_error_returns_409(self, monkeypatch):
        """Monkeypatching store.upsert_memory to raise IntegrityError → endpoint returns 409."""
        import psycopg.errors as _pe

        def _raise_integrity(*args, **kwargs):
            raise _pe.IntegrityError()

        monkeypatch.setattr(store, "upsert_memory", _raise_integrity)

        from fastapi.testclient import TestClient
        client = TestClient(_memory_main.app)

        resp = client.post("/memory", json={
            "agent_slug": "test-agent",
            "key": "test-key",
            "value": "test-value",
        })
        assert resp.status_code == 409, (
            f"Expected 409 for IntegrityError, got {resp.status_code}: {resp.text}. "
            "mem-8: endpoint must catch psycopg IntegrityError as 409."
        )

    def test_normal_upsert_still_returns_200(self):
        """Baseline: a normal upsert still returns 200 (regression guard)."""
        from fastapi.testclient import TestClient
        client = TestClient(_memory_main.app)

        resp = client.post("/memory", json={
            "agent_slug": "mem8-sanity",
            "key": "sanity-key",
            "value": {"ok": True},
        })
        assert resp.status_code == 200, (
            f"Expected 200 for normal upsert, got {resp.status_code}: {resp.text}"
        )
