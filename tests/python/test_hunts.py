"""
test_hunts.py -- Acceptance tests for agents/hunter/main.py + store hunt functions.

Covers SLICE6.md acceptance criteria:
  1. Hunt registry: init registers built-in templates; GET /hunts lists >=6; GET /hunts/{id}.
  2. due_hunts(now): pure function with injected clock.
     - Never-run enabled hunt -> due.
     - Ran 1h ago with 24h interval -> NOT due.
     - Ran 25h ago with 24h interval -> due.
     - Disabled hunt -> never due.
  3. POST /hunts/{id}/run with FakeInvestigatorClient -> hunt_run recorded,
     list_hunt_runs shows investigation_run_id + mitre_technique; last_run_at set.
  4. scheduler_tick with injected clock + fake client: runs exactly the 2 due,
     skips the 1 disabled.
  5. Investigator failure -> POST /run returns 502; last_run_at NOT updated.
  6. enable/disable toggles reflected in due_hunts.

Requires live Postgres+pgvector. Module skipped if PG_DSN unreachable.
No real investigator, no Athena, no Gemini.
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
    import psycopg as _psycopg_check
    _conn_check = _psycopg_check.connect(_PG_DSN, connect_timeout=3)
    _conn_check.close()
except Exception as _pg_exc:
    pytest.skip(f"no postgres: {_pg_exc}", allow_module_level=True)

# ---------------------------------------------------------------------------
# Env setup -- BEFORE any agent imports
# ---------------------------------------------------------------------------
os.environ["PG_DSN"] = _PG_DSN
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("OTEL_CONSOLE_TRACES", "false")
os.environ.setdefault("GEMINI_API_KEY", "test-dummy-key")
os.environ.setdefault("LLM_PROVIDER", "gemini")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
# Disable background scheduler loop -- tests inject the client directly
os.environ["HUNTER_AUTORUN"] = "0"

_REPO = Path(__file__).resolve().parents[2]
_SHARED = str(_REPO / "agents" / "shared")
_HUNTER = str(_REPO / "agents" / "hunter")
for _p in [_SHARED, _HUNTER]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Load hunter main via conftest helper
# ---------------------------------------------------------------------------
from conftest import load_agent_main  # noqa: E402

hunter_main = load_agent_main("hunter", "hunter_main")

import store  # noqa: E402
import psycopg  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from hunt_templates import HUNT_TEMPLATES  # noqa: E402

# ---------------------------------------------------------------------------
# Fixed base datetime for clock injection -- never call now() in asserts
# ---------------------------------------------------------------------------
_BASE = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Fake InvestigatorClient implementations
# ---------------------------------------------------------------------------


class FakeInvestigatorClient:
    """Returns a scripted finding for testing."""

    def __init__(self, scripted_finding: dict):
        self._finding = scripted_finding

    async def investigate(self, query: str, window_hours: int = 24) -> dict:
        return self._finding


class FailingInvestigatorClient:
    """Always raises to simulate investigator being down."""

    async def investigate(self, query: str, window_hours: int = 24) -> dict:
        raise RuntimeError("investigator is down")


_THREAT_FINDING = {
    "run_id": "fake-hunt-run-001",
    "finding": {
        "verdict": "threat",
        "severity": "high",
        "summary": "Suspicious C2 beaconing detected on port 4444.",
        "recommendation": "Isolate host and block external IP.",
    },
}

_BENIGN_FINDING = {
    "run_id": "fake-hunt-run-002",
    "finding": {
        "verdict": "benign",
        "severity": "informational",
        "summary": "No anomalous activity detected.",
    },
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_hunt_tables():
    """Ensure schema exists and truncate hunt tables before each test."""
    store.init_schema()
    with psycopg.connect(_PG_DSN) as conn:
        conn.execute("TRUNCATE hunt_runs, hunts RESTART IDENTITY CASCADE")
        conn.commit()
    yield


def _client_with(investigator_client=None) -> TestClient:
    """Build a TestClient with an injected InvestigatorClient."""
    # Re-register templates since we truncated the table
    store.register_hunts(HUNT_TEMPLATES)
    client = TestClient(hunter_main.app, raise_server_exceptions=True)
    if investigator_client is not None:
        hunter_main.app.state.investigator_client = investigator_client
    else:
        if hasattr(hunter_main.app.state, "investigator_client"):
            del hunter_main.app.state.investigator_client
    return client


# ---------------------------------------------------------------------------
# 1. Hunt registry
# ---------------------------------------------------------------------------


class TestHuntRegistry:
    def test_list_hunts_returns_builtins(self):
        """GET /hunts returns at least 6 hunt templates."""
        client = _client_with()
        resp = client.get("/hunts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 6
        assert len(data["hunts"]) >= 6

    def test_list_hunts_has_required_fields(self):
        """Each hunt has the required MITRE-mapped fields."""
        client = _client_with()
        resp = client.get("/hunts")
        for hunt in resp.json()["hunts"]:
            assert "id" in hunt
            assert "name" in hunt
            assert "mitre_tactic" in hunt
            assert "mitre_technique" in hunt
            assert "hunt_query" in hunt
            assert "enabled" in hunt
            assert "interval_hours" in hunt

    def test_get_hunt_by_id(self):
        """GET /hunts/{id} returns the correct hunt."""
        client = _client_with()
        hunt_id = "c2-non-standard-port"
        resp = client.get(f"/hunts/{hunt_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == hunt_id
        assert "T1571" in data["mitre_technique"]

    def test_get_hunt_404_for_missing(self):
        client = _client_with()
        resp = client.get("/hunts/does-not-exist")
        assert resp.status_code == 404

    def test_register_hunts_idempotent(self):
        """Calling register_hunts twice does not duplicate rows."""
        store.register_hunts(HUNT_TEMPLATES)
        store.register_hunts(HUNT_TEMPLATES)
        hunts = store.list_hunts()
        ids = [h["id"] for h in hunts]
        assert len(ids) == len(set(ids)), "duplicate hunt ids after double register"

    def test_register_preserves_enabled_on_conflict(self):
        """Re-registering a template does not clobber a disabled flag."""
        store.register_hunts(HUNT_TEMPLATES)
        store.set_hunt_enabled("c2-non-standard-port", False)
        # Re-register (simulates service restart)
        store.register_hunts(HUNT_TEMPLATES)
        hunt = store.get_hunt("c2-non-standard-port")
        assert hunt is not None
        assert hunt["enabled"] is False, "enabled flag was clobbered by re-register"


# ---------------------------------------------------------------------------
# 2. due_hunts -- pure function with injected clock
# ---------------------------------------------------------------------------


class TestDueHunts:
    def test_never_run_enabled_hunt_is_due(self):
        """An enabled hunt that has never run is always due."""
        store.register_hunts(HUNT_TEMPLATES)
        due_ids = [h["id"] for h in store.due_hunts(_BASE)]
        # All templates start with last_run_at=NULL so all should be due
        assert len(due_ids) >= 6

    def test_just_ran_hunt_not_due(self):
        """A hunt run 1h ago with interval 24h is NOT yet due."""
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        # Mark as run at base time
        store.mark_hunt_ran(hunt_id, _BASE)
        # Check 1 hour later -- interval is 6h, so NOT due
        due_ids = [h["id"] for h in store.due_hunts(_BASE + timedelta(hours=1))]
        assert hunt_id not in due_ids

    def test_overdue_hunt_is_due(self):
        """A hunt run at base, checked at base+interval+1h is due."""
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None
        interval = hunt["interval_hours"]  # 6
        store.mark_hunt_ran(hunt_id, _BASE)
        # One hour past the interval deadline
        due_ids = [h["id"] for h in store.due_hunts(_BASE + timedelta(hours=interval + 1))]
        assert hunt_id in due_ids

    def test_just_at_deadline_is_due(self):
        """A hunt checked exactly at last_run_at + interval_hours is due."""
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None
        interval = hunt["interval_hours"]
        store.mark_hunt_ran(hunt_id, _BASE)
        due_ids = [h["id"] for h in store.due_hunts(_BASE + timedelta(hours=interval))]
        assert hunt_id in due_ids

    def test_disabled_hunt_never_due(self):
        """A disabled hunt is never returned by due_hunts regardless of last_run_at."""
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        store.set_hunt_enabled(hunt_id, False)
        # Even if never run
        due_ids = [h["id"] for h in store.due_hunts(_BASE)]
        assert hunt_id not in due_ids

    def test_due_hunts_uses_injected_now_not_wall_clock(self):
        """Passing a far-past now returns an empty list for recently-run hunts."""
        store.register_hunts(HUNT_TEMPLATES)
        # Mark all hunts as run at _BASE
        for hunt in store.list_hunts():
            store.mark_hunt_ran(hunt["id"], _BASE)
        # Ask for due hunts 1 second BEFORE the base -- none should be due
        # (last_run_at==_BASE and now < _BASE means all are in the future)
        past_now = _BASE - timedelta(seconds=1)
        due = store.due_hunts(past_now)
        assert due == [], f"expected empty due list, got: {[h['id'] for h in due]}"

    def test_24h_interval_scenario(self):
        """Scenario matching the SLICE6 spec: 24h interval, 1h later not due, 25h later due."""
        # Use exfil hunt which has 24h interval
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "exfil-large-outbound"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None
        assert hunt["interval_hours"] == 24

        store.mark_hunt_ran(hunt_id, _BASE)

        # 1h later -- not due
        due_1h = [h["id"] for h in store.due_hunts(_BASE + timedelta(hours=1))]
        assert hunt_id not in due_1h, "hunt should NOT be due 1h after running (24h interval)"

        # 25h later -- due
        due_25h = [h["id"] for h in store.due_hunts(_BASE + timedelta(hours=25))]
        assert hunt_id in due_25h, "hunt SHOULD be due 25h after running (24h interval)"


# ---------------------------------------------------------------------------
# 3. POST /hunts/{id}/run -- full run flow
# ---------------------------------------------------------------------------


class TestRunHunt:
    def test_run_threat_finding_records_hunt_run(self):
        """POST /run with a threat finding records the hunt_run and links the run_id."""
        client = _client_with(FakeInvestigatorClient(_THREAT_FINDING))
        hunt_id = "c2-non-standard-port"

        resp = client.post(f"/hunts/{hunt_id}/run")
        assert resp.status_code == 200
        data = resp.json()
        assert "hunt_run_id" in data
        assert data["investigation_run_id"] == "fake-hunt-run-001"
        assert data["finding"]["verdict"] == "threat"
        assert "T1571" in data["mitre_technique"]

    def test_run_records_run_in_list_hunt_runs(self):
        """After a successful run, list_hunt_runs shows the new row."""
        client = _client_with(FakeInvestigatorClient(_THREAT_FINDING))
        hunt_id = "c2-non-standard-port"

        resp = client.post(f"/hunts/{hunt_id}/run")
        assert resp.status_code == 200
        hunt_run_id = resp.json()["hunt_run_id"]

        runs_resp = client.get(f"/hunts/runs?hunt_id={hunt_id}")
        assert runs_resp.status_code == 200
        runs = runs_resp.json()["runs"]
        assert len(runs) >= 1
        run = runs[0]
        assert run["id"] == hunt_run_id
        assert run["investigation_run_id"] == "fake-hunt-run-001"
        assert run["verdict"] == "threat"
        assert run["severity"] == "high"
        assert "T1571" in run["mitre_technique"]

    def test_run_sets_last_run_at(self):
        """After a successful run, the hunt's last_run_at is set."""
        client = _client_with(FakeInvestigatorClient(_THREAT_FINDING))
        hunt_id = "c2-non-standard-port"

        # Confirm last_run_at starts as None
        hunt_before = store.get_hunt(hunt_id)
        assert hunt_before is not None
        assert hunt_before["last_run_at"] is None

        resp = client.post(f"/hunts/{hunt_id}/run")
        assert resp.status_code == 200

        hunt_after = store.get_hunt(hunt_id)
        assert hunt_after is not None
        assert hunt_after["last_run_at"] is not None, "last_run_at should be set after run"

    def test_run_404_for_missing_hunt(self):
        client = _client_with(FakeInvestigatorClient(_THREAT_FINDING))
        resp = client.post("/hunts/does-not-exist/run")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 4. scheduler_tick -- pure function with injected clock + fake client
# ---------------------------------------------------------------------------


class TestSchedulerTick:
    def test_scheduler_tick_runs_due_hunts(self):
        """scheduler_tick with 2 due + 1 disabled runs exactly the 2 due hunts."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)

        # Disable all but two specific hunts, and disable a third explicitly
        all_hunts = store.list_hunts()
        for hunt in all_hunts:
            store.set_hunt_enabled(hunt["id"], False)

        hunt_a = "c2-non-standard-port"
        hunt_b = "exfil-large-outbound"
        hunt_disabled = "credential-brute-force"

        store.set_hunt_enabled(hunt_a, True)
        store.set_hunt_enabled(hunt_b, True)
        store.set_hunt_enabled(hunt_disabled, False)

        fake_client = FakeInvestigatorClient(_BENIGN_FINDING)
        ran = asyncio.run(hunter_main.scheduler_tick(_BASE, fake_client))

        assert set(ran) == {hunt_a, hunt_b}, f"expected {{hunt_a, hunt_b}}, got {ran}"

    def test_scheduler_tick_records_hunt_runs(self):
        """Each hunt run by the scheduler gets a hunt_run row."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)

        # Enable only one hunt
        all_hunts = store.list_hunts()
        for hunt in all_hunts:
            store.set_hunt_enabled(hunt["id"], False)
        hunt_id = "c2-non-standard-port"
        store.set_hunt_enabled(hunt_id, True)

        fake_client = FakeInvestigatorClient(_THREAT_FINDING)
        ran = asyncio.run(hunter_main.scheduler_tick(_BASE, fake_client))

        assert hunt_id in ran
        runs = store.list_hunt_runs(hunt_id=hunt_id)
        assert len(runs) == 1
        assert runs[0]["investigation_run_id"] == "fake-hunt-run-001"

    def test_scheduler_tick_skips_disabled(self):
        """Disabled hunts are never in the scheduler_tick output."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)
        # Disable all hunts
        for hunt in store.list_hunts():
            store.set_hunt_enabled(hunt["id"], False)

        fake_client = FakeInvestigatorClient(_BENIGN_FINDING)
        ran = asyncio.run(hunter_main.scheduler_tick(_BASE, fake_client))
        assert ran == [], f"expected no runs, got {ran}"


# ---------------------------------------------------------------------------
# 5. Investigator failure -> 502, last_run_at NOT updated
# ---------------------------------------------------------------------------


class TestInvestigatorFailure:
    def test_investigator_failure_returns_502(self):
        """If the investigator raises, POST /run returns 502."""
        client = _client_with(FailingInvestigatorClient())
        resp = client.post("/hunts/c2-non-standard-port/run")
        assert resp.status_code == 502
        assert "investigator" in resp.json()["detail"].lower()

    def test_investigator_failure_does_not_set_last_run_at(self):
        """On investigator failure, last_run_at is NOT updated (so the hunt retries)."""
        client = _client_with(FailingInvestigatorClient())
        hunt_id = "c2-non-standard-port"

        resp = client.post(f"/hunts/{hunt_id}/run")
        assert resp.status_code == 502

        hunt = store.get_hunt(hunt_id)
        assert hunt is not None
        assert hunt["last_run_at"] is None, (
            "last_run_at must remain None after investigator failure so the hunt retries"
        )

    def test_investigator_failure_records_no_hunt_run(self):
        """On investigator failure, no hunt_run row is created."""
        client = _client_with(FailingInvestigatorClient())
        hunt_id = "c2-non-standard-port"
        client.post(f"/hunts/{hunt_id}/run")
        runs = store.list_hunt_runs(hunt_id=hunt_id)
        assert runs == [], "no hunt_run should be recorded on investigator failure"

    def test_scheduler_tick_continues_after_failure(self):
        """scheduler_tick logs the failure but continues running other hunts."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)

        all_hunts = store.list_hunts()
        for hunt in all_hunts:
            store.set_hunt_enabled(hunt["id"], False)

        hunt_a = "c2-non-standard-port"  # will fail
        hunt_b = "exfil-large-outbound"  # will succeed
        store.set_hunt_enabled(hunt_a, True)
        store.set_hunt_enabled(hunt_b, True)

        # Failing client for hunt_a, but we share one client -- both use same client
        # To test continuation we can use a selective fake
        class SelectiveFakeClient:
            async def investigate(self, query: str, window_hours: int = 24) -> dict:
                if "exfil" in query.lower() or "100 mb" in query.lower() or "transfer" in query.lower():
                    return _BENIGN_FINDING
                raise RuntimeError("investigator down for c2 hunt")

        ran = asyncio.run(hunter_main.scheduler_tick(_BASE, SelectiveFakeClient()))
        # hunt_b should have run; hunt_a failed but didn't block hunt_b
        assert hunt_b in ran


# ---------------------------------------------------------------------------
# 6. enable/disable toggles
# ---------------------------------------------------------------------------


class TestEnableDisable:
    def test_disable_removes_from_due_hunts(self):
        """Disabling a hunt removes it from due_hunts."""
        client = _client_with()
        hunt_id = "c2-non-standard-port"

        # Currently enabled, never run -> should be due
        due_before = [h["id"] for h in store.due_hunts(_BASE)]
        assert hunt_id in due_before

        # Disable
        resp = client.post(f"/hunts/{hunt_id}/disable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

        due_after = [h["id"] for h in store.due_hunts(_BASE)]
        assert hunt_id not in due_after

    def test_enable_adds_back_to_due_hunts(self):
        """Re-enabling a disabled hunt adds it back to due_hunts."""
        client = _client_with()
        hunt_id = "c2-non-standard-port"

        client.post(f"/hunts/{hunt_id}/disable")
        due_disabled = [h["id"] for h in store.due_hunts(_BASE)]
        assert hunt_id not in due_disabled

        resp = client.post(f"/hunts/{hunt_id}/enable")
        assert resp.status_code == 200
        assert resp.json()["enabled"] is True

        due_enabled = [h["id"] for h in store.due_hunts(_BASE)]
        assert hunt_id in due_enabled

    def test_enable_404_for_missing(self):
        client = _client_with()
        resp = client.post("/hunts/does-not-exist/enable")
        assert resp.status_code == 404

    def test_disable_404_for_missing(self):
        client = _client_with()
        resp = client.post("/hunts/does-not-exist/disable")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# hnt-1 — interval_hours clamp
# ---------------------------------------------------------------------------


class TestIntervalHoursClamp:
    def test_zero_interval_clamped_to_one(self):
        """hnt-1: A hunt registered with interval_hours=0 is clamped to 1."""
        store.register_hunts([{
            "id": "test-zero-interval",
            "name": "Zero Interval Hunt",
            "mitre_tactic": "TA0001",
            "mitre_technique": "T9999",
            "hypothesis": "test",
            "hunt_query": "SELECT 1",
            "enabled": True,
            "interval_hours": 0,
        }])
        hunt = store.get_hunt("test-zero-interval")
        assert hunt is not None
        assert hunt["interval_hours"] >= 1, (
            f"interval_hours should be clamped to >= 1, got {hunt['interval_hours']}"
        )

    def test_zero_interval_hunt_not_due_every_tick(self):
        """hnt-1: A hunt with interval_hours=0 (clamped to 1) is NOT due again right after running."""
        store.register_hunts([{
            "id": "test-zero-interval-due",
            "name": "Zero Interval Due Hunt",
            "mitre_tactic": "TA0001",
            "mitre_technique": "T9999",
            "hypothesis": "test",
            "hunt_query": "SELECT 1",
            "enabled": True,
            "interval_hours": 0,
        }])
        # Mark as run right at _BASE
        store.mark_hunt_ran("test-zero-interval-due", _BASE)
        # Check 1 second later — with interval clamped to 1h, should NOT be due
        due_ids = [h["id"] for h in store.due_hunts(_BASE + timedelta(seconds=1))]
        assert "test-zero-interval-due" not in due_ids, (
            "hunt with interval_hours=0 should not be due 1 second after running (clamped to 1h)"
        )


# ---------------------------------------------------------------------------
# hnt-3 — record_hunt_run_and_mark atomicity
# ---------------------------------------------------------------------------


class TestRecordHuntRunAndMark:
    def test_atomic_record_advances_both(self):
        """hnt-3: record_hunt_run_and_mark advances hunt_run row AND last_run_at in one call."""
        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"

        hunt_before = store.get_hunt(hunt_id)
        assert hunt_before is not None
        assert hunt_before["last_run_at"] is None

        ran_at = _BASE
        run_id = store.record_hunt_run_and_mark(
            hunt_id=hunt_id,
            investigation_run_id="fake-atomic-run-001",
            verdict="benign",
            severity="informational",
            mitre_technique=hunt_before["mitre_technique"],
            summary="atomic test",
            ran_at=ran_at,
        )

        # hunt_run row must exist
        runs = store.list_hunt_runs(hunt_id=hunt_id)
        assert len(runs) == 1
        assert runs[0]["id"] == run_id
        assert runs[0]["investigation_run_id"] == "fake-atomic-run-001"

        # last_run_at must be advanced
        hunt_after = store.get_hunt(hunt_id)
        assert hunt_after is not None
        assert hunt_after["last_run_at"] is not None, "last_run_at should be set"
        # Normalize timezone for comparison
        last = hunt_after["last_run_at"]
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        assert last == ran_at, f"expected last_run_at={ran_at}, got {last}"


# ---------------------------------------------------------------------------
# hnt-2 — in-flight concurrency guard
# ---------------------------------------------------------------------------


class TestInflightGuard:
    def test_second_concurrent_run_skipped(self):
        """hnt-2: Simulating a second run of the same hunt_id while one is in-flight -> skipped."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None

        # Manually add the hunt to the in-flight set to simulate a concurrent run
        hunter_main._inflight_hunts.add(hunt_id)
        try:
            with pytest.raises(RuntimeError, match="already in-flight"):
                asyncio.run(hunter_main._run_hunt_core(hunt, FakeInvestigatorClient(_BENIGN_FINDING)))
        finally:
            hunter_main._inflight_hunts.discard(hunt_id)

    def test_inflight_set_cleared_after_success(self):
        """hnt-2: After a successful run, hunt_id is removed from _inflight_hunts."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None

        asyncio.run(hunter_main._run_hunt_core(hunt, FakeInvestigatorClient(_BENIGN_FINDING)))
        assert hunt_id not in hunter_main._inflight_hunts, (
            "hunt_id should be removed from _inflight_hunts after successful run"
        )

    def test_inflight_set_cleared_after_failure(self):
        """hnt-2: Even on investigator failure, hunt_id is removed from _inflight_hunts."""
        import asyncio

        store.register_hunts(HUNT_TEMPLATES)
        hunt_id = "c2-non-standard-port"
        hunt = store.get_hunt(hunt_id)
        assert hunt is not None

        with pytest.raises(RuntimeError):
            asyncio.run(hunter_main._run_hunt_core(hunt, FailingInvestigatorClient()))
        assert hunt_id not in hunter_main._inflight_hunts, (
            "hunt_id should be removed from _inflight_hunts even after failure"
        )


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHealth:
    def test_health(self):
        client = _client_with()
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "hunter"
        assert "autorun" in data
        # In tests, HUNTER_AUTORUN=0 so autorun should be False
        assert data["autorun"] is False
