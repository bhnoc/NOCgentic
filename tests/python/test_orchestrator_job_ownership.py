"""CodeMender 39f25da0: /hints/{job_id} and /lanes/{job_id} lacked any
per-job ownership check, unlike the web-server's /api/v1/chat/:id (which
refuses to serve a job to anyone but the bh_sid session that created it).

A caller who could reach the orchestrator's internal port (compose
expose-only, not published, but a defense-in-depth gap regardless) and knew
or guessed a job_id could read another session's full hints/lane data.

Fix mirrors packages/web-server/src/api/chat.ts's jobOwners /
jobOwnedByRequester pattern: record the owning session at /query time, gate
the two GET routes on an X-Session-Id header the web-server now forwards, and
keep the SAME lenient rule for cookie-less/unowned jobs (curl, health checks)
that the web-server already applies.

Response shape must not leak "job exists but isn't yours" as distinct from
"no data yet" / "unknown job" -- both endpoints degrade a foreign job to the
same shape as an empty one, not a 404/403.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from conftest import load_agent_main

_orch = load_agent_main("orchestrator", "orch_main")


@pytest.fixture(autouse=True)
def _clean_job_ownership_state():
    _orch._job_owners.clear()
    _orch._hints_cache.clear()
    _orch._lane_store.clear()
    yield
    _orch._job_owners.clear()
    _orch._hints_cache.clear()
    _orch._lane_store.clear()


@pytest.fixture
def client():
    return TestClient(_orch.app)


# ---------------------------------------------------------------------------
# _job_owned_by: the predicate itself
# ---------------------------------------------------------------------------

def test_unowned_job_is_readable_by_anyone():
    """A job created without a session cookie (curl, health check) has no
    recorded owner and must stay readable -- same rule as jobOwnedByRequester
    on the web-server side."""
    assert _orch._job_owned_by("no-such-job", None) is True
    assert _orch._job_owned_by("no-such-job", "some-session") is True


def test_owned_job_requires_matching_session():
    _orch._record_job_owner("job-1", "sid-A")
    assert _orch._job_owned_by("job-1", "sid-A") is True
    assert _orch._job_owned_by("job-1", "sid-B") is False
    assert _orch._job_owned_by("job-1", None) is False


def test_record_job_owner_ignores_missing_session():
    """REVERT-CHECK: without the `if not session_id: return` guard, a
    cookie-less job would record owner=None and then _job_owned_by would
    compare `session_id == None`, locking a real session OUT of a job it
    never had a recorded owner for in the first place."""
    _orch._record_job_owner("job-2", None)
    assert "job-2" not in _orch._job_owners
    assert _orch._job_owned_by("job-2", "anyone") is True


# ---------------------------------------------------------------------------
# /hints/{job_id}: through the real HTTP route
# ---------------------------------------------------------------------------

class TestHintsEndpointOwnership:
    def test_foreign_session_gets_pending_not_the_real_hints(self, client):
        """REVERT-CHECK: before this fix, /hints/{job_id} ignored the caller
        entirely and this would return status=ready with the victim's real
        hints. This test would FAIL (hints leaked) if the ownership check on
        get_hints were removed."""
        _orch._record_job_owner("victim-job", "victim-sid")
        _orch._hints_cache["victim-job"] = ["do the secret follow-up hunt"]

        resp = client.get("/hints/victim-job", headers={"X-Session-Id": "attacker-sid"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "pending"
        assert body["hints"] == []

    def test_owning_session_gets_the_real_hints(self, client):
        _orch._record_job_owner("victim-job", "victim-sid")
        _orch._hints_cache["victim-job"] = ["do the secret follow-up hunt"]

        resp = client.get("/hints/victim-job", headers={"X-Session-Id": "victim-sid"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ready"
        assert body["hints"] == ["do the secret follow-up hunt"]

    def test_no_session_header_on_unowned_job_still_works(self, client):
        """A job with no recorded owner (created cookie-less) must stay
        readable by a caller sending no X-Session-Id at all."""
        _orch._hints_cache["curl-job"] = ["fallback hint"]
        resp = client.get("/hints/curl-job")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ready", "hints": ["fallback hint"]}


# ---------------------------------------------------------------------------
# /lanes/{job_id}: through the real HTTP route
# ---------------------------------------------------------------------------

class TestLanesEndpointOwnership:
    def test_foreign_session_gets_done_empty_not_the_real_lanes(self, client):
        """REVERT-CHECK: before this fix, /lanes/{job_id} returned the
        victim's full lane pair (including both models' raw answers) to any
        caller who knew the job_id. This test would FAIL (lanes leaked) if
        the ownership check on get_lanes were removed."""
        _orch._record_job_owner("victim-job", "victim-sid")
        _orch._lane_store["victim-job"] = {
            "status": "done",
            "lanes": [
                _orch._lane_result(
                    _orch.LANE_CLOUD, answer="the secret answer", confidence=0.9,
                    agent_used="athena-hunter", data=None, elapsed_ms=100.0, winner=True,
                ),
            ],
        }

        resp = client.get("/lanes/victim-job", headers={"X-Session-Id": "attacker-sid"})
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"status": "done", "lanes": []}

    def test_owning_session_gets_the_real_lanes(self, client):
        _orch._record_job_owner("victim-job", "victim-sid")
        _orch._lane_store["victim-job"] = {
            "status": "done",
            "lanes": [
                _orch._lane_result(
                    _orch.LANE_CLOUD, answer="the secret answer", confidence=0.9,
                    agent_used="athena-hunter", data=None, elapsed_ms=100.0, winner=True,
                ),
            ],
        }

        resp = client.get("/lanes/victim-job", headers={"X-Session-Id": "victim-sid"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "done"
        assert len(body["lanes"]) == 1
        assert body["lanes"][0]["answer"] == "the secret answer"

    def test_no_session_header_on_unowned_job_still_works(self, client):
        _orch._lane_store["curl-job"] = {
            "status": "done",
            "lanes": [
                _orch._lane_result(
                    _orch.LANE_CLOUD, answer="fallback answer", confidence=0.5,
                    agent_used="athena-hunter", data=None, elapsed_ms=50.0, winner=True,
                ),
            ],
        }
        resp = client.get("/lanes/curl-job")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "done"
        assert body["lanes"][0]["answer"] == "fallback answer"

    def test_unknown_job_id_still_returns_done_empty(self, client):
        """Unrelated to ownership: an unknown job_id (single-lane box, never
        raced) must keep returning done+empty, not 404 -- unchanged
        pre-existing behaviour."""
        resp = client.get("/lanes/never-heard-of-it")
        assert resp.status_code == 200
        assert resp.json() == {"status": "done", "lanes": []}
