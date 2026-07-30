"""
test_triage.py — Acceptance tests for agents/triage/main.py

Covers all SLICE3.md acceptance criteria:
  1. POST /alerts single + batch; dedup: repeat -> count==2.
  2. GET /triage/queue ordered by severity desc.
  3. Full investigate->verdict->two-transitions flow with linked run_id.
     FakeInvestigatorClient returns scripted findings.
  4. Analyst override: legal edge works; audit row written.
  5. Guard: illegal edge -> 409, no state change; unknown bucket -> 400;
     force=true on illegal edge -> succeeds AND writes audit row.
  6. Investigator failure -> 502, alert transitions back to 'alerts'.

Requires live Postgres+pgvector. Module skipped if PG_DSN unreachable.
No real investigator, no Athena, no Gemini.
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

# ---------------------------------------------------------------------------
# Env setup — BEFORE any agent imports
# ---------------------------------------------------------------------------
os.environ.setdefault("PG_DSN", _PG_DSN)
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("OTEL_CONSOLE_TRACES", "false")
os.environ.setdefault("GEMINI_API_KEY", "test-dummy-key")
os.environ.setdefault("LLM_PROVIDER", "gemini")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

_REPO = Path(__file__).resolve().parents[2]
_SHARED = str(_REPO / "agents" / "shared")
_TRIAGE = str(_REPO / "agents" / "triage")
for _p in [_SHARED, _TRIAGE]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Load triage main via conftest helper
# ---------------------------------------------------------------------------
from conftest import load_agent_main  # noqa: E402

triage_main = load_agent_main("triage", "triage_main")

import store  # noqa: E402
import psycopg  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

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
    """Always raises to test the 502 / retry path."""

    async def investigate(self, query: str, window_hours: int = 24) -> dict:
        raise RuntimeError("investigator is down")


# Standard scripted findings
_THREAT_FINDING = {
    "run_id": "fake-run-threat-001",
    "finding": {
        "verdict": "threat",
        "severity": "high",
        "summary": "Cobalt Strike beacon detected.",
        "recommendation": "Isolate host immediately.",
    },
    "evidence": {
        "high_signals": ["ET MALWARE CobaltStrike Beacon"],
        "queries": [],
    },
}

_BENIGN_FINDING = {
    "run_id": "fake-run-benign-001",
    "finding": {
        "verdict": "benign",
        "severity": "informational",
        "summary": "Normal scan activity.",
        "recommendation": "No action required.",
    },
    "evidence": {
        "high_signals": [],
        "queries": [],
    },
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_triage_tables():
    """Ensure schema exists and truncate triage tables before each test."""
    store.init_schema()
    with psycopg.connect(_PG_DSN) as conn:
        conn.execute(
            "TRUNCATE bucket_transitions, alerts RESTART IDENTITY CASCADE"
        )
        conn.commit()
    yield


def _client_with(investigator_client=None):
    """Build a TestClient with an injected InvestigatorClient (or default)."""
    client = TestClient(triage_main.app, raise_server_exceptions=True)
    if investigator_client is not None:
        triage_main.app.state.investigator_client = investigator_client
    else:
        # Remove any previously injected client
        if hasattr(triage_main.app.state, "investigator_client"):
            del triage_main.app.state.investigator_client
    return client


# ---------------------------------------------------------------------------
# Acceptance 1 — POST /alerts single + batch; dedup
# ---------------------------------------------------------------------------


class TestIngestAlerts:
    def test_single_alert(self):
        client = _client_with()
        resp = client.post("/alerts", json={
            "dedup_key": "sig1|1.2.3.4|5.6.7.8",
            "severity": 3,
            "signature": "ET SCAN",
            "source_ip": "1.2.3.4",
            "dest_ip": "5.6.7.8",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 1
        assert len(data["ids"]) == 1

    def test_batch_alerts(self):
        client = _client_with()
        resp = client.post("/alerts", json={"alerts": [
            {"dedup_key": "sig-a|1.1.1.1|2.2.2.2", "severity": 1},
            {"dedup_key": "sig-b|3.3.3.3|4.4.4.4", "severity": 2},
        ]})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ingested"] == 2
        assert len(data["ids"]) == 2

    def test_dedup_increments_count(self):
        """Posting the same dedup_key twice -> one row, count==2."""
        client = _client_with()
        resp1 = client.post("/alerts", json={
            "dedup_key": "et-scan|10.0.0.1|10.0.0.2",
            "severity": 2,
        })
        resp2 = client.post("/alerts", json={
            "dedup_key": "et-scan|10.0.0.1|10.0.0.2",
            "severity": 5,
        })
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Same id returned
        id1 = resp1.json()["ids"][0]
        id2 = resp2.json()["ids"][0]
        assert id1 == id2

        # Verify count==2 and severity upgraded
        alert = store.get_alert(id1)
        assert alert is not None
        assert alert["count"] == 2
        assert alert["severity"] == 5  # GREATEST applied

    def test_dedup_key_derived_if_absent(self):
        """If dedup_key is not provided, it's derived from signature|source|dest."""
        client = _client_with()
        resp = client.post("/alerts", json={
            "signature": "ET MALWARE",
            "source_ip": "192.168.1.1",
            "dest_ip": "8.8.8.8",
        })
        assert resp.status_code == 200
        assert resp.json()["ingested"] == 1


# ---------------------------------------------------------------------------
# Acceptance 2 — GET /triage/queue grouping/order
# ---------------------------------------------------------------------------


class TestTriageQueue:
    def test_ordered_by_severity_desc(self):
        """Insert 3 alerts with different severities -> queue ordered severity desc."""
        client = _client_with()
        for sev, key in [(1, "low-sev"), (5, "high-sev"), (3, "mid-sev")]:
            client.post("/alerts", json={"dedup_key": key, "severity": sev})

        resp = client.get("/triage/queue")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        severities = [a["severity"] for a in data["alerts"]]
        assert severities == sorted(severities, reverse=True)

    def test_filter_by_bucket(self):
        """Filtering by bucket=alerts returns only new alerts."""
        client = _client_with()
        client.post("/alerts", json={"dedup_key": "k1", "severity": 1})
        client.post("/alerts", json={"dedup_key": "k2", "severity": 2})

        resp = client.get("/triage/queue?bucket=alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        for a in data["alerts"]:
            assert a["bucket"] == "alerts"

    def test_filter_by_severity_min(self):
        """Filtering by severity>=3 excludes lower-severity alerts."""
        client = _client_with()
        client.post("/alerts", json={"dedup_key": "low", "severity": 1})
        client.post("/alerts", json={"dedup_key": "high", "severity": 4})

        resp = client.get("/triage/queue?severity=3")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["alerts"][0]["dedup_key"] == "high"


# ---------------------------------------------------------------------------
# Acceptance 3 — Full investigate flow with two transitions
# ---------------------------------------------------------------------------


class TestInvestigateFlow:
    def test_threat_finding_yields_true_positive(self):
        """FakeInvestigatorClient returns threat -> validated_true_positive + 2 transitions."""
        client = _client_with(FakeInvestigatorClient(_THREAT_FINDING))
        # Ingest alert
        resp = client.post("/alerts", json={
            "dedup_key": "beacon-test|192.168.1.100|1.2.3.4",
            "severity": 8,
            "signature": "ET MALWARE CobaltStrike",
            "source_ip": "192.168.1.100",
            "dest_ip": "1.2.3.4",
        })
        alert_id = resp.json()["ids"][0]

        # Investigate
        inv_resp = client.post(f"/triage/{alert_id}/investigate")
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()
        assert inv_data["verdict_bucket"] == "validated_true_positive"
        assert inv_data["investigation_run_id"] == "fake-run-threat-001"

        # Check two transitions recorded
        detail_resp = client.get(f"/triage/{alert_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        transitions = detail["transitions"]
        assert len(transitions) == 2

        assert transitions[0]["from_bucket"] == "alerts"
        assert transitions[0]["to_bucket"] == "validating"
        assert transitions[1]["from_bucket"] == "validating"
        assert transitions[1]["to_bucket"] == "validated_true_positive"
        assert transitions[1]["investigation_run_id"] == "fake-run-threat-001"

        # run_id linked
        assert "fake-run-threat-001" in detail["investigation_run_ids"]

    def test_benign_finding_yields_false_positive(self):
        """FakeInvestigatorClient returns benign -> validated_false_positive."""
        client = _client_with(FakeInvestigatorClient(_BENIGN_FINDING))
        resp = client.post("/alerts", json={
            "dedup_key": "benign-test|10.0.0.1|10.0.0.2",
            "severity": 2,
        })
        alert_id = resp.json()["ids"][0]

        inv_resp = client.post(f"/triage/{alert_id}/investigate")
        assert inv_resp.status_code == 200
        assert inv_resp.json()["verdict_bucket"] == "validated_false_positive"

        transitions = store.alert_transitions(alert_id)
        assert len(transitions) == 2
        assert transitions[-1]["to_bucket"] == "validated_false_positive"

    def test_high_signals_nonempty_overrides_benign_verdict(self):
        """verdict=='benign' but high_signals nonempty -> still true_positive."""
        finding = {
            "run_id": "fake-run-override-001",
            "finding": {"verdict": "benign", "severity": "medium"},
            "evidence": {"high_signals": ["ET SCAN Port Scan Detected"], "queries": []},
        }
        client = _client_with(FakeInvestigatorClient(finding))
        resp = client.post("/alerts", json={"dedup_key": "override-test|1.1.1.1|2.2.2.2"})
        alert_id = resp.json()["ids"][0]

        inv_resp = client.post(f"/triage/{alert_id}/investigate")
        assert inv_resp.status_code == 200
        assert inv_resp.json()["verdict_bucket"] == "validated_true_positive"

    def test_investigate_404_for_missing_alert(self):
        client = _client_with(FakeInvestigatorClient(_BENIGN_FINDING))
        resp = client.post("/triage/nonexistent-id/investigate")
        assert resp.status_code == 404

    def test_get_triage_detail_404(self):
        client = _client_with()
        resp = client.get("/triage/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Acceptance 4 — Analyst override: legal edge works; audit row written
# ---------------------------------------------------------------------------


class TestAnalystOverride:
    def test_legal_transition_succeeds(self):
        """validated_false_positive -> tuning_queue is a legal edge."""
        client = _client_with(FakeInvestigatorClient(_BENIGN_FINDING))
        resp = client.post("/alerts", json={"dedup_key": "override-legal|1.1.1.1|2.2.2.2"})
        alert_id = resp.json()["ids"][0]

        # Run investigate to reach validated_false_positive
        client.post(f"/triage/{alert_id}/investigate")

        # Analyst moves to tuning_queue
        t_resp = client.post(f"/triage/{alert_id}/transition", json={
            "to_bucket": "tuning_queue",
            "reason": "Rule needs tuning",
        })
        assert t_resp.status_code == 200
        data = t_resp.json()
        assert data["to_bucket"] == "tuning_queue"
        assert data["forced"] is False

        # Audit row present
        transitions = store.alert_transitions(alert_id)
        last = transitions[-1]
        assert last["from_bucket"] == "validated_false_positive"
        assert last["to_bucket"] == "tuning_queue"
        assert last["reason"] == "Rule needs tuning"

        # Alert state updated
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "tuning_queue"


# ---------------------------------------------------------------------------
# Acceptance 5 — State-machine guard
# ---------------------------------------------------------------------------


class TestStateMachineGuard:
    def test_illegal_edge_returns_409_no_state_change(self):
        """alerts -> validated_true_positive without going through validating is illegal."""
        client = _client_with()
        resp = client.post("/alerts", json={"dedup_key": "guard-test|1.1.1.1|2.2.2.2"})
        alert_id = resp.json()["ids"][0]

        t_resp = client.post(f"/triage/{alert_id}/transition", json={
            "to_bucket": "validated_true_positive",
            "reason": "direct skip",
        })
        assert t_resp.status_code == 409
        assert "illegal transition" in t_resp.json()["detail"]

        # State unchanged
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "alerts"

        # No audit row written
        transitions = store.alert_transitions(alert_id)
        assert len(transitions) == 0

    def test_unknown_bucket_returns_400(self):
        client = _client_with()
        resp = client.post("/alerts", json={"dedup_key": "unknown-bucket|1.1.1.1|2.2.2.2"})
        alert_id = resp.json()["ids"][0]

        t_resp = client.post(f"/triage/{alert_id}/transition", json={
            "to_bucket": "definitely_not_a_bucket",
        })
        assert t_resp.status_code == 400
        assert "unknown bucket" in t_resp.json()["detail"]

    def test_force_overrides_illegal_edge_and_audits(self):
        """force=True allows any edge AND still writes an audit row."""
        client = _client_with()
        resp = client.post("/alerts", json={"dedup_key": "force-test|1.1.1.1|2.2.2.2"})
        alert_id = resp.json()["ids"][0]

        t_resp = client.post(f"/triage/{alert_id}/transition", json={
            "to_bucket": "validated_true_positive",
            "reason": "analyst override — confirmed via SIEM",
            "force": True,
        })
        assert t_resp.status_code == 200
        data = t_resp.json()
        assert data["to_bucket"] == "validated_true_positive"
        assert data["forced"] is True

        # Audit row MUST be written even when forced
        transitions = store.alert_transitions(alert_id)
        assert len(transitions) == 1
        assert transitions[0]["from_bucket"] == "alerts"
        assert transitions[0]["to_bucket"] == "validated_true_positive"

        # State updated
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "validated_true_positive"


# ---------------------------------------------------------------------------
# Acceptance 6 — Investigator failure -> 502 + retry to 'alerts'
# ---------------------------------------------------------------------------


class TestInvestigatorFailure:
    def test_investigator_down_returns_502(self):
        """If investigator call raises, triage returns 502."""
        client = _client_with(FailingInvestigatorClient())
        resp = client.post("/alerts", json={
            "dedup_key": "fail-test|1.1.1.1|2.2.2.2",
            "severity": 5,
        })
        alert_id = resp.json()["ids"][0]

        inv_resp = client.post(f"/triage/{alert_id}/investigate")
        assert inv_resp.status_code == 502
        assert "investigator" in inv_resp.json()["detail"].lower()

    def test_investigator_failure_retransitions_to_alerts(self):
        """After investigator failure, alert is moved back to 'alerts' bucket."""
        client = _client_with(FailingInvestigatorClient())
        resp = client.post("/alerts", json={
            "dedup_key": "fail-retry|10.0.0.5|10.0.0.6",
            "severity": 3,
        })
        alert_id = resp.json()["ids"][0]

        # Start investigation (will fail)
        client.post(f"/triage/{alert_id}/investigate")

        # Alert should be back in 'alerts' bucket for retry
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "alerts"

        # Two transitions: alerts->validating, validating->alerts (retry)
        transitions = store.alert_transitions(alert_id)
        assert len(transitions) == 2
        assert transitions[0]["to_bucket"] == "validating"
        assert transitions[1]["to_bucket"] == "alerts"
        assert "failed" in (transitions[1]["reason"] or "").lower()


# ---------------------------------------------------------------------------
# tri-3 — dedup suppression: reopen on higher severity
# ---------------------------------------------------------------------------


class TestDedupReopen:
    def test_higher_severity_reopens_dismissed_alert(self):
        """tri-3: Dismiss an alert, then re-upsert with HIGHER severity -> bucket back to 'alerts' + audit transition exists."""
        # Insert initial alert (severity 3)
        alert_id = store.upsert_alert(
            dedup_key="tri3-reopen-test|1.1.1.1|2.2.2.2",
            severity=3,
            signature="ET TEST",
            source_ip="1.1.1.1",
            dest_ip="2.2.2.2",
        )
        # Dismiss it (force, since dismissed is not a direct edge from alerts via legal path,
        # but we can do alerts->dismissed which IS a legal edge)
        store.transition_alert(alert_id, "dismissed", reason="false positive")
        alert_after_dismiss = store.get_alert(alert_id)
        assert alert_after_dismiss is not None
        assert alert_after_dismiss["bucket"] == "dismissed"

        # Re-upsert same dedup_key with HIGHER severity (8 > 3)
        returned_id = store.upsert_alert(
            dedup_key="tri3-reopen-test|1.1.1.1|2.2.2.2",
            severity=8,
            signature="ET TEST",
            source_ip="1.1.1.1",
            dest_ip="2.2.2.2",
        )
        assert returned_id == alert_id, "should return same alert id"

        alert_after_reopen = store.get_alert(alert_id)
        assert alert_after_reopen is not None
        assert alert_after_reopen["bucket"] == "alerts", (
            f"expected bucket='alerts' after higher-severity reopen, got {alert_after_reopen['bucket']}"
        )

        # Audit transition row must exist: dismissed -> alerts
        transitions = store.alert_transitions(alert_id)
        reopen_transitions = [
            t for t in transitions
            if t["from_bucket"] == "dismissed" and t["to_bucket"] == "alerts"
        ]
        assert len(reopen_transitions) >= 1, "expected a dismissed->alerts audit transition"
        assert "higher-severity" in (reopen_transitions[0]["reason"] or "").lower()

    def test_same_or_lower_severity_stays_dismissed(self):
        """tri-3: Dismiss an alert, then re-upsert with SAME severity -> stays dismissed, count bumped."""
        alert_id = store.upsert_alert(
            dedup_key="tri3-stay-dismissed|3.3.3.3|4.4.4.4",
            severity=5,
            signature="ET STAY",
            source_ip="3.3.3.3",
            dest_ip="4.4.4.4",
        )
        store.transition_alert(alert_id, "dismissed", reason="fp")

        # Re-upsert with same severity (5 == 5)
        store.upsert_alert(
            dedup_key="tri3-stay-dismissed|3.3.3.3|4.4.4.4",
            severity=5,
        )
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "dismissed", (
            "bucket should remain dismissed when new severity <= existing severity"
        )
        assert alert["count"] == 2, "count should be incremented"

    def test_lower_severity_stays_dismissed(self):
        """tri-3: Dismiss an alert, re-upsert with LOWER severity -> stays dismissed."""
        alert_id = store.upsert_alert(
            dedup_key="tri3-lower-sev|5.5.5.5|6.6.6.6",
            severity=7,
        )
        store.transition_alert(alert_id, "dismissed", reason="fp")

        store.upsert_alert(
            dedup_key="tri3-lower-sev|5.5.5.5|6.6.6.6",
            severity=2,
        )
        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "dismissed"


# ---------------------------------------------------------------------------
# tri-1 — transition TOCTOU: SELECT...FOR UPDATE is present
# ---------------------------------------------------------------------------


class TestTransitionLocking:
    def test_transition_works_normally_single_threaded(self):
        """tri-1: Normal single-threaded transition still succeeds (lock is transparent)."""
        alert_id = store.upsert_alert(
            dedup_key="tri1-lock-test|7.7.7.7|8.8.8.8",
            severity=4,
        )
        result = store.transition_alert(alert_id, "dismissed", reason="lock test")
        assert result["to_bucket"] == "dismissed"
        assert result["from_bucket"] == "alerts"

        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "dismissed"

        transitions = store.alert_transitions(alert_id)
        assert len(transitions) == 1

    def test_transition_alert_uses_for_update(self):
        """tri-1: Verify SELECT...FOR UPDATE is present in transition_alert source."""
        import inspect
        source = inspect.getsource(store.transition_alert)
        assert "FOR UPDATE" in source, "transition_alert must use SELECT...FOR UPDATE"


# ---------------------------------------------------------------------------
# tri-2 — reap_stale_validating
# ---------------------------------------------------------------------------


class TestReapStaleValidating:
    def test_reap_returns_zero_when_nothing_stuck(self):
        """tri-2: reap on empty/fresh tables returns 0."""
        count = store.reap_stale_validating(older_than_minutes=5)
        assert count == 0

    def test_reap_recovers_stuck_validating_alert(self):
        """tri-2: An alert artificially aged in validating gets reaped back to alerts."""
        import psycopg as _pg

        alert_id = store.upsert_alert(
            dedup_key="tri2-reap-test|9.9.9.9|10.10.10.10",
            severity=3,
        )
        # Force into validating
        store.transition_alert(alert_id, "validating", reason="triage started")
        # Artificially age updated_at to trigger the reaper
        with _pg.connect(_PG_DSN) as conn:
            conn.execute(
                "UPDATE alerts SET updated_at = now() - interval '10 minutes' WHERE id = %s",
                (alert_id,),
            )
            conn.commit()

        count = store.reap_stale_validating(older_than_minutes=5)
        assert count >= 1

        alert = store.get_alert(alert_id)
        assert alert is not None
        assert alert["bucket"] == "alerts", (
            f"expected reaped alert back in 'alerts', got {alert['bucket']}"
        )

        # Audit transition must exist
        transitions = store.alert_transitions(alert_id)
        reap_transitions = [
            t for t in transitions
            if t["from_bucket"] == "validating" and t["to_bucket"] == "alerts"
            and "reap" in (t["reason"] or "").lower()
        ]
        assert len(reap_transitions) >= 1

    def test_reap_endpoint_via_http(self):
        """tri-2: POST /triage/reap returns {reaped: N}."""
        client = _client_with()
        resp = client.post("/triage/reap")
        assert resp.status_code == 200
        data = resp.json()
        assert "reaped" in data
        assert isinstance(data["reaped"], int)


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
        assert data["service"] == "triage"
