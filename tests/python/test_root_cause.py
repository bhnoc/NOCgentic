"""
test_root_cause.py — Acceptance tests for agents/root-cause/main.py

Requires a live Postgres+pgvector. The whole module is skipped if PG_DSN is
unreachable (same pattern as test_store.py).

Uses FixtureAnomalySource injected via app.state, so no AWS creds or Gemini key
are needed. The stub embedder is active (GEMINI_API_KEY not set in real creds).
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module-level skip if PG is unreachable
# ---------------------------------------------------------------------------
_PG_DSN = os.environ.get("PG_DSN", "postgresql://nocgentic:nocgentic@localhost:5432/nocgentic")

try:
    import psycopg as _psycopg_check
    _conn_check = _psycopg_check.connect(_PG_DSN, connect_timeout=3)
    _conn_check.close()
except Exception as _pg_exc:
    pytest.skip(f"no postgres: {_pg_exc}", allow_module_level=True)

# ---------------------------------------------------------------------------
# Env + sys.path setup — BEFORE any agent imports
# ---------------------------------------------------------------------------
os.environ.setdefault("PG_DSN", _PG_DSN)
# Force stub embedder — no key needed
os.environ["EMBED_PROVIDER"] = "stub"
# Prevent telemetry from doing network things
os.environ.setdefault("OTEL_ENABLED", "false")
os.environ.setdefault("OTEL_CONSOLE_TRACES", "false")
os.environ.setdefault("GEMINI_API_KEY", "")
os.environ.setdefault("LLM_PROVIDER", "gemini")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")

_REPO = Path(__file__).resolve().parents[2]
_SHARED = str(_REPO / "agents" / "shared")
_ROOT_CAUSE = str(_REPO / "agents" / "root-cause")
for p in [_SHARED, _ROOT_CAUSE]:
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Load the root-cause main via conftest helper (handles module-alias de-dup)
# ---------------------------------------------------------------------------
from conftest import load_agent_main  # noqa: E402

rc_main = load_agent_main("root-cause", "rc_main")

from fastapi.testclient import TestClient  # noqa: E402
import store  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_tables():
    """Wipe all tables before each test."""
    store.init_schema()
    import psycopg as _pg
    with _pg.connect(_PG_DSN) as conn:
        conn.execute(
            """
            TRUNCATE agent_events, agent_runs, incidents,
                     log_templates, deploy_markers RESTART IDENTITY CASCADE
            """
        )
        conn.commit()
    yield


def _make_client(anomaly_source=None) -> TestClient:
    """Return a TestClient with an optional injected anomaly source."""
    client = TestClient(rc_main.app)
    if anomaly_source is not None:
        rc_main.app.state.anomaly_source = anomaly_source
    else:
        # Reset to default (no state override)
        try:
            del rc_main.app.state.anomaly_source
        except (AttributeError, KeyError):
            pass
    return client


# ---------------------------------------------------------------------------
# Fixture anomaly source helpers
# ---------------------------------------------------------------------------

def _suricata_line(sig: str, src_ip: str, dst_ip: str, ts: float | None = None) -> str:
    """Build a fixture suricata event line."""
    ts = ts or time.time()
    return (
        f"suricata ts={ts:.3f} sig={sig} cat=Exploit sev=1 "
        f"src={src_ip}:12345 dst={dst_ip}:443 svc=http"
    )


def _make_fixture_source(
    sig: str = "ET EXPLOIT CVE-2026-1234",
    n_events: int = 10,
    z: float = 8.5,
    window_t0: float | None = None,
    window_t1: float | None = None,
) -> "rc_main.FixtureAnomalySource":
    now = time.time()
    t0 = window_t0 if window_t0 is not None else now - 3600
    t1 = window_t1 if window_t1 is not None else now

    # Generate n_events lines with different source IPs
    event_lines = [
        _suricata_line(sig, f"10.0.0.{i % 255}", "185.220.101.5", t0 + i * 10)
        for i in range(n_events)
    ]
    spikes = [{"signature": sig, "count": n_events, "baseline": 1.0, "t0": t0, "t1": t1, "z": z}]
    return rc_main.FixtureAnomalySource(
        spikes=spikes,
        events_by_sig={sig: event_lines},
        window={"t0": t0, "t1": t1},
    )


# ---------------------------------------------------------------------------
# Tests: /health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health(self):
        client = _make_client()
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "root-cause"
        assert body["embed_stub"] is True  # no GEMINI_API_KEY


# ---------------------------------------------------------------------------
# Tests: /ingest — template deduplication
# ---------------------------------------------------------------------------

class TestIngest:
    def test_50_identical_except_ip_collapses_to_1_template(self):
        """50 lines with the same structure but different IPs → 1 unique template."""
        sig = "ET MALWARE Beacon Heartbeat"
        events = [
            {
                "raw": _suricata_line(sig, f"10.{i}.{i}.{i % 255}", "1.2.3.4"),
                "source": "suricata",
            }
            for i in range(50)
        ]
        client = _make_client()
        resp = client.post("/ingest", json={"events": events})
        assert resp.status_code == 200
        body = resp.json()
        assert body["events_seen"] == 50
        assert body["unique_templates"] == 1, (
            f"Expected 1 unique template, got {body['unique_templates']}: "
            f"{body}"
        )
        assert body["templates_upserted"] == 1

    def test_different_signatures_produce_multiple_templates(self):
        """Two structurally different sigs → at least 2 templates."""
        events = [
            {"raw": _suricata_line("ET SCAN Port Sweep", "10.0.0.1", "10.0.0.2"), "source": "s"},
            {"raw": "DHCP discover mac=aa:bb:cc:dd:ee:ff host=laptop-123", "source": "dhcp"},
        ]
        client = _make_client()
        resp = client.post("/ingest", json={"events": events})
        assert resp.status_code == 200
        body = resp.json()
        assert body["unique_templates"] >= 2

    def test_empty_events_returns_zero(self):
        client = _make_client()
        resp = client.post("/ingest", json={"events": []})
        assert resp.status_code == 200
        body = resp.json()
        assert body["events_seen"] == 0
        assert body["templates_upserted"] == 0


# ---------------------------------------------------------------------------
# Tests: /similar
# ---------------------------------------------------------------------------

class TestSimilar:
    def test_just_ingested_template_is_nearest(self):
        """After ingesting a template, /similar with the same text → distance ≈ 0."""
        sig = "ET EXPLOIT Metasploit Shellcode"
        line = _suricata_line(sig, "192.168.1.5", "10.20.30.40")
        client = _make_client()
        client.post("/ingest", json={"events": [{"raw": line, "source": "test"}]})

        # Query with the template text (already clustered)
        from templating import TemplateMiner
        tmp = TemplateMiner()
        result = tmp.add(line)
        template_text = result["template"]

        resp = client.get("/similar", params={"text": template_text, "k": 5})
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["templates"]) >= 1
        nearest = body["templates"][0]
        assert nearest["distance"] < 0.2, (
            f"Expected distance < 0.2 (near-duplicate), got {nearest['distance']}"
        )

    def test_similar_returns_both_keys(self):
        client = _make_client()
        resp = client.get("/similar", params={"text": "some security event", "k": 3})
        assert resp.status_code == 200
        body = resp.json()
        assert "templates" in body
        assert "incidents" in body


# ---------------------------------------------------------------------------
# Tests: /incidents
# ---------------------------------------------------------------------------

class TestIncidents:
    def test_record_incident_then_recall(self):
        """POST /incidents records it; /similar then returns it under incidents."""
        client = _make_client()
        text = "CVE-2026-5678 exploit on suricata"
        resp = client.post("/incidents", json={
            "title": "CVE exploit spike",
            "summary": text,
            "root_cause": "unpatched service",
            "resolution": "patched and rebooted",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert "id" in body
        inc_id = body["id"]

        # Now query similar — the incident should come back
        sim_resp = client.get("/similar", params={"text": text, "k": 5})
        assert sim_resp.status_code == 200
        sim_body = sim_resp.json()
        ids = [i["id"] for i in sim_body["incidents"]]
        assert inc_id in ids, f"Incident {inc_id} not found in similar results: {ids}"


# ---------------------------------------------------------------------------
# Tests: /investigate — full loop
# ---------------------------------------------------------------------------

class TestInvestigate:
    def test_investigate_returns_run_id_and_finding(self):
        """Basic smoke: returns run_id, finding with severity and root_cause."""
        src = _make_fixture_source(sig="ET EXPLOIT CVE-2026-9999", n_events=5, z=8.5)
        client = _make_client(src)

        resp = client.post("/investigate", json={"query": "why is traffic spiking", "window_hours": 1})
        assert resp.status_code == 200
        body = resp.json()

        assert "run_id" in body
        assert "finding" in body
        assert "evidence" in body

        finding = body["finding"]
        assert finding.get("severity") in ("critical", "high", "medium", "low")
        assert finding.get("root_cause") is not None
        assert "title" in finding
        assert "summary" in finding

    def test_get_runs_returns_ordered_events(self):
        """After /investigate, /runs/{id} contains events in order with expected types."""
        src = _make_fixture_source(sig="ET SCAN Nmap Probe", n_events=3, z=5.0)
        client = _make_client(src)

        resp = client.post("/investigate", json={"query": "scan detected", "window_hours": 2})
        assert resp.status_code == 200
        run_id = resp.json()["run_id"]

        runs_resp = client.get(f"/runs/{run_id}")
        assert runs_resp.status_code == 200
        runs_body = runs_resp.json()

        assert "run" in runs_body
        assert "events" in runs_body

        event_types = [e["event_type"] for e in runs_body["events"]]

        # Required event types from the spec
        for required in ("plan", "anomaly_detected", "cluster", "recall", "correlate", "verdict"):
            assert required in event_types, (
                f"Missing event type '{required}' in trace: {event_types}"
            )

        # Events must be in seq order (1, 2, 3, ...)
        seqs = [e["seq"] for e in runs_body["events"]]
        assert seqs == sorted(seqs), f"Events not in seq order: {seqs}"

    def test_no_spike_returns_baseline_nominal(self):
        """When fixture has no spikes, finding says no anomaly."""
        src = rc_main.FixtureAnomalySource(spikes=[], events_by_sig={})
        client = _make_client(src)

        resp = client.post("/investigate", json={"query": "any anomalies?", "window_hours": 1})
        assert resp.status_code == 200
        body = resp.json()
        finding = body["finding"]
        # root_cause or summary should mention no anomaly
        assert (
            "no anomaly" in finding.get("root_cause", "").lower()
            or "nominal" in finding.get("title", "").lower()
            or "no anomaly" in finding.get("summary", "").lower()
        )


# ---------------------------------------------------------------------------
# Tests: deploy-marker correlation
# ---------------------------------------------------------------------------

class TestDeployMarkerCorrelation:
    def test_marker_inside_spike_window_correlates(self):
        """Seed a marker inside the fixture spike window; investigate; finding references it."""
        now = time.time()
        t0 = now - 3600
        t1 = now

        sig = "ET EXPLOIT Deploy Canary"
        src = _make_fixture_source(
            sig=sig, n_events=8, z=9.0,
            window_t0=t0, window_t1=t1,
        )

        client = _make_client(src)

        # Seed a marker with ts inside the spike window
        marker_ts_epoch = t0 + 300  # 5 minutes into the window
        marker_ts_iso = datetime.fromtimestamp(marker_ts_epoch, tz=timezone.utc).isoformat()
        marker_resp = client.post("/markers", json={
            "ts": marker_ts_iso,
            "kind": "deploy",
            "ref": "v2.5.0",
            "commit_sha": "deadbeef1234",
            "note": "pushed new IDS rules",
        })
        assert marker_resp.status_code == 200
        marker_id = marker_resp.json()["id"]

        # Run investigation
        inv_resp = client.post("/investigate", json={"query": "spike after deploy", "window_hours": 2})
        assert inv_resp.status_code == 200
        body = inv_resp.json()

        finding = body["finding"]
        evidence = body["evidence"]

        # Root cause should reference the deploy marker
        rc = finding.get("root_cause", "")
        assert (
            "deploy" in rc.lower()
            or "v2.5.0" in rc
            or "deadbeef1234" in rc
        ), f"Expected deploy reference in root_cause, got: {rc!r}"

        # Evidence should include the marker
        markers_in_evidence = evidence.get("markers", [])
        marker_ids = [m.get("id") for m in markers_in_evidence]
        assert marker_id in marker_ids, (
            f"Expected marker {marker_id} in evidence.markers: {marker_ids}"
        )

    def test_embed_stub_is_true(self):
        """Sanity: stub embedder is active (no Gemini key)."""
        from embeddings import is_stub
        assert is_stub() is True
