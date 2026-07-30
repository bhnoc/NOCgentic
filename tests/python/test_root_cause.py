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


# ---------------------------------------------------------------------------
# rc-1: densify+detect — novel detection and correct baseline
# ---------------------------------------------------------------------------

class TestDensifyDetect:
    """rc-1 / rc-2: _densify_and_score correctness."""

    def _hour(self, offset: int, base: float) -> int:
        """Return epoch for base + offset hours (already-rounded)."""
        return int(base // 3600) * 3600 + offset * 3600

    def test_novel_sig_only_in_last_hour(self):
        """Sig appearing only in the final bucket of a 4-hour window -> novel=True."""
        base = 1_700_000_000.0  # arbitrary stable epoch
        t0 = self._hour(0, base)
        t1 = self._hour(3, base)
        # Only the last hour bucket has data
        rows = [{"sig": "ET NOVEL SIG", "bucket_epoch": self._hour(3, base), "n": 5.0}]
        results = rc_main._densify_and_score(rows, float(t0), float(t1))
        assert len(results) == 1
        r = results[0]
        assert r["novel"] is True, f"Expected novel=True, got {r}"

    def test_novel_sig_in_baseline_half_is_not_novel(self):
        """Sig present in first bucket (baseline half) -> novel=False."""
        base = 1_700_000_000.0
        t0 = self._hour(0, base)
        t1 = self._hour(3, base)
        rows = [
            {"sig": "ET KNOWN SIG", "bucket_epoch": self._hour(0, base), "n": 2.0},
            {"sig": "ET KNOWN SIG", "bucket_epoch": self._hour(3, base), "n": 8.0},
        ]
        results = rc_main._densify_and_score(rows, float(t0), float(t1))
        assert len(results) == 1
        r = results[0]
        assert r["novel"] is False, f"Expected novel=False, got {r}"

    def test_densified_baseline_includes_quiet_hours(self):
        """Baseline mean must include zero-count hours (dense window, not just active hours)."""
        base = 1_700_000_000.0
        t0 = self._hour(0, base)
        t1 = self._hour(3, base)  # 4 buckets: hours 0,1,2,3
        # Sig only active in hour 3 with count=8; hours 0-2 are zero
        rows = [{"sig": "ET SPARSE SIG", "bucket_epoch": self._hour(3, base), "n": 8.0}]
        results = rc_main._densify_and_score(rows, float(t0), float(t1))
        assert len(results) == 1
        r = results[0]
        # With 4 buckets [0, 0, 0, 8], mean = 2.0 (not 8.0 if only active hours counted)
        assert r["baseline"] == 2.0, f"Expected mean=2.0 (dense), got {r['baseline']}"


# ---------------------------------------------------------------------------
# rc-2: single-bucket std=0 does not escalate to critical
# ---------------------------------------------------------------------------

class TestSingleBucketNoCritical:
    """rc-2: counts=[3] should not produce severity=critical."""

    def test_single_bucket_low_count_z_is_zero(self):
        """One bucket, count=3 (<5 threshold) -> z=0.0 -> severity low/medium, not critical."""
        base = 1_700_000_000.0
        t0 = int(base // 3600) * 3600
        t1 = t0  # single-bucket window
        rows = [{"sig": "ET RARE ONE", "bucket_epoch": t0, "n": 3.0}]
        results = rc_main._densify_and_score(rows, float(t0), float(t1))
        assert len(results) == 1
        r = results[0]
        assert r["z"] == 0.0, f"Expected z=0.0 for single low-count bucket, got {r['z']}"
        severity = rc_main._map_severity(r["z"], r["count"])
        assert severity != "critical", f"Should not be critical for insufficient baseline, got {severity}"


# ---------------------------------------------------------------------------
# rc-3: no self-match in recall
# ---------------------------------------------------------------------------

class TestNoSelfMatchRecall:
    """rc-3: investigate recall should not return the current run's own template."""

    def test_recall_does_not_return_own_template(self):
        """After /investigate, the dominant template should not appear as a recall hit
        at distance ~0 (self-match). If the store was empty before the run, similar_templates
        should return nothing (or nothing at distance 0)."""
        sig = "ET SELF MATCH TEST"
        src = _make_fixture_source(sig=sig, n_events=5, z=8.0)
        client = _make_client(src)

        resp = client.post("/investigate", json={"query": "self match test", "window_hours": 1})
        assert resp.status_code == 200

        run_id = resp.json()["run_id"]
        run_resp = client.get(f"/runs/{run_id}")
        assert run_resp.status_code == 200

        recall_events = [
            e for e in run_resp.json().get("events", []) if e["event_type"] == "recall"
        ]
        assert recall_events, "no recall event found in run trace"
        recall_data = recall_events[0]["data"]
        similar_templates = recall_data.get("similar_templates", [])

        # No template should have distance 0.0 (that would be self-match)
        for t in similar_templates:
            assert t.get("distance", 1.0) > 1e-6, (
                f"Self-match found in recall: {t}"
            )


# ---------------------------------------------------------------------------
# rc-5: marker selection picks nearest to spike, not earliest
# ---------------------------------------------------------------------------

class TestMarkerNearestToSpike:
    """rc-5: when two markers exist, the one closest to (latest at-or-before) the spike wins."""

    def test_two_markers_nearest_wins(self):
        """Seed marker_a (early in window) and marker_b (close to spike end).
        The investigation root_cause should reference marker_b's ref, not marker_a's."""
        now = time.time()
        t0 = now - 7200  # 2-hour window
        t1 = now

        sig = "ET NEAREST MARKER TEST"
        src = _make_fixture_source(sig=sig, n_events=5, z=9.0, window_t0=t0, window_t1=t1)
        client = _make_client(src)

        # marker_a: early in window (should NOT be chosen)
        marker_a_ts = datetime.fromtimestamp(t0 + 60, tz=timezone.utc).isoformat()
        client.post("/markers", json={
            "ts": marker_a_ts, "kind": "deploy", "ref": "v1.0.0-early", "note": "early deploy"
        })

        # marker_b: close to spike end (should BE chosen as nearest to spike)
        marker_b_ts = datetime.fromtimestamp(t1 - 120, tz=timezone.utc).isoformat()
        client.post("/markers", json={
            "ts": marker_b_ts, "kind": "deploy", "ref": "v2.0.0-near", "note": "near spike"
        })

        resp = client.post("/investigate", json={"query": "marker test", "window_hours": 3})
        assert resp.status_code == 200
        rc = resp.json()["finding"]["root_cause"]
        assert "v2.0.0-near" in rc, (
            f"Expected nearest marker ref 'v2.0.0-near' in root_cause, got: {rc!r}"
        )


# ---------------------------------------------------------------------------
# rc-7: missing 'z' key in spike does not raise TypeError
# ---------------------------------------------------------------------------

class TestProxyFallbackNoZ:
    """rc-7: spike dict missing 'z' key must not raise TypeError in prose_fallback."""

    def test_investigate_spike_without_z_returns_finding(self):
        """Fixture spike without 'z' key -> /investigate returns 200, not 500."""
        now = time.time()
        t0 = now - 3600
        t1 = now
        sig = "ET NO Z KEY"
        # Deliberately omit 'z' from the spike
        spike_no_z = {"signature": sig, "count": 5, "baseline": 1.0, "t0": t0, "t1": t1}
        src = rc_main.FixtureAnomalySource(
            spikes=[spike_no_z],
            events_by_sig={sig: [_suricata_line(sig, "10.0.0.1", "1.2.3.4")]},
            window={"t0": t0, "t1": t1},
        )
        client = _make_client(src)
        resp = client.post("/investigate", json={"query": "z missing test", "window_hours": 1})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        body = resp.json()
        assert "finding" in body


# ---------------------------------------------------------------------------
# rc-8: /ingest input bounds
# ---------------------------------------------------------------------------

class TestIngestBounds:
    """rc-8: oversized payloads are rejected; normal payloads still work."""

    def test_raw_too_long_rejected(self):
        """A single event with raw > 10000 chars -> 422 Unprocessable Entity."""
        client = _make_client()
        long_raw = "x" * 10_001
        resp = client.post("/ingest", json={"events": [{"raw": long_raw, "source": "test"}]})
        assert resp.status_code == 422, (
            f"Expected 422 for over-limit raw, got {resp.status_code}"
        )

    def test_too_many_events_rejected(self):
        """5001 events -> 422."""
        client = _make_client()
        events = [{"raw": f"event {i}", "source": "test"} for i in range(5_001)]
        resp = client.post("/ingest", json={"events": events})
        assert resp.status_code == 422, (
            f"Expected 422 for over-limit event list, got {resp.status_code}"
        )

    def test_normal_ingest_still_works(self):
        """Normal payload under limits -> 200."""
        client = _make_client()
        events = [{"raw": _suricata_line("ET TEST", "1.2.3.4", "5.6.7.8"), "source": "test"}]
        resp = client.post("/ingest", json={"events": events})
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# rc-9: per-investigation miner — no cross-contamination
# ---------------------------------------------------------------------------

class TestPerInvestigationMiner:
    """rc-9: two sequential investigations should not contaminate each other."""

    def test_two_sequential_investigations_independent_templates(self):
        """Two different signatures investigated sequentially → each gets its own dominant template."""
        sig1 = "ET MINER TEST SIG ONE"
        sig2 = "ET MINER TEST SIG TWO"

        src1 = _make_fixture_source(sig=sig1, n_events=5, z=8.0)
        src2 = _make_fixture_source(sig=sig2, n_events=5, z=8.0)

        client1 = _make_client(src1)
        resp1 = client1.post("/investigate", json={"query": "sig1", "window_hours": 1})
        assert resp1.status_code == 200
        run_id1 = resp1.json()["run_id"]

        client2 = _make_client(src2)
        resp2 = client2.post("/investigate", json={"query": "sig2", "window_hours": 1})
        assert resp2.status_code == 200
        run_id2 = resp2.json()["run_id"]

        # Retrieve run traces and check dominant templates are correct per investigation
        run1 = client1.get(f"/runs/{run_id1}").json()
        run2 = client2.get(f"/runs/{run_id2}").json()

        cluster1 = next(
            e["data"] for e in run1["events"] if e["event_type"] == "cluster"
        )
        cluster2 = next(
            e["data"] for e in run2["events"] if e["event_type"] == "cluster"
        )

        dom1 = cluster1.get("dominant", "")
        dom2 = cluster2.get("dominant", "")

        # sig1 should NOT dominate run2 and vice versa
        assert sig1.lower() not in dom2.lower() or sig2.lower() in dom2.lower(), (
            f"Cross-contamination: run2 dominant template references sig1: {dom2!r}"
        )
