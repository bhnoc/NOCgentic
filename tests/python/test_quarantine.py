"""Manifold-driven session quarantine (orchestrator).

A Manifold threat names the SESSION it was seen in only by trace id, so
containment depends on two things being right:

  * trace ids from Manifold (dashed, UUID-style) matching ours (32 undashed
    hex). Same 128 bits, different rendering -- a literal == never matches.
  * the trace -> session mapping surviving long enough for a threat to arrive,
    since Manifold scans asynchronously after the session.

Both are locked in here, along with expiry, extend-not-shorten, and the
fail-closed admin gate.
"""

from __future__ import annotations

import time

import pytest

from conftest import load_agent_main

_orch = load_agent_main("orchestrator", "orch_main")


@pytest.fixture(autouse=True)
def _clean_quarantine_state():
    """Both stores are module-level; start every test empty."""
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()
    yield
    _orch._trace_sessions.clear()
    _orch._quarantined.clear()


# ---------------------------------------------------------------------------
# trace id normalisation -- the correlation hinge
# ---------------------------------------------------------------------------

def test_dashed_manifold_id_matches_undashed_otel_id():
    """The whole integration hangs on this: Manifold renders the trace id
    UUID-style, OTel emits 32 undashed hex. They must compare equal."""
    otel = "8f3c1e02aabbccdd1122334455667788"
    manifold = "8f3c1e02-aabb-ccdd-1122-334455667788"
    assert _orch.normalize_trace_id(otel) == _orch.normalize_trace_id(manifold)


def test_normalize_is_case_insensitive_and_trims():
    assert _orch.normalize_trace_id("  8F3C1E02-AABB  ") == "8f3c1e02aabb"


def test_normalize_handles_absent_ids():
    assert _orch.normalize_trace_id(None) == ""
    assert _orch.normalize_trace_id("") == ""


def test_resolve_accepts_either_rendering():
    """Recorded undashed (as OTel gives it), resolved dashed (as Manifold sends
    it) -- and the reverse."""
    _orch.record_trace_session("8f3c1e02aabbccdd1122334455667788", "sid-A")
    assert _orch.resolve_trace_to_session("8f3c1e02-aabb-ccdd-1122-334455667788") == "sid-A"

    _orch.record_trace_session("11112222-3333-4444-5555-666677778888", "sid-B")
    assert _orch.resolve_trace_to_session("11112222333344445555666677778888") == "sid-B"


# ---------------------------------------------------------------------------
# mapping + quarantine mechanics
# ---------------------------------------------------------------------------

def test_unknown_trace_resolves_to_none():
    assert _orch.resolve_trace_to_session("deadbeef" * 4) is None


def test_record_ignores_incomplete_pairs():
    _orch.record_trace_session(None, "sid-A")
    _orch.record_trace_session("abc123", None)
    assert _orch._trace_sessions == {}


def test_quarantine_blocks_only_the_named_session():
    _orch.quarantine_session("sid-A")
    assert _orch.is_quarantined("sid-A") is True
    assert _orch.is_quarantined("sid-B") is False


def test_absent_session_is_never_quarantined():
    """A cookie-less client has no sid; that must not be treated as contained
    (nor as a wildcard match)."""
    assert _orch.is_quarantined(None) is False
    assert _orch.is_quarantined("") is False


def test_quarantine_expires_after_its_ttl():
    _orch.quarantine_session("sid-A", ttl_seconds=1.0)
    assert _orch.is_quarantined("sid-A") is True
    # Evaluate at a point past expiry rather than sleeping.
    assert _orch.is_quarantined("sid-A", now=time.time() + 2.0) is False


def test_second_threat_extends_never_shortens():
    """A follow-up threat on an already-contained session must not pull the
    release time closer -- that would let a low-TTL event free an attacker
    early."""
    _orch.quarantine_session("sid-A", ttl_seconds=3600.0)
    far = _orch._quarantined["sid-A"]
    _orch.quarantine_session("sid-A", ttl_seconds=1.0)
    assert _orch._quarantined["sid-A"] == far


def test_trace_mapping_outlives_the_quarantine_ttl():
    """Manifold scans after the session ends, so the mapping has to survive
    well past one quarantine window or the threat arrives unresolvable."""
    _orch.record_trace_session("aa" * 16, "sid-A")
    expires_at, sid = _orch._trace_sessions[_orch.normalize_trace_id("aa" * 16)]
    assert sid == "sid-A"
    assert expires_at > time.time() + _orch.QUARANTINE_TTL_SECONDS


def test_expired_entries_are_pruned():
    _orch.quarantine_session("sid-A", ttl_seconds=1.0)
    _orch.record_trace_session("bb" * 16, "sid-A")
    _orch._prune_quarantine(now=time.time() + 10_000)
    assert "sid-A" not in _orch._quarantined


def test_trace_map_is_bounded():
    """A long conference run must not leak memory through the mapping."""
    cap = _orch._QUARANTINE_MAX_TRACES
    for i in range(cap + 250):
        _orch.record_trace_session(f"{i:032x}", f"sid-{i}")
    assert len(_orch._trace_sessions) <= cap


# ---------------------------------------------------------------------------
# admin gate
# ---------------------------------------------------------------------------

def test_admin_gate_fails_closed_when_token_unset(monkeypatch):
    """With ADMIN_BEARER_TOKEN unset the routes must deny everything rather
    than stand wide open."""
    monkeypatch.setattr(_orch, "ADMIN_BEARER_TOKEN", "")
    with pytest.raises(Exception) as exc:
        _orch._require_admin("Bearer anything")
    assert getattr(exc.value, "status_code", None) == 401


def test_admin_gate_rejects_wrong_token(monkeypatch):
    monkeypatch.setattr(_orch, "ADMIN_BEARER_TOKEN", "right-token")
    with pytest.raises(Exception) as exc:
        _orch._require_admin("Bearer wrong-token")
    assert getattr(exc.value, "status_code", None) == 401


def test_admin_gate_accepts_the_right_token(monkeypatch):
    monkeypatch.setattr(_orch, "ADMIN_BEARER_TOKEN", "right-token")
    _orch._require_admin("Bearer right-token")  # must not raise
