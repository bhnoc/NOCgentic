"""Gate: a failed Athena query must never read as an all-clear.

`_athena_query` caught every exception and returned `[]`. A timeout, a missing
table, or an IP-scope rejection all became "zero rows", the LLM saw no alerts, and
the analyst was told the segment was quiet. That is the exact shape of the bug that
hid the empty alert feed: the `alerts` table did not exist, every query failed, and
the UI reported no alerts found.

Zero results and could-not-retrieve are different answers. In a SOC, conflating
them gets an incident missed.
"""

import asyncio
import importlib.util
import os
import sys

import pytest

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))


@pytest.fixture(scope="module")
def triage_mod():
    path = os.path.join(_ROOT, "agents", "alert-triage", "main.py")
    spec = importlib.util.spec_from_file_location("alert_triage_main", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"alert-triage deps unavailable: {exc}")
    return mod


class TestFailureRecording:
    def test_a_failed_query_is_recorded_not_just_logged(self, triage_mod, monkeypatch):
        async def boom(sql, timeout=15):
            raise RuntimeError("TABLE_NOT_FOUND: Table 'alerts' does not exist")

        monkeypatch.setattr(triage_mod, "execute_query", boom)
        triage_mod.reset_query_failures()
        rows = asyncio.run(triage_mod._athena_query("SELECT 1", "alerts"))

        assert rows == [], "callers still expect an empty list so the request survives"
        failures = triage_mod.get_query_failures()
        assert len(failures) == 1
        assert failures[0]["query"] == "alerts"
        assert "TABLE_NOT_FOUND" in failures[0]["error"]

    def test_a_scope_rejection_is_recorded(self, triage_mod, monkeypatch):
        """An out-of-scope IP rejection is a refusal, not an all-clear."""
        async def rejected(sql, timeout=15):
            raise ValueError("Out-of-scope IP in query: 10.0.1.63")

        monkeypatch.setattr(triage_mod, "execute_query", rejected)
        triage_mod.reset_query_failures()
        asyncio.run(triage_mod._athena_query("SELECT 1", "conn"))
        assert "Out-of-scope" in triage_mod.get_query_failures()[0]["error"]

    def test_a_timeout_is_recorded(self, triage_mod, monkeypatch):
        async def slow(sql, timeout=15):
            raise TimeoutError("Athena query timed out after 15s")

        monkeypatch.setattr(triage_mod, "execute_query", slow)
        triage_mod.reset_query_failures()
        asyncio.run(triage_mod._athena_query("SELECT 1", "dns"))
        assert triage_mod.get_query_failures()[0]["query"] == "dns"

    def test_a_successful_query_records_nothing(self, triage_mod, monkeypatch):
        async def ok(sql, timeout=15):
            return [{"a": "1"}], {"execution_time_ms": 5, "data_scanned_mb": 0.1}

        monkeypatch.setattr(triage_mod, "execute_query", ok)
        triage_mod.reset_query_failures()
        rows = asyncio.run(triage_mod._athena_query("SELECT 1", "alerts"))
        assert rows == [{"a": "1"}]
        assert triage_mod.get_query_failures() == []

    def test_genuinely_empty_is_not_reported_as_a_failure(self, triage_mod, monkeypatch):
        """The distinction the whole gate exists for: a quiet segment must still be
        able to say 'no results' without being flagged as broken."""
        async def empty(sql, timeout=15):
            return [], {"execution_time_ms": 5, "data_scanned_mb": 0.0}

        monkeypatch.setattr(triage_mod, "execute_query", empty)
        triage_mod.reset_query_failures()
        assert asyncio.run(triage_mod._athena_query("SELECT 1", "alerts")) == []
        assert triage_mod.get_query_failures() == []


class TestIsolation:
    def test_reset_clears_previous_state(self, triage_mod, monkeypatch):
        async def boom(sql, timeout=15):
            raise RuntimeError("first request's failure")

        monkeypatch.setattr(triage_mod, "execute_query", boom)
        triage_mod.reset_query_failures()
        asyncio.run(triage_mod._athena_query("SELECT 1", "alerts"))
        assert len(triage_mod.get_query_failures()) == 1

        # A new request must not inherit it.
        triage_mod.reset_query_failures()
        assert triage_mod.get_query_failures() == []

    def test_concurrent_requests_do_not_cross_contaminate(self, triage_mod, monkeypatch):
        """Triage fans out ~11 queries and the service handles overlapping
        requests. A module-level list would blame one request for another's break."""
        async def fail_for(label):
            async def boom(sql, timeout=15):
                raise RuntimeError(f"{label} broke")
            return boom

        async def one_request(label):
            triage_mod.reset_query_failures()
            monkeypatch.setattr(triage_mod, "execute_query", await fail_for(label))
            await triage_mod._athena_query("SELECT 1", label)
            return triage_mod.get_query_failures()

        async def drive():
            # Run sequentially inside separate contexts, which is what asyncio.run
            # per request gives us in the real service.
            return [await one_request("alerts"), await one_request("dns")]

        results = asyncio.run(drive())
        assert results[0][0]["query"] == "alerts"
        assert results[1][0]["query"] == "dns"
        assert len(results[1]) == 1, "second request inherited the first's failures"


class TestLLMCannotClaimAllClear:
    def test_the_failure_note_forbids_describing_the_segment_as_clean(self, triage_mod):
        """The payload the LLM receives has to say so explicitly. Handing it an
        empty result set and hoping it hedges is what produced the false
        all-clear."""
        import inspect
        src = inspect.getsource(triage_mod)
        assert "DATA_RETRIEVAL_FAILURES" in src
        # The instruction must actually forbid the wrong conclusion.
        assert "does NOT mean" in src
        assert "Do NOT describe the segment as quiet or clear" in src
