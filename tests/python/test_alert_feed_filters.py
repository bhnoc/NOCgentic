"""Gate for the /alerts/recent scope, severity, and self-signed-cert filters.

Three requirements the live feed needs beyond the existing ET-INFO exclusion:
  * only alerts touching a conference subnet belong in a Black Hat NOC feed
  * 'informational' severity (83% of live Suricata rows) is noise, not signal
  * the SSL::Invalid_Server_Cert self-signed-cert notice was 476 of 500 sampled
    notice rows on this event's own re-used demo cert — pure noise, not a find

This imports the REAL SQL text and the REAL row filter rather than
reimplementing them, so a regression in either is actually caught.
"""

import importlib.util
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))

TS = "2026-08-04T22:00:00"


@pytest.fixture(scope="module")
def hunter():
    path = os.path.join(_ROOT, "agents", "athena-hunter", "main.py")
    spec = importlib.util.spec_from_file_location("athena_hunter_main_filters", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # fastapi / otel not installed in this venv
        pytest.skip(f"athena-hunter deps unavailable: {exc}")
    return module


def _row(orig_h: str, resp_h: str = "8.8.8.8"):
    return {
        "alert_name": "Port scan",
        "alert_detail": "Port scan",
        "orig_h": orig_h,
        "resp_h": resp_h,
        "severity": "high",
        "ts_datetime": TS,
    }


class TestScopeFilter:
    def test_conference_origin_touches_scope(self, hunter):
        assert hunter._row_touches_conference_network(_row("10.220.40.7", "45.83.193.150"))

    def test_conference_destination_touches_scope(self, hunter):
        """Inbound-scan case: a public origin hitting a conference host stays."""
        assert hunter._row_touches_conference_network(_row("45.83.193.150", "10.220.40.7"))

    def test_neither_endpoint_in_conference_is_dropped(self, hunter):
        assert not hunter._row_touches_conference_network(_row("8.8.8.8", "45.83.193.150"))

    def test_out_of_scope_private_endpoints_are_dropped(self, hunter):
        """Neither endpoint is the venue, even though both are private."""
        assert not hunter._row_touches_conference_network(_row("10.0.1.63", "192.168.1.7"))

    def test_missing_hosts_do_not_crash_and_are_dropped(self, hunter):
        assert not hunter._row_touches_conference_network({})


class TestFeedSqlExclusions:
    """The exclusions live in the SQL text (grouped/counted server-side before
    _athena_row_to_alert ever runs), so the gate is on the query string itself."""

    def _sql(self, hunter):
        import inspect

        return inspect.getsource(hunter.alerts_recent)

    def test_informational_severity_excluded(self, hunter):
        sql = self._sql(hunter)
        assert "severity <> 'informational'" in sql

    def test_self_signed_cert_notice_excluded(self, hunter):
        sql = self._sql(hunter)
        assert "SSL::Invalid_Server_Cert" in sql
        assert "self signed" in sql.lower()

    def test_et_info_exclusion_still_present(self, hunter):
        """Regression: the new exclusions must not have replaced the old one."""
        sql = self._sql(hunter)
        assert "ET INFO%" in sql
        assert "ETPRO INFO%" in sql
