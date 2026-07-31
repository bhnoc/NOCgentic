"""Gate for alert-feed identity under scope redaction.

QA sweep regression: redacting orig_h BEFORE building alert_id collapsed every
out-of-scope host onto one id. The UI dedups on data-id (static/index.html), so
distinct incidents were silently dropped from the analyst's feed.

The id must be UNIQUE per host (so nothing is dropped) and OPAQUE (it lands in a
data-id DOM attribute, so it must not carry the address redaction removed).

This imports the REAL _athena_row_to_alert. Reimplementing its logic here would
make the gate vacuous: it would pass against the buggy version too.
"""

import importlib.util
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(_ROOT, "agents", "shared"))

import ipscope  # noqa: E402

TS = "2026-07-31T22:00:00"


@pytest.fixture(scope="module")
def hunter():
    """Import agents/athena-hunter/main.py by path (the directory name has a
    hyphen, so it is not importable as a normal package)."""
    path = os.path.join(_ROOT, "agents", "athena-hunter", "main.py")
    spec = importlib.util.spec_from_file_location("athena_hunter_main", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # fastapi / otel not installed in this venv
        pytest.skip(f"athena-hunter deps unavailable: {exc}")
    return module


def _row(orig_h: str, name: str = "Port scan", resp_h: str = "8.8.8.8"):
    return {
        "alert_name": name,
        "alert_detail": name,
        "orig_h": orig_h,
        "resp_h": resp_h,
        "severity": "high",
        "ts_datetime": TS,
    }


def test_distinct_out_of_scope_hosts_get_distinct_ids(hunter):
    a = hunter._athena_row_to_alert(_row("10.0.1.63"))["id"]
    b = hunter._athena_row_to_alert(_row("10.0.1.47"))["id"]
    assert a != b, "same-signature alerts from different hosts must not collide"


def test_id_does_not_leak_the_redacted_address(hunter):
    out = hunter._athena_row_to_alert(_row("10.0.1.63"))["id"]
    assert "10.0.1.63" not in out
    assert ipscope.OUT_OF_SCOPE_PLACEHOLDER not in out


def test_id_is_stable_for_the_same_host(hunter):
    a = hunter._athena_row_to_alert(_row("10.0.1.63"))["id"]
    b = hunter._athena_row_to_alert(_row("10.0.1.63"))["id"]
    assert a == b


def test_in_scope_host_stays_readable_in_the_id(hunter):
    out = hunter._athena_row_to_alert(_row("10.220.40.7"))["id"]
    assert "10.220.40.7" in out


def test_displayed_fields_are_still_redacted(hunter):
    """Identity is unique, but what the analyst SEES stays redacted."""
    alert = hunter._athena_row_to_alert(_row("10.0.1.63"))
    assert alert["srcIp"] == ipscope.OUT_OF_SCOPE_PLACEHOLDER
    assert "10.0.1.63" not in alert["description"]


def test_public_peer_survives_on_the_display_field(hunter):
    alert = hunter._athena_row_to_alert(_row("10.220.40.7", resp_h="45.83.193.150"))
    assert alert["dstIp"] == "45.83.193.150"
