"""Gate on the near-miss column repair in athena-hunter.

The last two Athena failures on the AQLight v4 probe, both COLUMN_NOT_FOUND:

    SELECT ts_datetime, orig_h, resp_h, alert_name, alert_severity FROM alerts ...
    SELECT ip, hostname, mac, vendor_mac, device_type, os_name, confidence
      FROM entity_context ...

The prompt already covers both by name. It says "alerts has NO alert_severity ...
the severity is `severity`" and it lists id_confidence in entity_context's columns.
v4 reaches for the plausible synonym anyway, so this is repaired in code.

The licence, verified against information_schema on prod 2026-08-04: each rename
has exactly one candidate on that table. alerts has one severity column out of 13.
entity_context has one id-confidence column; the other four (org_, owner_name_,
internal_domain_, home_) are confidences about different things, so mapping a bare
`confidence` to any of them would be a guess.

Most of what these tests pin is the refusals. A rename that fires too widely turns
a visible COLUMN_NOT_FOUND into a plausible wrong answer, which is strictly worse.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import athena_client as ac
from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_fix = _ah._fix_column_synonyms


# ---------------------------------------------------------------------------
# The two probe failures
# ---------------------------------------------------------------------------

def test_alert_severity_on_alerts_becomes_severity():
    """REVERT-CHECK: `FAIL beacon: Column 'alert_severity' cannot be resolved`."""
    out = _fix("SELECT ts_datetime, orig_h, alert_name, alert_severity FROM alerts "
               "WHERE dt='2026-08-04' ORDER BY ts DESC LIMIT 200")
    assert "alert_severity" not in out
    assert "severity" in out


def test_confidence_on_entity_context_becomes_id_confidence():
    """REVERT-CHECK: `FAIL entity: Column 'confidence' cannot be resolved`.

    id_confidence and not one of the other four, because "tell me about this host"
    is asking how sure we are of the host's identity.
    """
    out = _fix("SELECT ip, hostname, mac, device_type, confidence FROM entity_context "
               "WHERE dt IN ('2026-08-04','2026-08-05') AND ip='10.220.83.99'")
    assert "id_confidence" in out
    assert "org_confidence" not in out
    assert "home_confidence" not in out


@pytest.mark.parametrize("wrong,right", [
    ("alert_signature", "alert_name"),
    ("alert_category", "alert_type"),
])
def test_the_other_suricata_borrowings_on_alerts(wrong, right):
    """Same borrowing, different column. These three travel together on
    suricata_corelight, so a model that reaches for one reaches for all of them."""
    out = _fix(f"SELECT {wrong} FROM alerts WHERE dt='x'")
    assert wrong not in out and right in out


def test_a_correct_query_is_untouched():
    sql = "SELECT severity, alert_name FROM alerts WHERE dt='x' LIMIT 5"
    assert _fix(sql) == sql
    sql2 = "SELECT id_confidence FROM entity_context WHERE dt='x' LIMIT 5"
    assert _fix(sql2) == sql2


def test_the_rename_is_not_applied_twice():
    """id_confidence must not become id_id_confidence.

    The lookbehind has to treat `_` as a word char, or the sub matches inside its
    own output and fails exactly as loudly as the bug it replaced.
    """
    out = _fix("SELECT id_confidence FROM entity_context WHERE dt='x'")
    assert "id_id_" not in out


# ---------------------------------------------------------------------------
# Refusals. Each one is a case where firing would produce a WRONG ANSWER rather
# than an error, which is the failure mode worth being paranoid about.
# ---------------------------------------------------------------------------

def test_alert_severity_on_suricata_is_left_alone():
    """It is the REAL column there. Renaming it to `severity` would break a
    working query, and suricata_corelight has no bare `severity`."""
    sql = "SELECT alert_severity FROM suricata_corelight WHERE dt='x'"
    assert _fix(sql) == sql


def test_confidence_on_asset_classification_is_left_alone():
    """asset_classification genuinely HAS a bare `confidence` column.

    A synonym table keyed on the column name alone rather than the table would
    rewrite this into id_confidence, which does not exist there. This is the exact
    reason the mapping is per-table.
    """
    sql = "SELECT mac, vendor_mac, confidence FROM asset_classification WHERE dt='x'"
    assert _fix(sql) == sql


def test_a_join_is_left_alone():
    """With two tables the name might belong to the other one.

    `alerts JOIN suricata_corelight` has a legitimate alert_severity in scope.
    """
    sql = ("SELECT a.orig_h, s.alert_severity FROM alerts a "
           "JOIN suricata_corelight s ON a.uid = s.uid WHERE a.dt='x'")
    assert _fix(sql) == sql


def test_a_qualified_reference_is_left_alone():
    """An alias needs FROM-clause resolution to attribute, which this does not do."""
    sql = "SELECT a.alert_severity FROM alerts a WHERE a.dt='x'"
    assert _fix(sql) == sql


def test_an_output_alias_is_not_renamed():
    """`AS confidence` is a result header the answer text and UI table read."""
    out = _fix("SELECT id_confidence AS confidence FROM entity_context WHERE dt='x'")
    assert "AS confidence" in out
    assert "AS id_confidence" not in out


def test_a_longer_column_containing_the_name_survives():
    """org_confidence contains `confidence` and is a real, different column."""
    out = _fix("SELECT org_confidence, owner_name_confidence, home_confidence "
               "FROM entity_context WHERE dt='x'")
    assert "org_confidence" in out
    assert "owner_name_confidence" in out
    assert "id_org_confidence" not in out


def test_an_unmapped_table_is_left_alone():
    sql = "SELECT confidence FROM some_new_view WHERE dt='x'"
    assert _fix(sql) == sql


def test_dated_snapshots_match_by_stem():
    out = _fix("SELECT confidence FROM entity_context_2026_08_04 WHERE dt='x'")
    assert "id_confidence" in out


def test_every_synonym_target_differs_from_its_source():
    """A no-op entry would be dead weight that reads as coverage."""
    for table, syn in _ah._COLUMN_SYNONYMS.items():
        for wrong, right in syn.items():
            assert wrong != right, f"{table}.{wrong} maps to itself"


# ---------------------------------------------------------------------------
# Wired into the real pipeline
# ---------------------------------------------------------------------------

def test_generate_sql_applies_the_repair():
    async def fake_llm_complete(system_prompt=None, user_content=None, **kw):
        return json.dumps([
            "SELECT ts_datetime, orig_h, alert_name, alert_severity FROM alerts "
            "WHERE dt = 'today' ORDER BY ts DESC LIMIT 200"])

    real = _ah.llm_complete
    _ah.llm_complete = fake_llm_complete
    try:
        out = asyncio.run(_ah.generate_sql("find beaconing or C2 traffic today", {
            "ips": [], "domains": [], "uids": [], "md5s": [], "sha256s": [],
        }, ac.today_partition()))
    finally:
        _ah.llm_complete = real
    assert "alert_severity" not in out[0], out[0]
    assert "severity" in out[0], out[0]


def test_the_prompt_still_states_both_facts():
    """The repair is a net, not a replacement. A model that learns the right column
    is better than one that gets corrected, and the prompt is how it learns."""
    assert "alerts has NO alert_signature" in _ah.SQL_GEN_PROMPT
    assert "NO bare `confidence` column here" in _ah.SQL_GEN_PROMPT
