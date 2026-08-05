"""Gate: SQL_GEN_PROMPT must not advertise columns that do not exist.

The prompt is the model's entire schema. When it names a column the catalog does
not have, the model uses it and the query dies COLUMN_NOT_FOUND, so a stale prompt
line is not cosmetic: it is a broken hunt for every question that touches that
table. And it is a slow rot, because nothing checks a prompt string.

Two claims shipped wrong and both were found by executing generated SQL rather
than by reading the prompt (probe against AQLight v4, live Athena, 2026-08-04):

  * conn was documented as having id_orig_mac / id_orig_mac_vendor / id_resp_mac /
    id_resp_mac_vendor. None of the four exist. The real columns are orig_l2_addr
    and resp_l2_addr, and there is no vendor column on conn at all.
  * every port column (id_orig_p, id_resp_p, orig_p, resp_p) is varchar, but a
    hunt-pattern exemplar wrote `id_resp_p IN (22,3389,...)` unquoted, which is
    TYPE_MISMATCH. An exemplar beats a rule, so v4 copied the shape.

These assertions are offline: they pin the prompt against column facts verified
against information_schema on prod, so they cost nothing per run and still fail
loudly if someone reintroduces the old names. They cannot detect a NEW schema
drift in Athena; only a live probe does that. Re-run bench/ or the ad-hoc probe
after any table rebuild.
"""

from __future__ import annotations

import re

import pytest

from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_P = _ah.SQL_GEN_PROMPT


# ---------------------------------------------------------------------------
# Columns that DO NOT exist and must never be advertised again.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ghost", [
    # conn MAC columns, verified absent on prod 2026-08-04.
    "id_orig_mac",
    "id_orig_mac_vendor",
    "id_resp_mac",
    "id_resp_mac_vendor",
])
def test_prompt_does_not_name_a_nonexistent_column(ghost):
    assert ghost not in _P, (
        f"SQL_GEN_PROMPT advertises {ghost}, which is not in the catalog; "
        "conn carries orig_l2_addr / resp_l2_addr and has no vendor column")


def test_prompt_names_the_real_conn_mac_columns():
    for real in ("orig_l2_addr", "resp_l2_addr"):
        assert real in _P, f"conn's real MAC column {real} is undocumented"


# ---------------------------------------------------------------------------
# varchar columns compared against bare integers. Both the RULE and every
# EXEMPLAR have to agree, because the exemplar is what the model copies.
# ---------------------------------------------------------------------------

_PORT_COLS = ("id_orig_p", "id_resp_p", "orig_p", "resp_p")

# `col IN (80,443)` / `col = 22` / `col > 1024` with an UNQUOTED number. A CAST
# is legitimate, so require that the comparison is not preceded by CAST(.
_UNQUOTED_IN = re.compile(
    r"\b(?:" + "|".join(_PORT_COLS) + r")\s+IN\s*\(\s*\d")
_UNQUOTED_CMP = re.compile(
    r"(?<!AS integer\) )\b(?:" + "|".join(_PORT_COLS) + r")\s*(?:=|<=|>=|<|>)\s*\d")


def test_no_exemplar_compares_a_port_to_a_bare_integer():
    """REVERT-CHECK on the line that taught v4 `id_resp_p IN (80,443)`.

    Restrict the search to the parts of the prompt that are not the warning about
    this very mistake, since the warning has to quote the bad form to name it.
    """
    for line in _P.splitlines():
        if "TYPE_MISMATCH" in line or "ALWAYS quote" in line:
            continue  # the rule itself, which quotes the bad form deliberately
        assert not _UNQUOTED_IN.search(line), f"unquoted port IN list: {line}"
        assert not _UNQUOTED_CMP.search(line), f"unquoted port comparison: {line}"


def test_the_prompt_states_the_port_type_rule():
    assert "EVERY PORT COLUMN IS ALSO A STRING" in _P
    assert "CAST(id_resp_p AS integer)" in _P, (
        "the rule must offer a way to compare ports numerically, else it just "
        "makes range questions unanswerable")


def test_the_severity_type_rule_survives():
    """The same trap on suricata_corelight.alert_severity, fixed earlier.

    Skip the rule's own line for the same reason as above: it has to show the broken
    form (`alert_severity = 1`) in order to forbid it.
    """
    assert "alert_severity is a STRING" in _P
    for line in _P.splitlines():
        if "TYPE_MISMATCH" in line or "ALWAYS quote" in line:
            continue
        assert not re.search(r"\balert_severity\s*(?:=|<=|>=|<|>)\s*\d", line), line


# ---------------------------------------------------------------------------
# Near-miss column names on the host-keyed tables. v4 reached for a bare
# `confidence` on entity_context (which has five prefixed ones) and `hostname` on
# device_links (which has nine columns and none of them is that).
# ---------------------------------------------------------------------------

def test_entity_context_bare_confidence_is_called_out():
    assert "NO bare `confidence` column here" in _P


def test_device_links_column_list_is_marked_exhaustive():
    assert "these NINE are all of them" in _P
    assert "no hostname" in _P
