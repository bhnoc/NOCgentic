"""Gate on the event-local day window in athena-hunter's generate_sql repair layer.

The bug this locks down: `dt` is the UTC calendar day of `ts`, but the analyst is
standing in the NOC and the venue is UTC-7. From 17:00 local onward the UTC date has
already rolled over, so `dt = '<utc today>'` covers only the hours since 17:00 local.

Measured on live prod at 19:33 Las Vegas time (02:33 UTC the next day):

    dt = '<utc today>'                      778,187 alerts
    the analyst's actual local day        4,186,931 alerts

A 5.4x undercount, and it gets worse the earlier in the evening you ask, reaching
~100% missing just after 17:00 local. It is the dangerous kind of wrong: the query
succeeds, the number looks plausible, nothing logs an error, and the show floor is
busiest during exactly the broken window.

Two halves to the fix and both are tested here:
  * the prompt/user_content teaches the 2-partition prune plus ts bounds;
  * the repair layer PROMOTES a single-partition same-day query to that form,
    because AQLight v4 emits `dt = '<one date>'` and never `dt IN (..)`, so the
    pre-existing ts safety net (keyed on `dt IN (`) structurally never fired.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone

import pytest

import athena_client as ac
from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")


def _gen(raw_sql_list, query="how many alerts today"):
    """Drive the REAL generate_sql with a stubbed model returning raw_sql_list.

    Stubbing only llm_complete keeps every repair step in play (token substitution,
    qualifier strip, dt injection, ts back-fill, LIMIT append), which is the point:
    these regexes are the last line of defence and testing them in isolation would
    not prove they are wired in.
    """
    captured = {}

    async def fake_llm_complete(system_prompt=None, user_content=None, **kw):
        captured["system"] = system_prompt
        captured["user"] = user_content
        return json.dumps(raw_sql_list)

    real = _ah.llm_complete
    _ah.llm_complete = fake_llm_complete
    try:
        out = asyncio.run(_ah.generate_sql(query, {
            "ips": [], "domains": [], "uids": [], "md5s": [], "sha256s": [],
        }, ac.today_partition()))
    finally:
        _ah.llm_complete = real
    return out, captured


def _bounds(sql):
    lo = re.search(r"ts\s*>=\s*(\d+)", sql)
    hi = re.search(r"ts\s*<=\s*(\d+)", sql)
    return (int(lo.group(1)) if lo else None, int(hi.group(1)) if hi else None)


# ---------------------------------------------------------------------------
# The promotion itself
# ---------------------------------------------------------------------------

def test_single_partition_today_is_promoted_to_the_local_day():
    """`dt = '<today>'` becomes the local-day prune plus bounds.

    REVERT-CHECK: this is the 5.4x undercount. If the promotion is removed the
    output keeps one partition and no ts bound, and this fails on both counts.
    """
    today = ac.today_partition()
    out, _ = _gen([f"SELECT COUNT(*) FROM alerts WHERE dt = '{today}'"])
    sql = out[0]
    assert "dt IN (" in sql, sql
    for part in ac.local_day_partitions(0):
        assert part in sql, f"{part} missing from {sql}"
    lo, hi = _bounds(sql)
    assert (lo, hi) == ac.local_day_bounds(0)


def test_the_utc_date_is_promoted_too():
    """The model may emit the UTC date rather than the local one; both promote.

    On a Vegas evening these are DIFFERENT strings, and the UTC one is precisely
    the wrong answer, so it must not slip through as "some other explicit date".
    """
    utc_today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out, _ = _gen([f"SELECT COUNT(*) FROM alerts WHERE dt = '{utc_today}'"])
    assert "dt IN (" in out[0]
    assert _bounds(out[0]) == ac.local_day_bounds(0)


def test_yesterday_gets_yesterdays_window_not_todays():
    """Keyed on the date VALUE, so "yesterday" is not silently retargeted at today.

    A promotion that always applied today's bounds would answer a question about
    yesterday with zero rows, which reads as "nothing happened".
    """
    from datetime import timedelta
    y = (datetime.strptime(ac.today_partition(), "%Y-%m-%d")
         - timedelta(days=1)).strftime("%Y-%m-%d")
    out, _ = _gen([f"SELECT COUNT(*) FROM alerts WHERE dt = '{y}'"],
                  query="what alerts fired yesterday")
    sql = out[0]
    for part in ac.local_day_partitions(-1):
        assert part in sql, f"{part} missing from {sql}"
    assert _bounds(sql) == ac.local_day_bounds(-1)


def test_an_unrelated_explicit_date_is_left_alone():
    """A date we have no local window for keeps its partition untouched.

    Guessing at the intent behind `dt = '2026-07-01'` is worse than leaving SQL the
    analyst can see is a whole-UTC-day query.
    """
    out, _ = _gen(["SELECT COUNT(*) FROM alerts WHERE dt = '2026-07-01'"],
                  query="how many alerts on july 1")
    assert "dt = '2026-07-01'" in out[0]
    assert "ts >=" not in out[0]


# ---------------------------------------------------------------------------
# Interactions with the pre-existing repair steps
# ---------------------------------------------------------------------------

def test_an_existing_ts_bound_is_never_second_guessed():
    """If the model already bounded ts, its window wins.

    The model can express windows the repair layer cannot infer (a 6-hour window,
    a specific incident span). Overwriting them would make precise questions
    impossible to ask.
    """
    today = ac.today_partition()
    out, _ = _gen([f"SELECT COUNT(*) FROM alerts WHERE dt = '{today}' "
                   f"AND ts >= 111 AND ts <= 222"])
    assert "ts >= 111" in out[0] and "ts <= 222" in out[0]


def test_an_alias_qualified_join_is_repaired():
    """`a.dt = '<today>'` inside a join becomes `a.dt IN (..) AND a.ts >= ..`.

    Joins used to be skipped wholesale because a BARE `ts` is AMBIGUOUS_NAME across
    aliases. When the dt predicate carries an alias that reasoning does not apply:
    `a.ts` is unambiguous. And v4 writes joins exactly that way, so skipping them
    left the 5.4x undercount in place on every joined hunt.
    """
    today = ac.today_partition()
    out, _ = _gen([f"SELECT a.uid FROM alerts a JOIN ssl s ON a.uid = s.uid "
                   f"WHERE a.dt = '{today}'"])
    sql = out[0]
    assert "a.dt IN (" in sql, sql
    assert "a.ts >=" in sql and "a.ts <=" in sql, sql
    # Never a bare ts, which is the AMBIGUOUS_NAME the old skip was avoiding.
    assert not re.search(r"(?<![.\w])ts\s*>=", sql), sql


def test_both_sides_of_a_join_get_the_widened_partition():
    """Each side is pruned separately, so each side has to be widened.

    Widening only the first would leave the second on one UTC partition, and the
    join then drops every row whose partner rolled into the next UTC day: the
    undercount survives in a place that looks fixed.
    """
    today = ac.today_partition()
    out, _ = _gen([f"SELECT a.uid FROM suricata_corelight a JOIN ssl s ON a.uid = s.uid "
                   f"WHERE a.dt = '{today}' AND s.dt = '{today}'"])
    sql = out[0]
    assert "a.dt IN (" in sql, sql
    assert "s.dt IN (" in sql, sql
    # The ts bound is applied once; bounding one side of a uid join bounds the result.
    assert len(re.findall(r"\bts\s*>=", sql)) == 1, sql


def test_an_unqualified_dt_inside_a_join_is_still_left_alone():
    """No alias to borrow means a bare `ts`, which fails the whole query.

    A partition-granularity answer the analyst can see beats AMBIGUOUS_NAME.
    """
    today = ac.today_partition()
    out, _ = _gen([f"SELECT uid FROM alerts JOIN ssl ON alerts.uid = ssl.uid "
                   f"WHERE dt = '{today}'"])
    assert "ts >=" not in out[0], out[0]


def test_the_two_day_prune_still_gets_its_bounds():
    """The original safety net must survive the new branch.

    Without ts bounds a 2-partition prune returns ~48h and inflates every COUNT,
    which is the mirror image of the undercount and was fixed earlier.
    """
    parts = ", ".join(repr(p) for p in ac.local_day_partitions(0))
    out, _ = _gen([f"SELECT COUNT(*) FROM alerts WHERE dt IN ({parts})"])
    lo, hi = _bounds(out[0])
    assert lo is not None and hi is not None and hi > lo


def test_injection_when_dt_is_missing_uses_the_local_prune():
    """A query with no dt predicate at all gets the local pair, not one partition.

    An unpartitioned query scans the whole projected range, so injection has to
    happen; injecting `dt = '<today>'` would just trade a scan blowup for the
    undercount.
    """
    out, _ = _gen(["SELECT COUNT(*) FROM alerts WHERE severity = 'high'"])
    assert "dt IN (" in out[0]
    for part in ac.local_day_partitions(0):
        assert part in out[0]


def test_injection_without_a_where_clause_stays_valid_sql():
    out, _ = _gen(["SELECT orig_h, COUNT(*) FROM alerts GROUP BY orig_h"])
    sql = out[0]
    assert sql.upper().index("WHERE") < sql.upper().index("GROUP BY")
    assert "dt IN (" in sql


# ---------------------------------------------------------------------------
# The ts-less snapshot tables. Widening the ts back-fill to the single-partition
# form also widened its blast radius: it started firing on the host-keyed tables,
# which have no ts column at all. Verified against information_schema on prod
# 2026-08-04 (87 of 114 tables have ts). Two distinct reasons to skip them:
#   * a bare `ts` there is COLUMN_NOT_FOUND, i.e. no answer instead of a small one;
#   * they are DAILY SNAPSHOTS of one row per host, so two partitions would return
#     every host twice with no ts bound available to trim it back.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("table", [
    "entity_context", "asset_classification", "device_links",
    # Dated view snapshots share the base shape; matched by stem, not enumerated.
    "entity_context_2026_08_04", "device_links_2026_08_05",
])
def test_ts_is_never_injected_into_a_ts_less_table(table):
    today = ac.today_partition()
    out, _ = _gen([f"SELECT ip, hostname FROM {table} WHERE dt = '{today}' "
                   f"AND ip = '10.220.83.99'"],
                  query="tell me about host 10.220.83.99")
    sql = out[0]
    assert "ts >=" not in sql, sql
    # And it keeps ONE partition, so each host appears once.
    assert "dt IN (" not in sql, sql
    assert f"dt = '{today}'" in sql


def test_a_ts_less_table_still_gets_a_partition_when_dt_is_missing():
    """Injection must still happen, just with a single local-day partition.

    No dt at all means a scan of the whole projected range, so skipping injection
    entirely would be the expensive kind of wrong.
    """
    out, _ = _gen(["SELECT ip, hostname FROM entity_context WHERE ip = '10.0.0.1'"],
                  query="tell me about host 10.0.0.1")
    assert f"dt = '{ac.today_partition()}'" in out[0]
    assert "ts >=" not in out[0]


def test_a_ts_bearing_table_is_unaffected_by_the_guard():
    """The guard must not swallow the fix for the tables that do have ts."""
    today = ac.today_partition()
    out, _ = _gen([f"SELECT COUNT(*) FROM conn WHERE dt = '{today}'"])
    assert "dt IN (" in out[0] and "ts >=" in out[0]


def test_the_guard_is_conservative_about_mixed_tables():
    """One ts-less table anywhere in the query disables the back-fill.

    A partial injection would reference ts on a table that has none, which fails
    the whole query rather than half of it.
    """
    assert _ah._query_supports_ts("SELECT 1 FROM conn") is True
    assert _ah._query_supports_ts(
        "SELECT 1 FROM conn c JOIN entity_context e ON c.id_orig_h = e.ip") is False


# ---------------------------------------------------------------------------
# What the model is told. A repair layer that silently fixes the model forever is
# a maintenance bill; the prompt has to teach the right shape too.
# ---------------------------------------------------------------------------

def test_the_prompt_forbids_the_bare_single_partition_form():
    assert "NEVER write a bare `dt = 'TODAY'`" in _ah.SQL_GEN_PROMPT


def test_user_content_hands_over_real_local_epoch_bounds():
    """The model cannot derive local midnight from a date string, so give it.

    It has no timezone context at all: it sees dates and a query. Anything it
    computed itself would be UTC.
    """
    _, cap = _gen(["SELECT 1 FROM alerts WHERE dt IN ('a','b') AND ts >= 1 AND ts <= 2"])
    uc = cap["user"]
    start, end = ac.local_day_bounds(0)
    assert str(start) in uc and str(end) in uc
    y_start, y_end = ac.local_day_bounds(-1)
    assert str(y_start) in uc and str(y_end) in uc
    assert "UTC calendar day" in uc


def test_no_advice_to_use_a_single_partition_survives_in_the_prompt():
    """REVERT-CHECK on the exemplar that caused this.

    The user_content used to say "For single-day queries use `dt = 'today'`", and an
    exemplar beats a rule: v4 emitted the single-partition form 22/22 times on the
    probe. Removing the rule while leaving the example would silently re-break it.
    """
    _, cap = _gen(["SELECT 1 FROM alerts WHERE dt IN ('a','b') AND ts >= 1 AND ts <= 2"])
    combined = cap["user"] + _ah.SQL_GEN_PROMPT
    assert "single-day queries use `dt =" not in combined
    # Every same-day example offered to the model uses the 2-partition prune.
    for line in cap["user"].splitlines():
        if line.startswith('- "today"') or line.startswith('- "yesterday"'):
            assert "dt IN (" in line, line
            assert "ts >=" in line, line


# ---------------------------------------------------------------------------
# Measured prompt-accuracy fixes from the same probe (2026-08-04, AQLight v4).
# ---------------------------------------------------------------------------

def test_the_prompt_names_the_alert_signature_mistake():
    """v4 wrote `a.alert_signature` on alerts; that column is suricata-only."""
    assert "alerts has NO alert_signature" in _ah.SQL_GEN_PROMPT


def test_the_prefix_rule_covers_the_select_list():
    """v4 filtered on id_orig_h and selected bare orig_h in the same query."""
    assert "SELECT orig_h FROM conn` fails" in _ah.SQL_GEN_PROMPT


@pytest.mark.parametrize("token", ["ntlm", "username"])
def test_the_prompt_documents_ntlm_usernames(token):
    """v4 reached for ntlm.username for "which usernames were observed" and both
    exist in Athena, so the prompt has to keep advertising them."""
    assert token in _ah.SQL_GEN_PROMPT
