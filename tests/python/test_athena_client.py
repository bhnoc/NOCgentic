"""
Regression tests for agents/shared/athena_client.py

Locks in:
  * sweep-1 sh-1   : sanitize_value truncates BEFORE escaping.
  * sweep-3 sh-101 : sanitize_like_value escapes % _ \\ (no wildcard injection).
  * sweep-2 sh-105 : sanitize_sql rejects UNION / stacked / comments, accepts legit SELECT+JOIN.
  * sweep-3 sh-106 : date_partitions does not over-generate a trailing day.

All functions are imported from the real module (bare-name import via conftest
putting agents/shared on sys.path); not reimplemented.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

import athena_client as ac


# ---------------------------------------------------------------------------
# sanitize_value; truncate BEFORE escape (sweep-1 sh-1)
# ---------------------------------------------------------------------------

def test_sanitize_value_truncates_before_escaping():
    """A value ending in a quote right at the 500-char boundary must not be
    able to break out of a '...' literal.

    REVERT-CHECK: if the fix were reverted to escape-then-truncate
    (`val.replace("'", "''")[:500]`), the doubled ''  at index 499/500 would be
    sliced back to a single lone trailing ' -> odd quote count -> the literal
    is broken open (injection). This test would then FAIL.
    """
    # 499 'A' + a single quote == 500 raw chars; escaping doubles the quote to
    # 501 chars, so a naive escape-then-[:500] would chop the doubled '' to '.
    raw = "A" * 499 + "'"
    out = ac.sanitize_value(raw)

    # Every single-quote in the output must be part of a doubled '' pair, i.e.
    # an even number of consecutive quotes at the tail. Simplest invariant:
    # total count of ' in the escaped output is EVEN (each real quote -> two).
    assert out.count("'") % 2 == 0, f"odd quote count can break the literal: {out[-5:]!r}"

    # And the literal 'out' must not terminate early: the tail is exactly '' .
    assert out.endswith("''"), out[-4:]


def test_sanitize_value_escapes_quotes_and_backslash():
    assert ac.sanitize_value("O'Brien") == "O''Brien"
    assert ac.sanitize_value("a\\b") == "a\\\\b"


def test_sanitize_value_respects_500_char_cap():
    out = ac.sanitize_value("x" * 5000)
    # Raw truncated to 500 first; 'x' needs no escaping so length stays 500.
    assert len(out) == 500


# ---------------------------------------------------------------------------
# sanitize_like_value; escape LIKE wildcards (sweep-3 sh-101)
# ---------------------------------------------------------------------------

def test_sanitize_like_value_escapes_wildcards():
    """% and _ inside a caller value must be neutralised so they cannot inject
    LIKE wildcards, and the backslash escape char itself must be escaped first.

    REVERT-CHECK: if the fix were reverted to just sanitize_value (no %/_
    escaping), an attacker value of '%' would widen `col LIKE '%x%'` into a
    match-everything pattern. This test would FAIL.
    """
    assert ac.sanitize_like_value("50%") == "50\\%"
    assert ac.sanitize_like_value("a_b") == "a\\_b"
    # Backslash escaped BEFORE the wildcards so ordering can't double-unescape.
    assert ac.sanitize_like_value("a\\b") == "a\\\\b"
    # A lone wildcard cannot survive as an active metacharacter.
    assert "%" not in ac.sanitize_like_value("%").replace("\\%", "")
    assert "_" not in ac.sanitize_like_value("_").replace("\\_", "")


def test_sanitize_like_value_also_escapes_quote():
    assert ac.sanitize_like_value("O'%").startswith("O''")


# ---------------------------------------------------------------------------
# sanitize_sql; reject injection, accept legit SELECT (sweep-2 sh-105)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "bad_sql",
    [
        "SELECT * FROM conn UNION SELECT username, password FROM users",
        "SELECT 1 UNION ALL SELECT 2",
        "SELECT * FROM conn; DROP TABLE conn",
        "SELECT * FROM conn WHERE x=1; DELETE FROM alerts",
        "SELECT * FROM conn -- rest is ignored",
        "SELECT * FROM conn /* sneaky */ WHERE 1=1",
        "SELECT * FROM conn WHERE a=1 # mysql comment",
        "DROP TABLE conn",
        "DELETE FROM alerts",
        "INSERT INTO conn VALUES (1)",
        "UPDATE conn SET x=1",
        "WITH x AS (SELECT 1) SELECT * FROM x",  # not starting with SELECT
    ],
)
def test_sanitize_sql_rejects_dangerous(bad_sql):
    """REVERT-CHECK: removing any of the _RE_UNION / _RE_COMMENT / stacked-;
    checks (or the DDL blocklist) would let one of these through and this
    parametrized case would FAIL (no ValueError raised)."""
    with pytest.raises(ValueError):
        ac.sanitize_sql(bad_sql)


def test_sanitize_sql_accepts_normal_select_group_by_limit():
    sql = (
        "SELECT id_orig_h, COUNT(*) AS c FROM conn "
        "WHERE dt = '2026-07-25' GROUP BY id_orig_h ORDER BY c DESC LIMIT 20"
    )
    assert ac.sanitize_sql(sql) == sql


def test_sanitize_sql_accepts_legit_join():
    sql = (
        "SELECT a.uid, b.query FROM conn a "
        "JOIN dns b ON a.uid = b.uid WHERE a.dt = '2026-07-25' LIMIT 100"
    )
    assert ac.sanitize_sql(sql) == sql


def test_sanitize_sql_strips_single_trailing_semicolon():
    # One optional trailing semicolon is allowed and stripped.
    assert ac.sanitize_sql("SELECT 1 FROM conn;") == "SELECT 1 FROM conn"


# ---------------------------------------------------------------------------
# date_partitions; no over-generation of a trailing day (sweep-3 sh-106)
# ---------------------------------------------------------------------------

def test_date_partitions_hours_le_zero_is_today_only():
    assert len(ac.date_partitions(0)) == 1
    assert len(ac.date_partitions(-5)) == 1


def test_date_partitions_small_window_matches_actual_day_span():
    """For a small N-hour window the count must equal the number of distinct
    UTC calendar days actually spanned by [now-hours, now]; never a fixed
    ceil(hours/24)+1.

    REVERT-CHECK: the old impl walked ceil(hours/24) days back from today, so
    hours=1 near mid-day still emitted BOTH yesterday and today (count 2) even
    though the 1-hour window never crosses midnight. This test computes the
    true span and asserts equality, so that over-generation would FAIL.
    """
    for hours in (1, 3, 6, 12):
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        # True set of distinct calendar days in the window.
        expected_days = {now.strftime("%Y-%m-%d")}
        cur = start
        while cur <= now:
            expected_days.add(cur.strftime("%Y-%m-%d"))
            cur += timedelta(days=1)
        got = ac.date_partitions(hours)
        assert set(got) == expected_days
        # Sanity: a sub-24h window spans at most 2 calendar days.
        assert len(got) <= 2


def test_date_partitions_are_sorted_and_valid_dates():
    parts = ac.date_partitions(72)
    assert parts == sorted(parts)
    for p in parts:
        datetime.strptime(p, "%Y-%m-%d")  # raises if malformed


# ---------------------------------------------------------------------------
# date_filter must bound by ts, not partitions alone. Partitions are whole-day
# granularity, so a "last 24h" window spans 2 partitions (~48h of rows) and
# over-counts every metric. The ts lower bound corrects the true window.
# ---------------------------------------------------------------------------

def test_date_filter_bounds_both_ends_for_positive_hours():
    frag = ac.date_filter(24)
    # partition prune present AND explicit epoch bounds on BOTH ends of the window
    assert "dt " in frag
    assert "ts >=" in frag
    assert "ts <=" in frag
    now = int(datetime.now(timezone.utc).timestamp())
    # lower bound: ~24h below now, sane recent epoch, not 0, not future
    mlo = re.search(r"ts >= (\d+)", frag)
    assert mlo, frag
    lo = int(mlo.group(1))
    assert now - 24 * 3600 - 60 <= lo <= now
    # upper bound: ~now (a rolling window is [now-24h, now], not open-ended). This is
    # what stops FUTURE-stamped rows (e.g. the dev demo's today 00:00-03:00 block) from
    # double-counting against a prior day's copy.
    mhi = re.search(r"ts <= (\d+)", frag)
    assert mhi, frag
    hi = int(mhi.group(1))
    assert now - 60 <= hi <= now + 60
    assert hi > lo


def test_date_filter_no_ts_bound_when_hours_le_zero():
    # hours<=0 means "today only", no meaningful rolling window to bound.
    assert "ts >=" not in ac.date_filter(0)
    assert "ts <=" not in ac.date_filter(0)
    assert "ts >=" not in ac.date_filter(-3)
