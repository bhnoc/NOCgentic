"""Gate on the bare/id_ endpoint-column repair in athena-hunter.

The catalog has two naming families for the same four columns: raw Zeek tables use
id_orig_h / id_resp_h / id_orig_p / id_resp_p, the derived tables use orig_h /
resp_h / orig_p / resp_p. Get it backwards and the query dies COLUMN_NOT_FOUND, so
the analyst gets an error instead of an answer.

The prompt states the rule twice, including the SELECT-list caveat that was added
after v4 filtered on id_orig_h and selected bare orig_h in the same statement. It
still misses on roughly 3 of 23 probe queries. Hence the code-side repair.

The licence for repairing this in code, verified against information_schema on prod
2026-08-04: no table carries columns from both families. 60 tables are prefixed, 5
are bare, 0 are both. For a single-table query the table decides, and the rewrite
has nothing to guess. Every ambiguous case is deliberately skipped, and that is
most of what these tests pin down: the repair being narrow is the property that
keeps it from corrupting working SQL.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import athena_client as ac
from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_fix = _ah._fix_endpoint_prefix


# ---------------------------------------------------------------------------
# The repair, in both directions
# ---------------------------------------------------------------------------

def test_bare_columns_on_a_raw_zeek_table_gain_the_prefix():
    out = _fix("SELECT orig_h, resp_p FROM conn WHERE resp_h = '10.0.0.1'")
    assert "id_orig_h" in out and "id_resp_p" in out and "id_resp_h" in out
    assert " orig_h" not in out


def test_prefixed_columns_on_a_derived_table_lose_the_prefix():
    out = _fix("SELECT id_orig_h FROM alerts WHERE id_resp_h = '10.0.0.1'")
    assert "id_orig_h" not in out and "id_resp_h" not in out
    assert "orig_h" in out and "resp_h" in out


def test_the_probe_failure_is_fixed():
    """The exact shape v4 emitted: right in WHERE, wrong in SELECT.

    REVERT-CHECK. This is the COLUMN_NOT_FOUND the live probe reported as
    `FAIL dns-domain: Column 'orig_h' cannot be resolved`.
    """
    out = _fix("SELECT orig_h, COUNT(*) AS c FROM dns "
               "WHERE dt = '2026-08-04' AND id_orig_h IS NOT NULL "
               "GROUP BY orig_h ORDER BY c DESC LIMIT 20")
    assert "(?)" not in out
    assert out.count("id_orig_h") == 3, out
    assert "SELECT id_orig_h" in out


def test_group_by_and_order_by_are_rewritten_too():
    """A half-repair is still COLUMN_NOT_FOUND, just later in the query."""
    out = _fix("SELECT id_orig_h, COUNT(*) c FROM ssl WHERE dt='x' "
               "GROUP BY orig_h ORDER BY orig_h LIMIT 5")
    assert "GROUP BY id_orig_h" in out and "ORDER BY id_orig_h" in out


def test_an_already_correct_query_is_untouched():
    sql = "SELECT id_orig_h, id_resp_p FROM conn WHERE dt='x' LIMIT 5"
    assert _fix(sql) == sql
    sql2 = "SELECT orig_h, resp_p FROM alerts WHERE dt='x' LIMIT 5"
    assert _fix(sql2) == sql2


def test_double_prefixing_cannot_happen():
    """The lookbehind must treat the `_` in id_orig_h as a word char.

    Without it the sub matches the tail of its own output and produces
    id_id_orig_h, which fails exactly as loudly as the bug it replaced.
    """
    out = _fix("SELECT id_orig_h FROM conn WHERE dt='x'")
    assert "id_id_" not in out


# ---------------------------------------------------------------------------
# Everything the repair must refuse to touch
# ---------------------------------------------------------------------------

def test_a_join_is_left_completely_alone():
    """A join can legitimately mix families, so there is no single right answer.

    `ON e.ip = a.orig_h` joined to conn is correct SQL with both spellings present.
    Rewriting either side would break a working query, which is worse than leaving
    a rare broken one for the prompt to handle.
    """
    sql = ("SELECT a.orig_h, c.id_resp_p FROM alerts a "
           "JOIN conn c ON a.orig_h = c.id_orig_h WHERE a.dt='x'")
    assert _fix(sql) == sql


def test_qualified_columns_are_left_alone_even_in_a_single_table_query():
    """An alias does not tell us which table it points at without real parsing.

    `conn.orig_h` is still wrong, but a table-qualified reference is a shape that
    needs FROM-clause resolution to rewrite safely, and the regex does not do that.
    """
    sql = "SELECT c.orig_h FROM conn c WHERE c.dt='x'"
    assert _fix(sql) == sql


def test_an_output_alias_is_not_renamed():
    """`AS orig_h` is a result header, not a column reference.

    The prompt actively recommends `SELECT id_orig_h AS orig_h` for a clean header.
    Renaming that alias would rename the key in the result rows, which is what the
    answer text and the UI table read.
    """
    out = _fix("SELECT id_orig_h AS orig_h, COUNT(*) FROM conn WHERE dt='x' "
               "GROUP BY id_orig_h")
    assert "AS orig_h" in out
    assert "AS id_orig_h" not in out


def test_an_unknown_table_is_left_alone():
    """Not in either census list means we do not know the family. Do nothing.

    Assuming the prefixed form because 60 of 65 tables use it would silently
    corrupt any new bare-column derived table someone adds.
    """
    sql = "SELECT orig_h FROM some_new_view WHERE dt='x'"
    assert _fix(sql) == sql


def test_other_columns_that_merely_start_the_same_survive():
    """orig_l2_addr and orig_bytes are real columns and are not endpoint columns."""
    sql = "SELECT orig_l2_addr, orig_bytes, orig_pkts FROM conn WHERE dt='x'"
    out = _fix(sql)
    assert "id_orig_l2_addr" not in out
    assert "id_orig_bytes" not in out
    assert "orig_pkts" in out and "id_orig_pkts" not in out


def test_dated_view_snapshots_match_by_stem():
    out = _fix("SELECT orig_h FROM conn_2026_08_04 WHERE dt='x'")
    assert "id_orig_h" in out


def test_the_two_families_do_not_overlap():
    """The whole licence for this repair. If a table ever appears in both lists the
    rewrite is no longer decidable from the table name and must be reconsidered."""
    assert not (_ah._BARE_COLUMN_TABLES & _ah._PREFIXED_COLUMN_TABLES)


# ---------------------------------------------------------------------------
# Wired into the real pipeline, not just callable
# ---------------------------------------------------------------------------

def test_generate_sql_applies_the_repair():
    """Testing the helper in isolation would not prove it runs on real output."""
    captured = {}

    async def fake_llm_complete(system_prompt=None, user_content=None, **kw):
        captured["user"] = user_content
        return json.dumps([
            "SELECT orig_h, COUNT(*) AS c FROM conn WHERE dt = 'today' "
            "GROUP BY orig_h LIMIT 10"])

    real = _ah.llm_complete
    _ah.llm_complete = fake_llm_complete
    try:
        out = asyncio.run(_ah.generate_sql("top talkers today", {
            "ips": [], "domains": [], "uids": [], "md5s": [], "sha256s": [],
        }, ac.today_partition()))
    finally:
        _ah.llm_complete = real
    assert "id_orig_h" in out[0], out[0]
    assert "SELECT orig_h" not in out[0], out[0]


def test_the_repair_runs_after_the_database_qualifier_strip():
    """Order matters: the census matches bare table names.

    With a `some_db.` prefix still attached the table lookup misses and the repair
    silently no-ops, so this pins the ordering rather than trusting it.
    """
    out = _fix(_ah._RE_DB_QUALIFIER.sub(r"\1\2",
               "SELECT orig_h FROM blackhat_pope_logs.conn WHERE dt='x'"))
    assert "id_orig_h" in out


@pytest.mark.parametrize("table", sorted(_ah._BARE_COLUMN_TABLES))
def test_every_bare_table_round_trips(table):
    out = _fix(f"SELECT id_orig_h FROM {table} WHERE dt='x'")
    assert "id_orig_h" not in out and "orig_h" in out
