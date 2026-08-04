"""Gate on _RE_DB_QUALIFIER in athena-hunter.

Why a dedicated file: the local AQLight fine-tune emits a `<database>.<table>`
prefix in every generated query no matter what the system prompt says, and it
does not always emit a database that exists. Probing the live model produced
`FROM blackhat_2026_logs.flows`, a database AND a table that were never in the
catalog, so a rewrite keyed on the known training-set name (blackhat_pope_logs)
could not have caught it. Stripping the qualifier works for both cases because
the Athena execution context already names the database.

The failure mode this replaced was loud: `SCHEMA_NOT_FOUND` on every hunt the
local lane won. The failure mode it could introduce is quiet, which is why the
column cases below matter more than the table cases. A bare `\\w+\\.\\w+` rule
would also strip a qualified COLUMN, turning `f.uid = s.uid` into `uid = uid`
(tautology, wrong row count) or `AMBIGUOUS_NAME` on a join where both sides
carry the column. Hence the FROM/JOIN anchor.
"""

from __future__ import annotations

import pytest

from conftest import load_agent_main

_ah = load_agent_main("athena-hunter", "athena_hunter_main")
_RE = _ah._RE_DB_QUALIFIER


def _strip(sql: str) -> str:
    return _RE.sub(r"\1\2", sql)


@pytest.mark.parametrize("sql,expected", [
    # The training-set name.
    ("SELECT * FROM blackhat_pope_logs.conn", "SELECT * FROM conn"),
    # A name the model invented, which is the case a rename map cannot handle.
    ("SELECT * FROM blackhat_2026_logs.flows", "SELECT * FROM flows"),
    # The current prod name is equally redundant and equally stripped.
    ("SELECT * FROM blackhatnoc_glue.alerts", "SELECT * FROM alerts"),
    # JOIN is a table position too.
    ("SELECT 1 FROM db.conn JOIN db.files ON 1=1",
     "SELECT 1 FROM conn JOIN files ON 1=1"),
    # Case and whitespace are the model's to vary, not ours.
    ("select * from DB_X.conn", "select * from conn"),
    ("SELECT * FROM\n  some_db.conn", "SELECT * FROM\n  conn"),
    # An alias after the table survives.
    ("SELECT c.uid FROM db.conn c", "SELECT c.uid FROM conn c"),
])
def test_table_qualifier_is_stripped(sql, expected):
    assert _strip(sql) == expected


@pytest.mark.parametrize("sql", [
    # THE REGRESSION THAT MATTERS. These are the files-join and uid-pivot
    # exemplars the prompt teaches, so a greedy rule would corrupt the exact
    # queries the model is most likely to emit.
    "SELECT f.uid, s.server_name FROM conn f JOIN ssl s ON f.uid = s.uid",
    "SELECT a.orig_h FROM alerts a WHERE a.dt = '2026-08-03'",
    "SELECT u.log_type FROM uid_lookup u JOIN files fl ON u.uid = fl.uid",
    # A qualified column in a predicate, GROUP BY and ORDER BY.
    "SELECT c.id_orig_h FROM conn c GROUP BY c.id_orig_h ORDER BY c.id_orig_h",
    # No qualifier at all: already correct, must be a no-op.
    "SELECT * FROM conn WHERE dt = '2026-08-03'",
    # A dotted string LITERAL is data, not a qualifier. Stripping inside it
    # would silently change which host the analyst asked about.
    "SELECT * FROM conn WHERE id_resp_h = '10.0.0.1' AND query = 'a.b.com'",
])
def test_non_table_positions_are_untouched(sql):
    assert _strip(sql) == sql


def test_a_catalog_prefix_keeps_its_database():
    """`awsdatacatalog.db.tbl` degrades to `db.tbl`, deliberately.

    Only one qualifier is stripped. Reducing a three-part name all the way to a
    bare table would silently retarget a genuine cross-catalog query at the
    local database, and guessing at that intent is worse than leaving SQL the
    caller can see is wrong.
    """
    assert _strip("SELECT * FROM cat.db.tbl") == "SELECT * FROM db.tbl"


def test_the_strip_is_actually_wired_into_the_sql_path():
    """Guards against the regex existing but nothing applying it.

    This spot previously held a prefix RENAME keyed on the old training-set
    database name. Testing the regex in isolation would still pass if someone
    deleted the .sub() call and left the pattern behind, so pin the call site.
    """
    import inspect
    src = inspect.getsource(_ah)
    assert "_RE_DB_QUALIFIER.sub" in src, (
        "the qualifier regex is defined but nothing applies it")
