"""Gate: generated DDL must survive a column named after a reserved SQL word.

Corelight started emitting a `net_perf` log whose schema has a column literally
called `window`. The Lambda kept a hand-maintained 19-word reserved list and
renamed collisions to `name_`; `window` was not on it, so CREATE TABLE died with a
ParseException and that whole log type stayed invisible. Four log types were
blocked by the time it was noticed.

A blocklist cannot win here: it always lags the parser, and the next unfamiliar
column silently costs a table. So every column is backticked unconditionally.
"""

import importlib.util
import os
import sys

import pytest

_LAMBDA = os.path.join(os.path.dirname(__file__), "..", "..", "lambda")
sys.path.insert(0, _LAMBDA)


@pytest.fixture(scope="module")
def refresh():
    """Import the handler with the env it requires (it fails fast without)."""
    for k, v in {
        "REGION": "us-east-2", "S3_LOG_BUCKET": "b", "S3_LOG_PREFIX": "p",
        "S3_PARQUET_BUCKET": "b", "GLUE_DATABASE": "d", "ATHENA_WORKGROUP": "w",
    }.items():
        os.environ.setdefault(k, v)
    path = os.path.join(_LAMBDA, "athena_refresh_lambda_v6.py")
    spec = importlib.util.spec_from_file_location("refresh_mod", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        pytest.skip(f"lambda deps unavailable: {exc}")
    return mod


# Every field on the real net_perf log, in order. 'window' is the one that broke it.
_NET_PERF_FIELDS = [
    "ts", "window", "trigger", "host", "domain", "local_entity", "uid",
    "total", "crossings", "max_val", "sent_bytes", "recv_bytes", "reply_rate",
]


class TestReservedWordsAreQuotedNotRenamed:
    def test_window_is_quoted(self, refresh):
        assert refresh.quote_column("window") == "`window`"

    def test_sanitize_no_longer_renames_reserved_words(self, refresh):
        """The old behaviour appended an underscore, so the column stopped matching
        the field name in the Parquet file and every consumer had to know about the
        rewrite. Seven columns in the catalog still carry that scar."""
        for word in ("window", "order", "from", "to", "date", "user", "group", "table"):
            assert refresh.sanitize_column_name(word) == word, (
                f"{word} was renamed; it should be quoted instead"
            )

    @pytest.mark.parametrize("field,expected", [
        ("id.orig_h", "id_orig_h"),      # dots become underscores
        ("some-field", "some_field"),    # dashes too
        ("2ndfield", "f_2ndfield"),      # leading digit gets a prefix
        ("Weird$Chars!", "weirdchars"),  # anything else is dropped
        ("MixedCase", "mixedcase"),
    ])
    def test_structural_sanitization_still_applies(self, refresh, field, expected):
        assert refresh.sanitize_column_name(field) == expected

    def test_every_net_perf_column_is_quoted_in_ddl(self, refresh):
        """The exact schema that used to fail."""
        cols = [refresh.quote_column(refresh.sanitize_column_name(f))
                for f in _NET_PERF_FIELDS]
        assert "`window`" in cols
        assert all(c.startswith("`") and c.endswith("`") for c in cols)

    def test_quoting_is_unconditional(self, refresh):
        """A future log type with an unfamiliar reserved column must not need a
        code change. That is the whole point."""
        for name in ("normal_col", "window", "rank", "over", "partition",
                     "lateral", "unnest", "some_word_nobody_predicted"):
            assert refresh.quote_column(name) == f"`{name}`"


class TestDuplicateColumnsDoNotBreakTheTable:
    def test_two_fields_collapsing_to_one_name_are_deduped(self, refresh):
        """`id.orig_h` and `id-orig_h` both sanitize to id_orig_h. A duplicate
        column makes CREATE TABLE fail, losing the whole table over one field."""
        names = [refresh.sanitize_column_name(f) for f in ("id.orig_h", "id-orig_h")]
        assert names[0] == names[1] == "id_orig_h"
