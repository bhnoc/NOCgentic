"""Gate for in-code scope enforcement at the Athena boundary.

The SQL-generation prompt asks the model to stay in scope; these tests cover the
control that does not depend on the model complying.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "agents", "shared"))

from athena_client import sanitize_sql  # noqa: E402


class TestScopeEnforcement:
    def test_in_scope_ip_allowed(self):
        sql = "SELECT * FROM conn WHERE id_orig_h = '10.220.40.7'"
        assert sanitize_sql(sql) == sql

    def test_public_ip_allowed(self):
        """External addresses are threat actors — must stay queryable."""
        sql = "SELECT * FROM conn WHERE id_resp_h = '45.83.193.150'"
        assert sanitize_sql(sql) == sql

    @pytest.mark.parametrize(
        "addr", ["10.0.1.63", "192.168.1.7", "172.16.5.9", "10.220.12.5", "169.254.169.254"]
    )
    def test_out_of_scope_ip_rejected(self, addr):
        with pytest.raises(ValueError, match="Out-of-scope IP"):
            sanitize_sql(f"SELECT * FROM conn WHERE id_orig_h = '{addr}'")

    def test_rejected_even_when_mixed_with_in_scope(self):
        with pytest.raises(ValueError, match="Out-of-scope IP"):
            sanitize_sql(
                "SELECT * FROM conn WHERE id_orig_h = '10.220.40.7' "
                "OR id_orig_h = '10.0.1.63'"
            )

    def test_scope_check_survives_case_and_whitespace(self):
        with pytest.raises(ValueError, match="Out-of-scope IP"):
            sanitize_sql("select  *\n  from conn\n  where id_orig_h='10.0.99.4'")

    def test_no_ip_literal_is_allowed(self):
        """Broad scans have no literal; the row filter handles those."""
        sql = "SELECT alert_name, COUNT(*) AS hits FROM alerts GROUP BY alert_name"
        assert sanitize_sql(sql) == sql


class TestPreExistingGuardsStillHold:
    """The scope check must not have weakened what was already enforced."""

    def test_ddl_rejected(self):
        with pytest.raises(ValueError, match="Dangerous SQL"):
            sanitize_sql("SELECT * FROM conn WHERE x IN (DROP TABLE conn)")

    def test_stacked_ddl_rejected_by_statement_guard(self):
        with pytest.raises(ValueError, match="Multiple SQL statements"):
            sanitize_sql("SELECT * FROM conn; DROP TABLE conn")

    def test_non_select_rejected(self):
        with pytest.raises(ValueError):
            sanitize_sql("DELETE FROM conn")

    def test_union_rejected(self):
        with pytest.raises(ValueError, match="UNION"):
            sanitize_sql("SELECT a FROM conn UNION SELECT b FROM dns")

    def test_comment_rejected(self):
        with pytest.raises(ValueError, match="comment"):
            sanitize_sql("SELECT * FROM conn -- rest ignored")

    def test_stacked_statement_rejected(self):
        with pytest.raises(ValueError, match="Multiple SQL statements"):
            sanitize_sql("SELECT 1 FROM conn; SELECT 2 FROM dns")

    def test_trailing_semicolon_still_ok(self):
        assert sanitize_sql("SELECT 1 FROM conn;") == "SELECT 1 FROM conn"


class TestPrefixBypass:
    """QA sweep: a LIKE/regexp prefix targets a subnet with no full dotted quad,
    so a literal-only check saw nothing to reject (both enforcement layers missed
    it: a COUNT(*) row carries no address for the row filter to catch either)."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '192.168.1.%'",
            "SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '10.0.%'",
            "SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '172.16.%'",
            r"SELECT h FROM conn WHERE regexp_like(id_orig_h, '^10\.0\.')",
        ],
    )
    def test_out_of_scope_prefix_rejected(self, sql):
        with pytest.raises(ValueError, match="Out-of-scope IP prefix"):
            sanitize_sql(sql)

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '10.220.40.%'",
            "SELECT COUNT(*) FROM conn WHERE id_orig_h LIKE '10.220.%'",
            "SELECT COUNT(*) FROM conn WHERE id_resp_h LIKE '45.83.193.%'",
        ],
    )
    def test_in_scope_and_public_prefixes_allowed(self, sql):
        """Over-blocking is a product defect: these must stay queryable."""
        assert sanitize_sql(sql) == sql


class TestDottedNonAddressAllowed:
    """A dotted-numeric token that is not a valid address must not be treated as
    an out-of-scope IP; rejecting it broke legitimate queries."""

    def test_version_like_value_allowed(self):
        sql = "SELECT * FROM conn WHERE version = '1.2.3.400'"
        assert sanitize_sql(sql) == sql
