"""Gate: every table the Lambda materializes must be documented to the LLM.

An undocumented table is an invisible table. The SQL-generating agent writes queries
from its prompt alone, so a table that exists in Glue but is missing from
SQL_GEN_PROMPT is dead weight -- the model cannot reference what it was never told
about, and it will hand-join the raw logs instead (expensively, and usually wrong).

This has happened TWICE. The known_* inventory tables were built and left
undocumented, then entity_context was built and left undocumented; both times the
tables sat unused in the catalog while the agent kept joining raw logs. It also
happened in reverse: the prompt described three dhcp columns (`uid`, `id_orig_h`,
`id_resp_h`) that do not exist, so every generated dhcp query failed until the
prompt was corrected against the real schema.

So this file asserts both directions of the contract:
  1. every module the Lambda rebuilds appears in the prompt, and
  2. the prompt's column list for those tables matches what the SQL actually emits.

Rule 2 is what catches the slow rot: a column added to entity_context.py without a
prompt update is invisible, and a column removed from the SQL but left in the prompt
makes the model emit a query that fails.
"""

import importlib.util
import os
import re
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
_LAMBDA = os.path.join(_ROOT, "lambda")
sys.path.insert(0, _LAMBDA)

HUNTER = os.path.join(_ROOT, "agents", "athena-hunter", "main.py")

# The tables the hourly Lambda materializes and re-points a stable view at.
MATERIALIZED = ("asset_classification", "entity_context", "device_links")


@pytest.fixture(scope="module")
def prompt():
    """The SQL_GEN_PROMPT text, read without importing the agent (which pulls in
    fastapi/httpx that are not installed in the test venv)."""
    src = open(HUNTER, encoding="utf-8").read()
    start = src.index("SQL_GEN_PROMPT")
    # The prompt is one long implicit-concatenation expression; take a generous
    # slice and let the substring assertions do the work.
    return src[start:start + 40000]


@pytest.fixture(scope="module")
def modules():
    mods = {}
    for name in MATERIALIZED:
        path = os.path.join(_LAMBDA, f"{name}.py")
        spec = importlib.util.spec_from_file_location(f"vis_{name}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mods[name] = mod
    return mods


def _emitted_columns(mod, name):
    """Column aliases the module's generated SQL actually produces.

    Read off the final SELECT list rather than a hand-kept constant, so the test
    tracks the code instead of a second copy of the truth.
    """
    catalog = {
        "conn": {"id_orig_h", "id_resp_h", "ts_datetime", "orig_bytes", "resp_bytes",
                 "id_orig_network_name", "id_resp_network_name", "id_orig_room_name",
                 "id_resp_room_name", "remote_country", "remote_city", "remote_asn",
                 "remote_organization", "dt"},
        "http": {"id_orig_h", "user_agent", "dt"},
        "ssl": {"id_orig_h", "server_name", "ja3", "ja3s", "dt"},
        "ssh": {"id_orig_h", "hassh", "hasshserver", "dt"},
        "dns": {"id_orig_h", "query", "dt"},
        "dhcp": {"mac", "assigned_addr", "host_name", "client_fqdn", "dt"},
        "software": {"host", "name", "software_type", "version_major",
                     "version_minor", "dt"},
        "alerts": {"orig_h", "alert_type", "alert_name", "severity", "ts_datetime", "dt"},
        "known_devices": {"host_ip", "mac", "vendor_mac", "dt"},
        "known_users": {"host_ip", "user_", "protocol", "dt"},
        "known_names": {"host_ip", "hostname", "dt"},
        "known_domains": {"host_ip", "domain", "dt"},
        "known_services": {"host_ip", "service", "port_num", "dt"},
        "uid_lookup": {"uid", "orig_h", "log_type", "dt"},
        "ntlm": {"id_orig_h", "username", "domainname", "dt"},
        "kerberos": {"id_orig_h", "client", "dt"},
        "asset_classification": {"ip", "mac", "vendor_mac", "hostname", "os_name",
                                 "device_type", "org_name", "mgmt_tooling",
                                 "randomized_mac", "network_name", "room_name",
                                 "connections", "mb_in", "mb_out", "first_seen",
                                 "last_seen", "confidence", "dt"},
        "dhcp_fp_lite": {"mac", "prl", "ts_datetime", "dt"},
        "rdp": {"id_orig_h", "rdfp_hash", "dt"},
        "vpn": {"id_orig_h", "ja3", "ja3s", "dt"},
    }
    builder = (getattr(mod, "build_entity_context_sql", None)
               or getattr(mod, "build_asset_classification_sql", None)
               or getattr(mod, "build_device_links_sql", None))
    sql = builder("db", "2026-08-01", catalog)
    if not sql:
        pytest.skip(f"{name} produced no SQL for the stub catalog")

    # Ask Athena's own dialect what the outermost SELECT projects. Regexing the SQL
    # tail was tried first and picked up CTE-internal aliases (members, strengths,
    # label), which are not output columns at all -- a test that lies about the
    # contract is worse than no test.
    sqlglot = pytest.importorskip("sqlglot")
    tree = sqlglot.parse_one(sql, dialect="trino")
    return {(e.alias_or_name or "").lower() for e in tree.selects}


class TestEveryMaterializedTableIsDocumented:
    @pytest.mark.parametrize("table", MATERIALIZED)
    def test_table_is_named_in_the_prompt(self, prompt, table):
        """The model cannot query a table it was never told exists."""
        assert f"- {table}:" in prompt, (
            f"{table} is materialized hourly but absent from SQL_GEN_PROMPT, so the "
            f"agent will never query it"
        )

    @pytest.mark.parametrize("table", MATERIALIZED)
    def test_table_is_listed_as_host_keyed(self, prompt, table):
        """These key on `ip`, not `orig_h`. Getting that wrong is the single most
        common generated-SQL failure against them."""
        section = prompt[prompt.index("(C) HOST-KEYED"):]
        section = section[:section.index("\\n\"") + 400]
        assert table in section, f"{table} missing from the HOST-KEYED join guidance"

    def test_device_links_evidence_is_marked_verbatim(self, prompt):
        """link_evidence is written for a human and names the fingerprint and its
        IP count. Paraphrasing it through the model drops the auditable part."""
        assert "link_evidence" in prompt
        assert "VERBATIM" in prompt


class TestPromptMatchesTheRealSchema:
    @pytest.mark.parametrize("table", MATERIALIZED)
    def test_no_column_is_emitted_but_undocumented(self, prompt, modules, table):
        """The slow-rot direction: a column added to the SQL without a prompt update
        is invisible to the agent, so the feature ships dead."""
        emitted = _emitted_columns(modules[table], table)
        section = prompt[prompt.index(f"- {table}:"):]
        section = section[:section.index("\\n\"")] if "\\n\"" in section else section
        # Only assert on the substantive columns; partition/plumbing names are noise.
        missing = sorted(c for c in emitted
                         if c not in section
                         and c not in {"dt", "ip", "true", "false", "null", "end",
                                       "varchar", "integer", "bigint", "double"}
                         and len(c) > 3)
        assert not missing, (
            f"{table} emits undocumented columns {missing}; add them to "
            f"SQL_GEN_PROMPT or the agent cannot use them"
        )

    @pytest.mark.parametrize("table", MATERIALIZED)
    def test_no_column_is_documented_but_absent(self, prompt, modules, table):
        """The other direction, which is worse: the prompt once described three dhcp
        columns that did not exist and every generated dhcp query failed."""
        emitted = _emitted_columns(modules[table], table)
        section = prompt[prompt.index(f"- {table}:"):]
        head = section[len(f"- {table}:"):]
        head = head[:head.index("(")] if "(" in head else head
        # The comma list before the parenthetical prose is the column contract.
        claimed = [c.strip().strip('"') for c in
                   re.sub(r'"\s*\n\s*"', "", head).split(",")]
        bogus = sorted(c for c in claimed
                       if c and re.fullmatch(r"[a-z_][a-z0-9_]*", c)
                       and c not in emitted)
        assert not bogus, (
            f"SQL_GEN_PROMPT claims {table} has columns {bogus} that the SQL does "
            f"not emit; generated queries referencing them will fail"
        )
