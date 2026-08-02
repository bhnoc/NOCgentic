"""Gates for entity_context (lambda/entity_context.py).

`uid_lookup` answers "what did this session do". This answers "what IS this host",
so a session can be pivoted to full entity context in ONE join instead of six.

The second hop exists because the known_* inventory tables do not carry the session
`uid`. They carry a `kuid` that appears in no session log and is per-observation
rather than per-host, so `host_ip` is the only real join key.

The property these gates protect above all else is NO FAN-OUT. Measured on live
data: `alerts` has up to 11,054 rows for one host and `known_services` up to 4,433,
so a naive alerts x services join produced 11,281,985 rows for a SINGLE host. Every
source must collapse to one row per host before anything is joined.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda"))

import entity_context as ec  # noqa: E402
import tool_taxonomy as tt  # noqa: E402

DB = "testdb"
DATE = "2026-08-01"


def _catalog(**extra):
    cat = {
        "asset_classification": {"ip", "mac", "vendor_mac", "hostname", "os_name",
                                 "device_type", "org_name", "mgmt_tooling",
                                 "randomized_mac", "network_name", "room_name",
                                 "connections", "mb_in", "mb_out", "first_seen",
                                 "last_seen", "confidence", "dt"},
        "alerts": {"orig_h", "alert_type", "alert_name", "severity", "ts_datetime", "dt"},
        "known_users": {"host_ip", "user_", "protocol", "dt"},
        "known_services": {"host_ip", "service", "port_num", "dt"},
        "known_names": {"host_ip", "hostname", "dt"},
        "known_domains": {"host_ip", "domain", "dt"},
        "uid_lookup": {"uid", "orig_h", "log_type", "dt"},
    }
    cat.update(extra)
    return cat


# The profiling sources are deliberately NOT in _catalog(): every gate above was
# written against that shape, and the base catalog doubles as the partial-catalog
# case proving the new columns degrade to NULL rather than vanishing.
_PROFILING = {
    "ssl": {"id_orig_h", "ja3", "ja3s", "server_name", "client_subject",
            "client_issuer", "client_cert_chain_fps", "dt"},
    "ssh": {"id_orig_h", "hassh", "hasshserver", "dt"},
    # `host` is a VARCHAR ip and the ONLY key on this table. Not id_orig_h.
    "software": {"ts_datetime", "ts", "host", "host_p", "software_type", "name",
                 "version_major", "version_minor", "version_minor2",
                 "version_minor3", "version_addl", "unparsed_version", "dt"},
    "conn": {"id_orig_h", "id_resp_h", "ts_datetime", "remote_country",
             "remote_city", "remote_asn", "remote_organization", "dt"},
    "ntlm": {"id_orig_h", "username", "hostname", "domainname", "dt"},
    "kerberos": {"id_orig_h", "client", "service", "dt"},
    "dns": {"id_orig_h", "query", "qtype_name", "rcode_name", "answers", "dt"},
    "dhcp": {"mac", "assigned_addr", "host_name", "client_fqdn", "domain", "dt"},
}

# Every CTE alias the full profiling catalog folds together, in join order. The
# top-level fold must be exactly one FULL OUTER JOIN per alias after the first.
_ALL_ALIASES = ("ac", "al", "ku", "ks", "kn", "kdom", "ul", "org", "ai", "sec",
                "own", "idom", "mtls", "home", "j3", "hsh", "sw", "du")

# column -> every catalog table that could populate it. domain_user has two because
# it merges ntlm and kerberos, so it only goes null when BOTH are gone.
_PROFILE_COLUMNS = {
    "org_confidence": ("ssl",),
    "org_reasons": ("ssl",),
    "home_region": ("conn",),
    "home_confidence": ("conn",),
    "home_reasons": ("conn",),
    "client_ja3": ("ssl",),
    "client_hassh": ("ssh",),
    "os_versions": ("software",),
    "domain_user": ("ntlm", "kerberos"),
    "org_tenant": ("ssl",),
    "org_tenant_sources": ("ssl",),
    # owner_name merges mDNS instance names with known_names hostnames, so it only
    # goes null when BOTH are gone.
    "owner_name": ("dns", "known_names"),
    "owner_name_source": ("dns", "known_names"),
    "owner_name_confidence": ("dns", "known_names"),
    "internal_domain": ("dns",),
    "internal_domain_confidence": ("dns",),
    "internal_domain_reasons": ("dns",),
    "client_cert_issuer_org": ("ssl",),
    "client_cert_class": ("ssl",),
    "client_cert_subject_hash": ("ssl",),
    "client_cert_reasons": ("ssl",),
    "ai_tools": ("ssl",),
    "security_tools": ("ssl",),
    # Both fall back across three sources, so they only go null when ALL are gone.
    "observed_hostnames": ("known_names", "dhcp", "dns"),
    "announced_domains": ("known_domains", "dns"),
}


def _profiling_catalog(**extra):
    cat = _catalog(**_PROFILING)
    cat.update(extra)
    return cat


def _cte(sql, alias):
    """The text of one CTE, so a gate can assert about that source alone."""
    start = sql.index(f"\n{alias} AS (") if f"\n{alias} AS (" in sql else sql.index(f"WITH {alias} AS (")
    tail = sql[start:]
    depth = 0
    for i, ch in enumerate(tail):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return tail[:i + 1]
    raise AssertionError(f"CTE {alias} is unterminated")


class TestNoFanOut:
    """The whole reason this is aggregate-first rather than a join of raw rows."""

    def test_every_source_aggregates_before_joining(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        # Each CTE must GROUP BY its host key: that is what guarantees one row.
        assert sql.count("GROUP BY") >= 7, "a source is not aggregating"

    def test_alerts_are_counted_not_expanded(self):
        """One host has 11,054 alerts. They must become a number, not 11,054 rows."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COUNT(*) alert_count_all" in sql
        assert "GROUP BY orig_h" in sql

    def test_services_are_counted_not_expanded(self):
        """One host has 4,433 services; crossed with its alerts that is 11.2M rows."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COUNT(DISTINCT service) service_count" in sql

    def test_top_n_lists_are_bounded(self):
        """An unbounded ARRAY_AGG on a busy host makes one enormous cell."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "SLICE(ARRAY_AGG" in sql
        assert "ARRAY_AGG(DISTINCT alert_name), 1," in sql or "SLICE" in sql


class TestNoiseFiltering:
    """DNS resolvers log tens of thousands of ET INFO 'Observed DNS Query' rows. The
    live feed already excludes those, and these counts have to agree with the
    sidebar or the same host reads as catastrophic in one view and quiet in another."""

    def test_informational_prefixes_are_excluded_from_the_headline_count(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "NOT LIKE 'ET INFO%'" in sql
        assert "NOT LIKE 'ETPRO INFO%'" in sql

    def test_raw_total_is_still_available(self):
        """Filtering must not destroy the information: a resolver's real volume is
        worth seeing if someone asks for it explicitly."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "alert_count_all" in sql
        assert "alert_count" in sql

    def test_high_severity_count_also_excludes_noise(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        high = sql[sql.index("high_alert_count") - 400:sql.index("high_alert_count")]
        assert "ET INFO" in high, "high_alert_count is counting informational rows"


class TestPartialCatalog:
    def test_returns_none_when_nothing_joinable_exists(self):
        assert ec.build_entity_context_sql(DB, DATE, {}) is None

    def test_a_missing_source_degrades_to_nulls(self):
        """A host should still get identity even if it has no alerts, and vice
        versa, so a partial catalog must not drop whole columns."""
        cat = _catalog()
        del cat["known_users"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"{DB}.known_users" not in sql
        assert "observed_users" in sql, "column vanished instead of becoming NULL"

    def test_alerts_only_catalog_still_builds(self):
        sql = ec.build_entity_context_sql(DB, DATE, {"alerts": {"orig_h", "alert_name",
                                                               "alert_type", "severity",
                                                               "ts_datetime", "dt"}})
        assert sql is not None
        assert "alert_count" in sql


class TestJoinSemantics:
    def test_full_outer_join_so_no_host_is_lost(self):
        """A host can be inventoried without alerting, or alert without ever being
        inventoried. Starting from one spine would silently drop the other kind."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "FULL OUTER JOIN" in sql
        assert "LEFT JOIN" not in sql

    def test_ip_is_coalesced_across_every_source(self):
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert "COALESCE(" in sql and " ip" in sql

    def test_partition_is_pinned(self):
        """Unpinned, this would scan every day in the catalog on every rebuild."""
        sql = ec.build_entity_context_sql(DB, DATE, _catalog())
        assert f"dt = '{DATE}'" in sql


class TestPivotColumns:
    """The columns that make the uid -> entity pivot worth a single query."""

    @pytest.mark.parametrize("col", [
        "hostname", "os_name", "org_name", "mac", "vendor_mac",   # identity
        "observed_users", "user_count",                            # accounts
        "service_count", "listening_ports",                        # exposure
        "alert_count", "high_alert_count", "top_alerts",           # risk
        "session_count", "log_type_count", "log_types",            # reach
    ])
    def test_column_is_present(self, col):
        assert col in ec.build_entity_context_sql(DB, DATE, _catalog())


class TestDDL:
    def test_table_is_per_day(self):
        assert ec.table_name(DATE) == "entity_context_2026_08_01"

    def test_ctas_targets_that_table(self):
        ddl = ec.build_ctas(DB, DATE, _catalog())
        assert ddl.startswith(f"CREATE TABLE {DB}.entity_context_2026_08_01 AS")

    def test_ctas_omits_external_location(self):
        """The workgroup enforces a centralized output path and rejects a CTAS that
        names its own."""
        assert "external_location" not in ec.build_ctas(DB, DATE, _catalog())

    def test_ctas_is_none_when_unsatisfiable(self):
        assert ec.build_ctas(DB, DATE, {}) is None


class TestProfileColumns:
    """The profile columns: org attribution WITH reasons, home-base inference, and
    the device fingerprints that link one device across networks."""

    @pytest.mark.parametrize("col", sorted(_PROFILE_COLUMNS))
    def test_column_is_present(self, col):
        assert col in ec.build_entity_context_sql(DB, DATE, _profiling_catalog())

    @pytest.mark.parametrize("col,sources", sorted(_PROFILE_COLUMNS.items()))
    def test_column_degrades_to_null_when_its_source_is_absent(self, col, sources):
        """PostCog is presence-gated on the column, not the table, so a dropped
        column breaks it where a null column just reads as 'not known'."""
        cat = _profiling_catalog()
        for source in sources:
            del cat[source]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"CAST(NULL AS VARCHAR) {col}" in sql, "column vanished instead of NULL"
        for source in sources:
            assert f"{DB}.{source}" not in sql

    def test_every_profile_column_is_null_on_the_base_catalog(self):
        """None of ssl/ssh/software/conn/ntlm/kerberos/dns exist there, so every
        column sourced from them must still ship, as NULL.

        Columns with a source the base catalog DOES carry (owner_name via known_names,
        observed_hostnames, announced_domains) are excluded -- they are covered by the
        parametrized degradation gate instead."""
        base = _catalog()
        sql = ec.build_entity_context_sql(DB, DATE, base)
        for col, sources in _PROFILE_COLUMNS.items():
            if any(s in base for s in sources):
                continue
            assert f"CAST(NULL AS VARCHAR) {col}" in sql

    def test_a_source_present_without_its_column_is_not_read(self):
        """The gate is column-level: an `ssl` predating ja3 would otherwise build a
        CTAS that fails, and one failed statement loses the whole rebuild."""
        cat = _profiling_catalog(ssl={"id_orig_h", "server_name", "dt"})
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert "CAST(NULL AS VARCHAR) client_ja3" in sql
        assert "org_reasons" in sql, "server_name evidence should still be read"

    def test_reasons_are_pipe_delimited_evidence(self):
        """PostCog shows these verbatim, so the separator is a contract."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        org = _cte(sql, "org")
        assert "' | '" in org
        assert "'okta'" in org and "'o365'" in org
        # The tenant is spliced in when one survived the denylist, so the evidence
        # reads okta:<tenant>@<tenant>.okta.com rather than just the SNI.
        assert "kind || ':' || COALESCE(tenant || '@', '') || sni" in org, (
            "reasons must name WHY, not just the SNI"
        )

    def test_org_confidence_is_a_bucket_not_a_number(self):
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        for bucket in ("'high'", "'medium'", "'low'"):
            assert bucket in org

    def test_home_region_comes_from_conn_not_the_geo_table(self):
        """The `geo` table has 4 rows. Using it would null out 13,000 hosts."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog(geo={"ip", "country", "dt"}))
        assert "remote_country" in _cte(sql, "home")
        assert f"{DB}.geo" not in sql

    def test_home_reasons_carries_the_percentage(self):
        """An inference an analyst cannot audit is worse than no inference."""
        home = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "home")
        assert "'% conns to '" in home
        assert "100.0" in home, "share must be a percentage, not a raw count"

    def test_remote_country_is_constrained_to_iso2(self):
        """`remote_country` is an unvalidated VARCHAR. Measured on dt=2026-08-01, only
        6.96M of 44.3M in-scope rows hold a real country code: 22.1M rows across 3,249
        IPs carry a 40-char hex hash and the rest stringified floats. Without this
        guard the majority share is usually a hash, so home_region shipped a hex blob
        as a host's country at medium or high confidence."""
        home = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "home")
        assert "REGEXP_LIKE(remote_country, '^[A-Z]{2}$')" in home, (
            "the ISO2 guard is gone; hashes will be reported as countries"
        )

    def test_home_reasons_makes_no_timezone_claim(self):
        """A UTC peak hour was tried and measured: it moves 4.12h between consecutive
        days for the same host, and 0 of 96 APAC-ccTLD hosts peaked in the APAC
        business day. It tracks the venue's schedule, not residency, so it is an
        unfalsifiable claim about where a real attendee lives."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert "tz:" not in sql, "timezone inference is back in home_reasons"
        assert "peak_hour" not in sql

    def test_fingerprints_are_the_dominant_value_per_host(self):
        """A device emits a dozen ja3s across its apps; only the top one is stable
        enough to match the same device on another network."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("j3", "hsh"):
            body = _cte(sql, alias)
            assert "ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC)" in body
            assert "WHERE rn = 1" in body


class TestSoftwareJoinsOnHost:
    """`software` keys on `host`, a VARCHAR ip. Nothing else in the catalog does
    this. Joining it on id_orig_h parses fine and returns an all-null column, so
    the regression is silent -- hence a gate rather than a comment."""

    def test_software_cte_keys_on_host(self):
        sw = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sw")
        assert '"host" ip' in sw
        assert 'GROUP BY "host"' in sw

    def test_software_cte_never_mentions_id_orig_h(self):
        sw = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sw")
        assert "id_orig_h" not in sw, "software has no id_orig_h; this yields all nulls"

    def test_host_is_double_quoted_because_it_is_reserved(self):
        """Backticks only work in DDL. In a SELECT they are a parse error."""
        sw = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sw")
        assert "`host`" not in sw
        assert "FROM " + DB + ".software" in sw

    def test_daily_churning_build_numbers_are_left_out(self):
        """version_minor2/minor3 are browser build numbers that roll every day, so
        including them rewrites the cell nightly without telling anyone anything."""
        sw = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sw")
        assert "version_minor2" not in sw
        assert "version_minor3" not in sw


class TestProfileSourcesDoNotFanOut:
    """The new sources are the biggest tables in the catalog: ssl is ~7M rows and
    conn ~40M. Each must collapse to one row per host in its own CTE before the
    FULL OUTER JOIN, exactly like the original seven."""

    def test_group_by_count_grows_with_the_new_ctes(self):
        base = ec.build_entity_context_sql(DB, DATE, _catalog())
        full = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert full.count("GROUP BY") > base.count("GROUP BY"), (
            "a new source joined raw rows instead of aggregating first"
        )

    def test_every_profiling_cte_aggregates_or_takes_one_row(self):
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("org", "home", "j3", "hsh", "sw", "du"):
            body = _cte(sql, alias)
            assert "GROUP BY" in body, f"{alias} does not aggregate"

    def test_join_shape_is_unchanged(self):
        """One FULL OUTER JOIN per source after the first, and nothing else. The
        owner-name CTE joins internally to gate on label rarity, so the assertion is
        scoped to the top-level fold rather than counting every JOIN in the file."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        top = sql[sql.index("\nSELECT\n  COALESCE("):]
        assert "LEFT JOIN" not in top
        assert top.count("FULL OUTER JOIN") == len(_ALL_ALIASES) - 1

    def test_new_ctes_pin_the_partition(self):
        """Unpinned, ssl and conn would scan every day in the catalog per rebuild."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("org", "home", "j3", "hsh", "sw", "du"):
            assert f"dt = '{DATE}'" in _cte(sql, alias), f"{alias} scans every partition"

    def test_evidence_lists_stay_bounded(self):
        """A host hitting hundreds of managed-endpoint SNIs must not make one
        enormous cell."""
        for alias in ("org", "sw", "du"):
            body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
            assert "SLICE(ARRAY_AGG" in body


class TestOpportunisticIdentity:
    """ntlm has 1 row and kerberos 20 at this show. Both are wired up anyway, but a
    populated domain_user is a gift, not something anything may depend on."""

    def test_either_source_alone_is_enough(self):
        for present, absent in (("ntlm", "kerberos"), ("kerberos", "ntlm")):
            cat = _profiling_catalog()
            del cat[absent]
            sql = ec.build_entity_context_sql(DB, DATE, cat)
            assert f"{DB}.{present}" in _cte(sql, "du")
            assert f"{DB}.{absent}" not in sql

    def test_both_sources_are_unioned_not_joined(self):
        """A join would multiply the two, and would drop hosts seen in only one."""
        du = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "du")
        assert "UNION ALL" in du
        assert " JOIN " not in du

    def test_ntlm_is_normalized_to_the_kerberos_principal_shape(self):
        """One column, two source formats. A backslash in a Trino literal is not
        escape-processed, so every consumer would have to guess if it was doubled."""
        du = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "du")
        assert "username || '@' || domainname" in du
        assert "\\" not in du


def _stem_rules():
    """The owner-stem regexes as Python patterns.

    The SQL ships them as Trino literals, so the '' escaping and the \\x{2019}
    unicode escape have to be undone to exercise the same grammar here. This is how
    a gate can assert on the RULE rather than on the presence of a substring.
    """
    out = []
    for rule in ec._OWNER_STEM_RULES:
        pat = rule.strip("'").replace("''", "'").replace(r"\x{2019}", "’")
        out.append(re.compile(pat))
    return out


def _extract_stem(label):
    for rx in _stem_rules():
        m = rx.match(label)
        if m and m.group(1):
            return m.group(1)
    return None


def _is_instance_named(query):
    pat = ec._MDNS_INSTANCE.strip("'")
    return re.match(pat, query) is not None


def _owner_emitted(label, n_ips, *, query=None):
    """The full owner_name gate as the SQL applies it, in order."""
    if query is not None and (".", "_sub.")[1] in query:
        return None
    if query is not None and not _is_instance_named(query):
        return None
    if label in ("", "-", "(empty)"):
        return None
    if any(w in label for w in ec._OWNER_STOPWORDS):
        return None
    if n_ips > ec._OWNER_MAX_IPS:
        return None
    return _extract_stem(label)


class TestOwnerNameRarityCeiling:
    """The measured failure this whole gate exists to prevent.

    Person-looking mDNS labels on 11-50 in-scope IPs (max 60 measured on
    dt=2026-08-01) are SHARED AirPlay / companion-link endpoints in session rooms --
    every single label above the ceiling resolved to _airplay or _companion-link.
    Emitting one there would attribute a staffer's name to up to 60 strangers.
    """

    def test_the_ceiling_is_a_documented_constant(self):
        assert isinstance(ec._OWNER_MAX_IPS, int)
        assert 1 <= ec._OWNER_MAX_IPS <= 10, "a ceiling above 10 admits shared AirPlay"

    def test_a_label_on_48_ips_yields_no_owner_name(self):
        """The exact shared-AirPlay case from the sweep."""
        assert _owner_emitted("firstname’s macbook pro", 48) is None

    def test_a_label_on_60_ips_yields_no_owner_name(self):
        """The worst measured spread."""
        assert _owner_emitted("firstname’s macbook pro", 60) is None

    def test_a_label_just_over_the_ceiling_is_refused(self):
        assert _owner_emitted("firstname’s mbp", ec._OWNER_MAX_IPS + 1) is None

    def test_a_rare_label_is_allowed(self):
        assert _owner_emitted("firstname’s mbp", 1) == "firstname"

    def test_the_sql_gates_on_the_ceiling(self):
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert f"<= {ec._OWNER_MAX_IPS}" in own, "the rarity ceiling is not enforced"
        assert "COUNT(DISTINCT ip) nip" in own

    def test_the_ceiling_binds_the_emitted_stem_not_just_the_label(self):
        """Measured: gating labels alone leaked. Two individually-rare labels
        ("<first>’s mbp" and "<first>s-iphone") share ONE stem, so 3 stems still
        reached 14 IPs -- above the ceiling -- until the stem was gated too."""
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "COUNT(DISTINCT ip) snip" in own
        assert f"snip <= {ec._OWNER_MAX_IPS}" in own


class TestOwnerNameGrammar:
    """mDNS instance names are the naming backbone, but only some shapes name a human."""

    def test_unicode_apostrophe_possessives_are_matched(self):
        """MEASURED: 58,170 in-scope .local rows use U+2019 and only 2,992 use ASCII.
        A rule written with "'s" alone silently misses 95% of the evidence."""
        assert _extract_stem("firstname’s macbook pro") == "firstname"

    def test_ascii_apostrophe_possessives_are_also_matched(self):
        assert _extract_stem("firstname's macbook pro") == "firstname"

    def test_the_unicode_codepoint_is_in_the_shipped_sql(self):
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert r"\x{2019}" in own, "only ASCII apostrophes would be matched"

    def test_possessive_hostname_shape_is_matched(self):
        assert _extract_stem("firstnames-iphone") == "firstname"

    def test_hyphenated_device_shape_is_matched(self):
        assert _extract_stem("firstname-macbook") == "firstname"

    def test_desktop_tag_shape_is_matched(self):
        """DESKTOP-<tag> is a Windows default. The tag is not a person's name, but it
        is a stable per-device label, so it is emitted at low confidence rather than
        thrown away."""
        assert _extract_stem("desktop-a1b2c3d") == "a1b2c3d"

    def test_a_label_naming_nobody_yields_nothing(self):
        for label in ("macbook pro", "iphone", "living room", "hp officejet"):
            assert _extract_stem(label) is None, label


class TestOwnerNameExcludesNonPeople:
    def test_a_bare_service_type_is_not_instance_named(self):
        """'_companion-link._tcp.local' is a browse query on 1,903 in-scope IPs and
        names nobody. 484,407 of the in-scope .local rows are that one query."""
        assert not _is_instance_named("_companion-link._tcp.local")
        assert _owner_emitted("_companion-link", 1,
                              query="_companion-link._tcp.local") is None

    def test_an_instance_named_record_is_accepted(self):
        q = "firstname’s mbp._companion-link._tcp.local"
        assert _is_instance_named(q)
        assert _owner_emitted("firstname’s mbp", 1, query=q) == "firstname"

    def test_sub_subtype_records_yield_no_owner_name(self):
        """'._sub.' records are subtype registrations: 38,023 in-scope .local rows."""
        q = "_printer._sub._http._tcp.local"
        assert _owner_emitted("_printer", 1, query=q) is None

    def test_the_sql_excludes_sub_and_requires_an_instance_name(self):
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "NOT LIKE '%._sub.%'" in own
        assert "[^_.][^.]*" in own, "bare service types are not excluded structurally"

    @pytest.mark.parametrize("label", [
        "conference room speaker", "apple tv", "chromecast-1234", "lobby display",
        "hp laserjet printer", "guest ipad", "shared macbook",
    ])
    def test_appliance_and_room_labels_yield_no_owner_name(self, label):
        assert _owner_emitted(label, 1) is None, label

    def test_confidence_is_a_bucket_with_a_source(self):
        """Invariant 4: an inferred field an analyst cannot audit is not shippable."""
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        for bucket in ("'high'", "'medium'", "'low'"):
            assert bucket in own
        assert "owner_name_source" in own
        assert "' ip, stem '" in own, "the source must show HOW RARE the label was"


class TestOrgInfraLabelDenylist:
    """Label 1 of an SSO hostname is the tenant, but only when it is not an infra
    word. Measured: 3 of slack's label-1 values, 4 of zoom's and 2 of okta's are
    infra words, and duo's real shapes are <t>.sso.duosecurity.com (55 hosts) and
    <t>.login.duosecurity.com (48) -- so a naive rule fills org with "sso"/"login".
    """

    @pytest.mark.parametrize("label", ["login", "sso", "www", "auth", "id", "portal",
                                       "mail", "vpn", "autodiscover", "outlook"])
    def test_generic_labels_are_denied(self, label):
        assert label in ec._INFRA_LABELS

    def test_the_denylist_is_applied_in_the_sql(self):
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        for label in ("'login'", "'sso'", "'www'"):
            assert label in org, f"{label} would be emitted as a company name"
        assert "NOT IN (" in org

    def test_a_real_tenant_is_not_denied(self):
        for t in ("acmecorp", "contoso", "initech"):
            assert t not in ec._INFRA_LABELS

    def test_very_short_and_numeric_tenants_are_refused(self):
        """A 1-2 char label and a pure-digit label are shard ids, not companies."""
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert "LENGTH(raw_tenant) >= 3" in org
        assert "'^[0-9]+$'" in org


class TestOrgTenantShareCeiling:
    """A denylist cannot win alone, and this is what it missed.

    Measured on dt=2026-08-01: the top slack label-1 values were `edgeapi` (463 hosts,
    93% of the family) and `wss-primary` (356, 71%) -- Slack-desktop infrastructure in
    no denylist -- outranking the REAL tenants blackhatnoc (98, 20%) and specterops
    (18, 4%). org_tenant is MAX_BY(tenant, n), so the infrastructure host WON and
    hundreds of hosts were attributed to an employer named "edgeapi".

    The structural insight: a shared endpoint is shared BY DEFINITION, so it trends
    toward 100% of its family's hosts, while a real employer only covers its own staff.
    """

    def test_the_ceiling_sits_in_the_measured_gap(self):
        """Above the largest true tenant (blackhatnoc, ~20%) and below the smallest
        measured infra label (files, 51%). A threshold tuned to the edge would be
        one new deployment away from being wrong."""
        assert 20 < ec._TENANT_MAX_FAMILY_SHARE < 51

    def test_the_ceiling_is_applied_in_the_sql(self):
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert f"<= {ec._TENANT_MAX_FAMILY_SHARE}" in org
        assert "label_hosts" in org and "family_hosts" in org

    def test_the_denominator_is_distinct_hosts_not_rows(self):
        """THE BUG THIS GATE EXISTS FOR. One host contributing several labels appears
        once per label, so slack's 500 hosts produce 2,275 (host,label) rows. Measured
        against the ROW count, edgeapi scored 463/2275 = 20% and sailed under a 25%
        ceiling; against distinct hosts it is 463/500 = 93% and is refused. The gate
        was silently useless until the denominator was fixed."""
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert "DENSE_RANK() OVER (PARTITION BY kind ORDER BY ip)" in org, (
            "family_hosts must count distinct ips, not rows")
        assert "MAX(ip_rank) OVER (PARTITION BY kind) family_hosts" in org

    def test_the_share_is_computed_per_family_not_globally(self):
        """A label's reach only means something relative to ITS OWN family: 50 hosts is
        most of okta's 75 but a fraction of sharepoint's 506."""
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert "PARTITION BY kind, raw_tenant" in org
        assert "PARTITION BY kind)" in org

    @pytest.mark.parametrize("label", [
        "us05web", "us04web", "us02web", "eu01web",   # zoom's numbered join pool
        "194775-ipv4v6fdse",                          # sharepoint machine id
        "api-6ff79abe",                               # slack machine id
        "us1", "ap2", "gw01",                         # bare region/shard ids
    ])
    def test_infrastructure_shapes_are_refused_structurally(self, label):
        """These cannot be a literal list: zoom keeps adding regions, so every new
        us<NN>web would silently become an "employer" until somebody noticed."""
        assert any(re.search(p, label) for p in ec._INFRA_PATTERNS), label

    def test_the_patterns_reach_the_generated_sql(self):
        """Asserting on the CONSTANT is not enough -- it passes whether or not
        _not_infra actually emits the patterns. Caught by mutation: removing them from
        _not_infra left the whole suite green."""
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        for p in ec._INFRA_PATTERNS:
            assert p in org, f"pattern {p} is never applied in SQL"
        assert org.count("NOT REGEXP_LIKE(LOWER(") >= len(ec._INFRA_PATTERNS)

    @pytest.mark.parametrize("tenant", [
        # Every one of these is a REAL organisation measured on this network.
        "blackhatnoc", "specterops", "corelight", "paloaltonetworks", "informaplc",
        "informaplc-my", "spectertrn", "gtkcybercommunity", "freemanco", "splunk",
        "swapcard", "crowdstrike", "se-training-bh-2026", "mgmresorts", "experian",
        "tenet", "packsize", "cisco-my",
    ])
    def test_real_tenants_survive_every_gate(self, tenant):
        """The cost of over-filtering is losing the employer attribution entirely, so
        the patterns and the denylist are both checked against measured true positives.
        `informaplc-my` and `cisco-my` matter: sharepoint's -my suffix is a PERSONAL
        OneDrive site and still names the employer."""
        assert tenant not in ec._INFRA_LABELS, f"{tenant} is denylisted"
        for p in ec._INFRA_PATTERNS:
            assert not re.search(p, tenant), f"{tenant} matches infra pattern {p}"

    @pytest.mark.parametrize("label", [
        "edgeapi", "wss-primary", "wss-backup", "wss-mobile",
        "zpns", "mpapis", "xmppapi", "file-paa", "contactservice", "ark", "stderr-my",
    ])
    def test_long_tail_infra_below_the_ceiling_is_denylisted(self, label):
        """These cover FEWER hosts than the largest real tenant (wss-mobile 14%,
        ark 21% vs blackhatnoc ~20%), so no ceiling separates them and the share gate
        genuinely cannot reach them. Naming them is the right tool."""
        assert label in ec._INFRA_LABELS


class TestAutodiscoverIsNotShadowed:
    """_ORG_SNI is a FIRST-MATCH CASE and autodiscover is the only PREFIX rule in a
    table of suffix rules, so the two overlap. When autodiscover sat LAST,
    autodiscover.acme.onmicrosoft.com matched `entra` first, its _TENANT_OVERRIDE never
    fired, and the tenant read the literal word "autodiscover" -> denylisted -> NULL.
    The one SNI shape that names the employer outright produced nothing."""

    def test_autodiscover_is_evaluated_first(self):
        kinds = [k for k, _, _ in ec._ORG_SNI]
        assert kinds[0] == "autodiscover", (
            f"autodiscover is at index {kinds.index('autodiscover')}; any suffix rule "
            "ahead of it shadows the prefix rule")

    def test_it_precedes_every_family_it_can_overlap(self):
        """Concretely: entra owns onmicrosoft.com and o365 owns sharepoint.com, both of
        which can carry an autodiscover. prefix."""
        kinds = [k for k, _, _ in ec._ORG_SNI]
        for overlapping in ("entra", "o365"):
            assert kinds.index("autodiscover") < kinds.index(overlapping)

    def test_the_override_is_reachable_in_the_generated_sql(self):
        """Both the kind CASE and the tenant CASE are emitted in table order, so
        autodiscover's arm must be the FIRST arm of each. Checking the tenant CASE
        specifically: that is the one whose arms carry _TENANT vs the override, and it
        only contains the naming families."""
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        override = ec._TENANT_OVERRIDE["autodiscover"]
        assert override in org
        # The tenant CASE is the block whose arms are 'THEN <tenant expr>'. Its first
        # arm must be autodiscover's, so the override precedes every plain _TENANT arm.
        tenant_case = org[org.index("END kind,"):org.index("END raw_tenant")]
        assert override in tenant_case, "the override is not in the tenant CASE"
        assert tenant_case.index(override) < tenant_case.index(ec._TENANT), (
            "a plain label-1 arm precedes autodiscover's override, so it never fires")


class TestPartitionsArePinned:
    """The stable `asset_classification` / `entity_context` names are VIEWS that UNION
    every retained day, not pointers at today. Reading them without a dt filter silently
    mixes days: measured 108,686 asset_classification rows on 2026-08-01 and 90,889 on
    08-02, and 108,835 of 138,461 entity_context ips appear on BOTH days."""

    def test_the_ac_cte_pins_the_partition(self):
        """It was the ONLY cte of 22 in this file without a dt filter, so
        SUM(connections)/mb_in/mb_out became multi-day totals stamped with one date."""
        ac = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "ac")
        assert f"dt = '{DATE}'" in ac, "asset_classification is read across every day"

    def test_every_cte_that_reads_a_table_pins_the_partition(self):
        """Generalised so the next CTE added cannot repeat it."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("ac", "al", "ku", "ks", "kn", "kdom", "ul", "org", "ai", "sec",
                      "own", "home", "idom", "mtls", "sw"):
            body = _cte(sql, alias)
            if f"{DB}." not in body:
                continue
            assert f"dt = '{DATE}'" in body, f"{alias} scans every partition"


class TestOrgBroadening:
    """okta+sharepoint alone reached 806 hosts. These families were each measured
    present on dt=2026-08-01 before being added."""

    @pytest.mark.parametrize("kind", [
        "okta", "o365", "entra", "ping", "onelogin", "duo", "jumpcloud", "auth0",
        "slack", "zoom", "atlassian", "jamf", "kandji", "intune", "workspaceone",
        "netskope", "zscaler", "cloudflare_zt", "autodiscover",
    ])
    def test_family_is_recognised(self, kind):
        assert any(k == kind for k, _, _ in ec._ORG_SNI), kind

    def test_there_are_at_least_sixteen_families(self):
        assert len(ec._ORG_SNI) >= 16

    def test_only_tenant_naming_families_set_org_tenant(self):
        """An EDR/MDM/SASE endpoint proves someone's IT owns the box; it does not name
        the company, so it must corroborate rather than attribute."""
        naming = {k for k, n, _ in ec._ORG_SNI if n}
        assert "okta" in naming and "o365" in naming
        for corroborating in ("jamf", "intune", "netskope", "zscaler", "edr", "duo"):
            assert corroborating not in naming, corroborating

    def test_gworkspace_names_no_company(self):
        """268 hosts but only 6 distinct SNIs: one shared Google endpoint every
        Workspace tenant hits, so label 1 is Google's, not the employer's."""
        naming = {k for k, n, _ in ec._ORG_SNI if n}
        assert "gworkspace" not in naming

    def test_autodiscover_takes_the_domain_after_the_prefix(self):
        """autodiscover.<corp>.tld puts the employer in label 2, so label 1 is
        literally the word "autodiscover" -- the one family needing an override."""
        assert "autodiscover" in ec._TENANT_OVERRIDE
        expr = ec._TENANT_OVERRIDE["autodiscover"]
        assert expr != ec._TENANT, "label 1 here is the word 'autodiscover'"
        assert "^autodiscover" in expr, "the prefix must be stripped, not captured"

    def test_reasons_name_the_family_and_the_tenant(self):
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert "org_tenant" in org and "org_tenant_sources" in org

    def test_confidence_counts_tenant_naming_evidence(self):
        org = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "org")
        assert "tenant IS NOT NULL THEN kind" in org


class TestInternalDomain:
    """A laptop still configured for its employer's AD leaks that domain via
    wpad / _ldap._tcp / _msdcs. Measured in-scope: 206 hosts, 485 domains. Genuinely
    additive -- these are overwhelmingly NXDOMAIN, so no TLS handshake ever happens
    and no server_name can ever produce them."""

    def test_the_three_leak_shapes_are_matched(self):
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        assert "wpad" in idom
        assert "_ldap" in idom
        assert "_msdcs" in idom

    def test_local_is_excluded(self):
        """mDNS .local is not an employer's AD domain; it is every Apple device."""
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        pat = re.search(r"\(\^\|[^)]*\)\(([a-z|]+)\)\$", idom)
        assert pat, "the exclusion regex is gone"
        excluded = pat.group(1).split("|")
        assert "local" in excluded
        for junk in ("arpa", "lan", "internal"):
            assert junk in excluded, junk

    def test_the_venues_own_domain_is_excluded(self):
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        assert "blackhat" in idom, "the venue's own domain would be read as an employer"

    def test_ad_evidence_outranks_wpad(self):
        """_msdcs / _ldap are Active Directory itself and only a domain member emits
        them. wpad is a plain DHCP search-suffix artifact, so it is weaker."""
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        assert "'msdcs','ldap'" in idom
        assert "'high'" in idom and "'medium'" in idom

    def test_a_reasons_column_names_the_leak_kind(self):
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        assert "kind || ':' || dom" in idom

    def test_a_bare_tld_is_refused(self):
        """The regex requires at least one dot, so a search suffix that is a single
        label cannot become an "employer domain"."""
        idom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "idom")
        assert "[a-z0-9-]+)+" in idom, "the domain regex no longer requires a dot"
        assert "dom <> ''" in idom


class TestClientCertPrivacy:
    """A client_subject DN carries a person's name, work email, employer and office in
    ONE string. Measured in-scope: 28 hosts have an emailAddress= in it and 175 an O=.
    The raw DN must never land in a table an analyst can SELECT *."""

    def test_the_raw_dn_is_never_selected(self):
        mtls = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "mtls")
        assert "SHA256" in mtls, "the DN is not hashed"
        assert "client_subject" in mtls
        # The ONLY appearances of client_subject are inside the hash and the presence
        # guard -- never as a bare projected value.
        assert "TO_UTF8(client_subject)" in mtls
        assert " client_subject," not in mtls
        assert "client_subject dn" not in mtls

    def test_the_hash_is_the_shipped_column(self):
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert "client_cert_subject_hash" in sql
        assert "client_cert_subject_dn" not in sql
        assert "client_subject client" not in sql

    def test_the_hash_is_stable_and_lowercase_hex(self):
        """A consumer joining two sightings of one certificate needs a stable form,
        and TO_HEX returns UPPERCASE, which measured as an inconsistent contract."""
        mtls = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "mtls")
        assert "LOWER(TO_HEX(SHA256(TO_UTF8(client_subject))))" in mtls

    def test_an_absent_subject_hashes_to_null_not_to_a_hash_of_the_marker(self):
        """Zeek writes '(empty)'. Hashing it would give every certless host the same
        non-null "certificate", which reads as evidence where there is none."""
        mtls = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "mtls")
        assert "CASE WHEN client_subject IS NOT NULL" in mtls

    def test_the_issuer_org_is_kept_because_it_names_no_human(self):
        mtls = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "mtls")
        assert "O=([^,]+)" in mtls
        assert "client_cert_issuer_org" in mtls

    def test_the_class_is_coarse(self):
        """Measured in-scope: 105 hosts / 48 orgs employer-specific, 106 SASE, 14 MDM.
        A coarse class is what an analyst needs; a finer one just re-leaks the DN."""
        mtls = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "mtls")
        for cls in ("'mdm'", "'sase'", "'public_ca'", "'employer_specific'",
                    "'unnamed_issuer'"):
            assert cls in mtls

    def test_a_reasons_column_exists(self):
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert "client_cert_reasons" in sql


class TestEmptyMarkerIsAbsent:
    """Zeek writes '-' AND the literal string '(empty)'. The latter appears on 1,910
    in-scope IPs (2,376 in ssl's client-cert columns alone) and the old _present()
    filter missed it, so every consumer treated the text "(empty)" as a real value."""

    def test_present_filters_the_empty_marker(self):
        assert "(empty)" in ec._present("x")

    def test_present_still_filters_dash_and_blank(self):
        p = ec._present("x")
        assert "'-'" in p and "''" in p
        assert "x IS NOT NULL" in p

    def test_the_marker_is_filtered_everywhere_a_value_is_read(self):
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert sql.count("'(empty)'") >= 8, "a source still admits the empty marker"

    def test_the_new_sources_filter_it(self):
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("own", "idom", "mtls", "org"):
            assert "'(empty)'" in _cte(sql, alias), f"{alias} admits '(empty)'"


class TestNewSourcesDoNotFanOut:
    """dns is ~86M rows/day and ssl ~7M. Invariant 1: exactly one row per host."""

    @pytest.mark.parametrize("alias", ["own", "idom", "mtls"])
    def test_each_new_cte_aggregates_to_one_row_per_host(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "GROUP BY ip" in body, f"{alias} does not collapse to one row per host"

    @pytest.mark.parametrize("alias", ["own", "idom", "mtls"])
    def test_each_new_cte_pins_the_partition(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert f"dt = '{DATE}'" in body, f"{alias} scans every partition"

    def test_owner_name_is_one_value_not_a_list(self):
        """A host announcing several instance names must still get ONE owner, chosen
        by score, rather than a concatenation that reads as several people."""
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "MAX_BY(stem, score) owner_name" in own

    def test_the_dns_source_is_read_once_for_both_columns(self):
        """owner_name and internal_domain both come from dns, in separate CTEs, so
        neither can multiply the other."""
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        assert _cte(sql, "own") != _cte(sql, "idom")

    def test_dhcp_corroboration_cannot_multiply_rows(self):
        """The DHCP stem join is the one inner join in the owner path. It is
        aggregated to a MAX flag, so a mac with several leases cannot fan out."""
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "MAX(CASE WHEN d.stem IS NOT NULL" in own


class TestNewColumnsSurviveAPartialCatalog:
    """Invariant 3: a missing column degrades to NULL, never a dropped column and
    never a failing CTAS. One failed statement loses the whole rebuild."""

    def test_ssl_without_client_cert_columns_still_builds(self):
        cat = _profiling_catalog(ssl={"id_orig_h", "ja3", "server_name", "dt"})
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert "CAST(NULL AS VARCHAR) client_cert_subject_hash" in sql
        assert "client_subject" not in sql
        assert "org_reasons" in sql, "server_name evidence should still be read"

    def test_dns_absent_leaves_owner_name_to_known_names(self):
        cat = _profiling_catalog()
        del cat["dns"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert "CAST(NULL AS VARCHAR) internal_domain" in sql
        assert "owner_name" in sql
        assert f"{DB}.known_names" in _cte(sql, "own")

    def test_dhcp_absent_still_yields_owner_name_without_corroboration(self):
        cat = _profiling_catalog()
        del cat["dhcp"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        own = _cte(sql, "own")
        assert f"{DB}.dhcp" not in sql
        assert "owner_name" in own
        assert "0 corroborated" in own

    def test_ctas_still_omits_external_location(self):
        ddl = ec.build_ctas(DB, DATE, _profiling_catalog())
        assert "external_location" not in ddl

    @pytest.mark.parametrize("col,alias", [("ai_tools", "ai"),
                                           ("security_tools", "sec")])
    def test_ssl_without_server_name_drops_the_sni_columns_to_null(self, col, alias):
        """An `ssl` predating server_name must not build a CTAS that fails: one failed
        statement loses the whole hourly rebuild."""
        cat = _profiling_catalog(ssl={"id_orig_h", "ja3", "dt"})
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"CAST(NULL AS VARCHAR) {col}" in sql
        assert f"\n{alias} AS (" not in sql
        assert "client_ja3" in sql, "ja3 should still be read"


class TestSniNeedlesAreDomainAnchored:
    """The substring trap this codebase keeps getting bitten by. Measured on
    dt=2026-08-01, in-scope: 'cros' matched "Microsoft-CryptoAPI" and reported ChromeOS
    on a Windows box; a bare 'cato' matches lcdn-locator.apple.com (950 IPs), 'eset'
    matches sync.resetdigital.co (78), and a bare 'okta' matches
    okta-featureflag-edge.azureedge.net (13) -- which is Azure, not Okta.
    """

    def test_dom_matches_the_apex_and_any_subdomain(self):
        pred = ec._dom("anthropic.com")
        assert "sni = 'anthropic.com'" in pred
        assert "sni LIKE '%.anthropic.com'" in pred

    def test_dom_never_emits_a_bare_leading_wildcard(self):
        """`LIKE '%anthropic.com'` would match evilanthropic.com; the dot is the
        boundary and it is what makes the needle a domain rather than a substring."""
        rules = tt.ai_label_rules() + tt.security_label_rules()
        for _, domains in rules:
            pred = tt._any_pred("fqdn", domains)
            assert "LIKE '%anthropic" not in pred
            for needle in ("okta", "cursor", "jamf", "claude", "gemini"):
                assert f"LIKE '%{needle}" not in pred, needle

    def test_the_shipped_sql_anchors_every_new_needle(self):
        """Only the MATCHING predicates are in scope. `fqdn LIKE` is a needle; the
        `query LIKE '%.local%'` source filters are exclusions that prune rows before
        matching, and a bare wildcard is correct there.
        """
        sql = ec.build_entity_context_sql(DB, DATE, _profiling_catalog())
        for alias in ("ai", "sec"):
            body = _cte(sql, alias)
            needles = re.findall(r"fqdn LIKE '([^']+)'", body)
            assert needles, f"{alias} has no fqdn needles at all"
            # Every needle is boundary-anchored ('%.<domain>'), never '%needle%'.
            for like in needles:
                assert not (like.startswith("%") and like.endswith("%")), like
                assert like.startswith("%."), like

    def test_okta_is_never_matched_on_an_azure_hostname(self):
        """okta-featureflag-edge.azureedge.net is Azure, not Okta. The taxonomy
        deliberately omits Okta entirely (entity_context's _ORG_SNI already owns those
        domains for org attribution), so the guarantee here is that nothing in the
        security table claims that host."""
        assert tt.classify_security("okta-featureflag-edge.azureedge.net") is None
        assert tt.classify_security("okta.com") is None, (
            "Okta is deliberately excluded; see the taxonomy's note on double-counting")

    def test_cursor_does_not_match_an_unrelated_hostname(self):
        """'cursor' as a bare substring is the same class of bug as 'cros'."""
        assert tt.classify_ai("cursor.sh") == ("Cursor", "coding")
        assert tt.classify_ai("api2.cursor.sh") == ("Cursor", "coding")
        assert tt.classify_ai("notcursor.sh") is None
        assert tt.classify_ai("mycursor.example.com") is None

    @pytest.mark.parametrize("name,rules", [
        ("ai", tt.ai_label_rules()),
        ("security", tt.security_label_rules()),
    ])
    def test_no_earlier_needle_shadows_a_later_one(self, name, rules):
        """First match wins, and the needle is a SUFFIX rule, so a broad domain placed
        ahead of a narrower one under it makes the narrower entry dead code that can
        never fire. This gate caught LangChain('langchain.com') shadowing
        LangSmith('smith.langchain.com') -- a silently unreachable product.

        It also guards the class REORDER: security_label_rules() re-sequences the table
        by SECURITY_CLASS_ORDER, so an ordering change could introduce a shadow that
        does not exist in the table as written.
        """
        shadows = []
        for i, (early, early_domains) in enumerate(rules):
            for late, late_domains in rules[i + 1:]:
                for ld in late_domains:
                    for ed in early_domains:
                        if ld == ed or ld.endswith("." + ed):
                            shadows.append(f"{early}({ed}) shadows {late}({ld})")
        assert not shadows, f"{name}: unreachable entries: " + "; ".join(shadows)

    @pytest.mark.parametrize("name,rules", [
        ("ai", tt.ai_label_rules()),
        ("security", tt.security_label_rules()),
    ])
    def test_every_entry_is_reachable_by_its_own_domains(self, name, rules):
        """The end-to-end form of the shadow gate: every domain in the table must
        classify to the product that declares it, apex and subdomain both."""
        classify = tt.classify_ai if name == "ai" else tt.classify_security
        prefixed = name == "security"
        for label, domains in rules:
            want = label.split(":", 1)[1] if prefixed else label
            for d in domains:
                for host in (d, "sub." + d):
                    got = classify(host)
                    assert got is not None, f"{host} ({label}) matches nothing"
                    assert got[0] == want, f"{host} -> {got[0]}, declared by {want}"

    def test_the_measured_substring_traps_are_all_refused(self):
        """Every one of these was measured matching a bare-substring rule on live
        traffic. lcdn-locator.apple.com alone is 950 hosts."""
        for host in ("lcdn-locator.apple.com",          # matched 'cato'
                     "sync.resetdigital.co",            # matched 'eset'
                     "okta-featureflag-edge.azureedge.net",
                     "mail.google.com",                 # matched '%ai%' via "m-ai-l"
                     "sync.programmaticx.ai",           # adtech on a .ai TLD
                     "dns.nrich.ai",
                     "sync.theagenticx.ai",
                     "secure.insightexpressai.com"):
            assert tt.classify_ai(host) is None, host
            assert tt.classify_security(host) is None, host


class TestAiTools:
    """The widest-reaching new signal in the table. Measured in-scope on dt=2026-08-01:
    ChatGPT 487 hosts, Claude 450, Copilot 293, Gemini 170, Cursor 39, Perplexity 25.
    """

    def test_the_column_is_present(self):
        assert "ai_tools" in ec.build_entity_context_sql(DB, DATE, _profiling_catalog())

    @pytest.mark.parametrize("host,product", [
        ("chatgpt.com", "ChatGPT"),
        ("ab.chatgpt.com", "ChatGPT"),
        ("api.anthropic.com", "Claude"),
        ("claude.ai", "Claude"),
        ("downloads.claude.ai", "Claude"),
        ("bridge.claudeusercontent.com", "Claude"),
        ("api.individual.githubcopilot.com", "GitHub Copilot"),
        ("copilot.microsoft.com", "Microsoft Copilot"),
        ("gemini.google.com", "Gemini"),
        ("appsgenaiserver-pa.clients6.google.com", "Gemini"),
        ("api2.cursor.sh", "Cursor"),
        ("perplexity.ai", "Perplexity"),
        # The categories the old 6-product list could not see at all.
        ("ollama.com", "Ollama"),
        ("registry.ollama.ai", "Ollama"),
        ("versions-prod.lmstudio.ai", "LM Studio"),
        ("openrouter.ai", "OpenRouter"),
        ("huggingface.co", "Hugging Face"),
        ("gnar.grammarly.com", "Grammarly"),
        ("cloud.langfuse.com", "Langfuse"),
    ])
    def test_every_measured_product_is_recognised(self, host, product):
        got = tt.classify_ai(host)
        assert got is not None, f"{host} matched nothing"
        assert got[0] == product, f"{host} -> {got[0]}, expected {product}"

    def test_the_local_runner_class_exists_and_is_populated(self):
        """A host running Ollama does inference ON ITSELF, which is a different risk
        conversation from a host calling a hosted API. ollama.com was measured at 88
        hosts -- the second-largest AI signal on the network."""
        runners = [l for l, k, _ in tt.AI_TOOLS if k == "local_runner"]
        assert "Ollama" in runners
        assert tt.classify_ai("ollama.com") == ("Ollama", "local_runner")

    def test_gemini_is_anchored_on_full_hosts_not_shared_google_infra(self):
        """clients6.google.com and googleapis.com are shared Google infrastructure. A
        suffix match on either would claim Gemini for most of the 1,236 hosts that
        touch google.com."""
        assert tt.classify_ai("appsgenaiserver-pa.clients6.google.com") is not None
        for shared in ("clients6.google.com", "googleapis.com", "www.google.com",
                       "mail.google.com", "storage.googleapis.com"):
            assert tt.classify_ai(shared) is None, shared

    def test_jetbrains_ide_traffic_is_not_an_ai_signal(self):
        """jetbrains.com (52 hosts) is the IDE fetching plugins and checking licences.
        Only jetbrains.ai is the AI Assistant."""
        assert tt.classify_ai("jetbrains.ai") == ("JetBrains AI", "coding")
        assert tt.classify_ai("plugins.jetbrains.com") is None

    def test_github_browsing_is_not_copilot(self):
        """github.com is 442 hosts -- everyone browsing repos."""
        assert tt.classify_ai("github.com") is None
        assert tt.classify_ai("api.individual.githubcopilot.com")[0] == "GitHub Copilot"

    def test_the_list_is_count_ranked(self):
        """A host's real assistant is the one it handshakes with most; a single stray
        CDN hit must not lead the cell."""
        ai = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "ai")
        assert "ORDER BY n DESC" in ai
        assert "COUNT(*) n" in ai

    def test_the_list_is_pipe_delimited(self):
        ai = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "ai")
        assert "' | '" in ai

    def test_the_list_is_slice_capped(self):
        """Invariant 4: a 60-entry cell is not read, it is scrolled past."""
        ai = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "ai")
        assert f"SLICE(ARRAY_AGG(label ORDER BY n DESC), 1, {ec._TOP_N})" in ai

    def test_the_third_party_copilot_saas_is_not_claimed_as_microsofts(self):
        """copilot.com is an unrelated client-portal product. Attributing it to GitHub
        Copilot would report an AI assistant on a host that never touched one."""
        assert tt.classify_ai("copilot.com") is None
        assert tt.classify_ai("app.copilot.com") is None
        assert tt.classify_ai("copilot.microsoft.com")[0] == "Microsoft Copilot"

    def test_the_office_portal_is_not_a_copilot_signal(self):
        """m365.cloud.microsoft is 54 hosts: every licensed user loads it whether or
        not Copilot is provisioned."""
        assert tt.classify_ai("m365.cloud.microsoft") is None


class TestSecurityToolsCarryTheClass:
    """The class is the part an analyst reads: it says what KIND of control the host
    talks to without needing to know the vendor. Measured in-scope on dt=2026-08-01:
    MDM 859 hosts, Vault 179, MFA 175, ZTNA 79, EDR 55."""

    def test_the_column_is_present(self):
        assert "security_tools" in ec.build_entity_context_sql(
            DB, DATE, _profiling_catalog())

    @pytest.mark.parametrize("cls", ["EDR", "MDM", "ZTNA", "MFA", "Vault",
                                     "Mesh VPN", "AV", "DLP", "SIEM", "VulnScan",
                                     "RMM", "Pentest", "ThreatIntel"])
    def test_every_class_in_the_spec_is_emitted(self, cls):
        sec = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sec")
        assert f"'{cls}:" in sec, f"{cls} is not labelled in the shipped SQL"

    def test_every_declared_class_actually_has_a_product(self):
        """A class in the closed set with no product is a column value nobody's
        dashboard will ever render."""
        used = {k for _, k, _ in tt.SECURITY_TOOLS}
        assert used == tt.SECURITY_CLASSES, (
            f"declared-but-unused: {tt.SECURITY_CLASSES - used}")

    @pytest.mark.parametrize("host,cls,product", [
        # Telemetry domains, not marketing sites -- see below.
        ("ts01-b.cloudsink.net", "edr", "CrowdStrike Falcon"),
        ("dv-us-prod.sentinelone.net", "edr", "SentinelOne"),
        ("conferdeploy.net", "edr", "Carbon Black"),
        ("cloud-ios-asn.amp.cisco.com", "edr", "Cisco Secure Endpoint"),
        ("ch-bh.traps.paloaltonetworks.com", "edr", "Cortex XDR"),
        ("feeds.elastic.co", "edr", "Elastic Agent"),
        ("cp.wd.microsoft.com", "edr", "Microsoft Defender for Endpoint"),
        ("agents.manage.microsoft.com", "mdm", "Microsoft Intune"),
        ("bhnoc.jamfcloud.com", "mdm", "Jamf"),
        ("web-api.kandji.io", "mdm", "Kandji"),
        ("events.goskope.com", "ztna", "Netskope"),
        ("zscloud.net", "ztna", "Zscaler"),
        ("zdxcloud.net", "ztna", "Zscaler"),
        ("tenant.sso.duosecurity.com", "mfa", "Duo"),
        ("my.1password.com", "vault", "1Password"),
        # Classes the old 11-product list had no entry for at all.
        ("derp3f.tailscale.com", "mesh_vpn", "Tailscale"),
        ("notifications.bitwarden.com", "vault", "Bitwarden"),
        ("pollserver.lastpass.com", "vault", "LastPass"),
        ("sadownload.mcafee.com", "av", "McAfee"),
        ("sensor.cloud.tenable.com", "vuln_scanner", "Tenable / Nessus"),
        ("http-intake.logs.us5.datadoghq.com", "siem_agent", "Datadog Agent"),
        ("console.us.code42.com", "dlp", "Code42 Incydr"),
        ("telemetry.portswigger.net", "pentest", "Burp Suite"),
        ("osquery.vanta.com", "compliance", "Vanta"),
        ("download.wireguard.com", "vpn", "WireGuard"),
    ])
    def test_the_vendor_is_classified(self, host, cls, product):
        got = tt.classify_security(host)
        assert got is not None, f"{host} matched nothing"
        assert got == (product, cls), f"{host} -> {got}, expected ({product}, {cls})"

    def test_the_value_is_class_colon_product(self):
        """The spec's format is `EDR:CrowdStrike | MDM:Intune`. A bare vendor name
        makes the reader look up what kind of tool it is."""
        sec = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sec")
        assert "'EDR:CrowdStrike Falcon'" in sec
        assert "'MDM:Microsoft Intune'" in sec

    def test_every_emitted_label_carries_a_known_class_prefix(self):
        prefixes = {tt._sec_display(k) for k in tt.SECURITY_CLASSES}
        for label, _ in tt.security_label_rules():
            head = label.split(":", 1)[0]
            assert head in prefixes, f"{label} has an unknown class prefix"

    def test_the_list_is_pipe_delimited_and_capped(self):
        sec = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "sec")
        assert "' | '" in sec
        assert f"SLICE(ARRAY_AGG(label ORDER BY rank), 1, {ec._TOP_N})" in sec

    def test_controls_outrank_the_hosts_own_tooling_in_the_slice(self):
        """A host matching more products than {_TOP_N} loses the tail. An analyst
        asking "who manages this box" needs the EDR and the MDM to survive; a Burp
        Suite install is interesting but is not a control."""
        order = [l for l, _ in tt.security_label_rules()]
        first_edr = next(i for i, l in enumerate(order) if l.startswith("EDR:"))
        first_mdm = next(i for i, l in enumerate(order) if l.startswith("MDM:"))
        first_pentest = next(i for i, l in enumerate(order) if l.startswith("Pentest:"))
        first_ti = next(i for i, l in enumerate(order) if l.startswith("ThreatIntel:"))
        assert first_edr < first_mdm < first_pentest
        assert first_ti < first_pentest

    def test_carbonblacks_sensor_domain_is_included(self):
        """conferdeploy.net is the only Carbon Black shape actually present (6 hosts);
        matching only the branded domains would ship a dead label."""
        assert tt.classify_security("conferdeploy.net")[0] == "Carbon Black"

    def test_marketing_sites_are_not_read_as_installed_agents(self):
        """THE BLACK HAT PROBLEM: thousands of people BROWSE vendor websites here.
        www.crowdstrike.com proves nothing about the host; cloudsink.net proves the
        Falcon sensor is running."""
        assert tt.classify_security("www.crowdstrike.com") is None
        assert tt.classify_security("ts01-b.cloudsink.net")[0] == "CrowdStrike Falcon"

    def test_generic_windows_telemetry_is_not_defender(self):
        """events.data.microsoft.com is 678 hosts of ordinary Windows telemetry and
        smartscreen ships in every Edge install. Folding them in would triple the
        Defender count with garbage."""
        for host in ("events.data.microsoft.com", "settings-win.data.microsoft.com",
                     "smartscreen.microsoft.com"):
            assert tt.classify_security(host) is None, host

    def test_datadog_rum_is_excluded_but_the_agent_intake_is_not(self):
        """browser-intake-*.datadoghq.com is a JavaScript beacon fired by a WEBSITE the
        host visited -- it says nothing about the host. Getting this wrong would have
        added ~120 phantom hosts."""
        assert tt.classify_security("browser-intake-datadoghq.com") is None
        assert tt.classify_security("js-cdn.dynatrace.com") is None
        assert tt.classify_security(
            "http-intake.logs.us5.datadoghq.com")[0] == "Datadog Agent"

    def test_the_shows_own_recursive_dns_is_not_an_umbrella_fleet(self):
        """doh.opendns.com is 635 hosts -- the show's own resolver, not an installed
        agent. Including it would make 646 hosts look like Umbrella customers."""
        assert tt.classify_security("doh.opendns.com") is None
        assert tt.classify_security("disthost.umbrella.com")[0] == "Cisco Secure Access"


class TestSniColumnsDoNotFanOut:
    """ssl is ~7M rows/day and a host can hit hundreds of these SNIs. Invariant 1."""

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_each_cte_collapses_to_one_row_per_host(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "GROUP BY ip" in body
        assert " JOIN " not in body, f"{alias} joins raw rows"

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_each_cte_pins_the_partition(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert f"dt = '{DATE}'" in body, f"{alias} scans every partition"

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_each_cte_filters_the_empty_marker(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "'(empty)'" in body

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_the_case_only_runs_on_prefiltered_rows(self, alias):
        """The WHERE that repeats the match predicate is NOT redundant with the CASE:
        it prunes ~99% of rows before a 200-arm CASE is evaluated over them. Losing it
        turns a cheap scan into a slow one across two of the largest tables."""
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "GROUP BY ip, fqdn" in body, (
            "rows must collapse per (ip, fqdn) before the CASE, not after")
        assert re.search(r"\)\s*WHERE \(\(", body), "the pre-CASE filter is gone"


class TestToolingColumnsMatchDnsAndSni:
    """The user's architectural point: a product is identified by FQDN, and the FQDN is
    visible in TLS SNI *and* in the DNS query name. Measured in-scope on dt=2026-08-01:
    SNI reaches 571 hosts, DNS 492, and the union 587 -- DNS finds 16 hosts SNI cannot,
    because a resolve that never completes a captured TLS handshake leaves no
    server_name behind. `ip` is only the join key; nothing here identifies a host by
    its address."""

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_both_sources_are_read(self, alias):
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert f"{DB}.ssl" in body, "SNI is the primary source"
        assert f"{DB}.dns" in body, "DNS is the additive tail"
        assert "UNION ALL" in body

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_the_sources_are_unioned_not_joined(self, alias):
        """A join would multiply SSL handshakes by DNS queries per host."""
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert " JOIN " not in body

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_the_dns_name_is_stripped_of_its_trailing_dot(self, alias):
        """Zeek writes the queried name verbatim, so 'claude.ai.' is common. A needle
        has no trailing dot, so without RTRIM every fully-qualified query silently
        fails to match."""
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "RTRIM(LOWER(query), '.')" in body

    @pytest.mark.parametrize("alias", ["ai", "sec"])
    def test_mdns_and_reverse_lookups_are_pruned_from_the_dns_source(self, alias):
        """.local and .arpa can never match a public registrable domain, so they are
        pruned at the source rather than rejected one row at a time by the CASE."""
        body = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), alias)
        assert "NOT LIKE '%.local%'" in body
        assert "NOT LIKE '%.arpa%'" in body

    @pytest.mark.parametrize("alias,col", [("ai", "ai_tools"),
                                           ("sec", "security_tools")])
    def test_dns_absent_still_populates_from_sni_alone(self, alias, col):
        """A catalog without `dns` must degrade to the SNI-only behaviour, not drop the
        column and not build a CTAS that references a missing table."""
        cat = _profiling_catalog()
        del cat["dns"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"{DB}.dns" not in sql
        assert col in sql
        body = _cte(sql, alias)
        assert f"{DB}.ssl" in body
        assert "UNION ALL" not in body, "no second source to union"


class TestObservedHostnamesFallsBack:
    """Round 2's core bug: observed_hostnames read known_names ALONE, so it came back
    empty for hosts that plainly have a name. Measured on the spec's cited host
    10.220.198.27: known_names 0 rows, but dhcp.host_name = 'iPhone' (36 rows) and
    2,506 mDNS .local rows. Verified against live data after the fix, that host now
    reads 'iPhone,phy9v452cw,wn29j0603l'."""

    def test_dhcp_host_name_is_a_source(self):
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert f"{DB}.dhcp" in kn
        assert "assigned_addr ip" in kn, "dhcp must be keyed by the leased address"

    def test_mdns_instance_names_are_a_source(self):
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert f"{DB}.dns" in kn
        assert "local" in kn

    def test_a_bare_service_type_contributes_no_hostname(self):
        """'_companion-link._tcp.local' is a browse query on 1,903 in-scope IPs and is
        not a hostname. The same structural rule owner_name uses excludes it."""
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert "[^_.][^.]*" in kn, "bare service types would become hostnames"
        assert "NOT LIKE '%._sub.%'" in kn

    def test_known_names_still_leads_when_present(self):
        """A self-reported hostname is the most direct claim, so it must survive the
        SLICE cap even on a host with dozens of mDNS instances."""
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert "1 rank, hostname" in kn
        assert "ORDER BY rank, n DESC" in kn

    def test_the_sources_are_unioned_not_joined(self):
        """A join would multiply dhcp leases by mDNS records and drop hosts in only
        one source. dhcp alone reaches hosts known_names never saw."""
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert "UNION ALL" in kn
        assert " JOIN " not in kn

    def test_it_survives_losing_known_names(self):
        cat = _profiling_catalog()
        del cat["known_names"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        kn = _cte(sql, "kn")
        assert f"{DB}.known_names" not in sql
        assert f"{DB}.dhcp" in kn, "the fallback must still populate the column"

    def test_the_list_is_capped(self):
        kn = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kn")
        assert f", 1, {ec._TOP_N})" in kn


class TestAnnouncedDomainsIncludesServiceTypes:
    """announced_domains read known_domains ALONE and was empty for the same reason.
    The mDNS SERVICE TYPES a host browses are the fallback: '_rdlink' and
    '_companion-link' say "this host speaks Apple Continuity", which is exactly the
    device-linking signal the column is for. Measured in-scope on dt=2026-08-01:
    _companion-link 826 hosts, _rdlink 662, _googlecast 608, _airplay 366."""

    def test_mdns_is_a_source(self):
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert f"{DB}.dns" in kdom
        assert "local" in kdom

    def test_a_bare_service_type_IS_a_valid_value_here(self):
        """The rule that is the OPPOSITE of owner_name's, and the one thing easiest to
        get wrong. For owner_name a bare '_airplay._tcp.local' names NOBODY and is
        refused structurally. Here it is the value itself -- it says the host speaks
        AirPlay. So this CTE must NOT carry the instance-name requirement."""
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert "[^_.][^.]*" not in kdom, (
            "the instance-name rule leaked in from owner_name and would drop every "
            "bare service type, which is the whole signal"
        )
        assert "(_[a-z0-9-]+)" in kdom, "the service type is not being extracted"

    def test_subtype_registrations_are_still_excluded(self):
        """'._sub.' records are subtype registrations that name nothing: 38,023 of the
        in-scope .local rows."""
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert "NOT LIKE '%._sub.%'" in kdom

    def test_the_dns_sd_meta_query_is_excluded(self):
        """'_services._dns-sd._udp.local' is the DNS-SD meta-query -- "list every
        service type on this link". EVERY mDNS speaker emits it, so the service-type
        regex pulls a bogus '_dns-sd' out of it that would rank at or near the top on
        nearly every host and push the real _companion-link/_rdlink pairing signal out
        of the TOP_N slice. It names no service the host actually speaks."""
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert "_dns-sd" in kdom, "the meta-query is not filtered at all"
        assert "NOT REGEXP_LIKE" in kdom

    @pytest.mark.parametrize("query,expected", [
        # The meta-query must yield nothing...
        ("_services._dns-sd._udp.local", None),
        ("_services._dns-sd._udp.local.", None),
        # ...while every real pairing signal survives.
        ("_companion-link._tcp.local", "_companion-link"),
        ("f4a45c5b-1234._companion-link._tcp.local.", "_companion-link"),
        ("_rdlink._tcp.local", "_rdlink"),
        ("_airplay._tcp.local", "_airplay"),
        ("_googlecast._tcp.local", "_googlecast"),
        ("_sleep-proxy._udp.local", "_sleep-proxy"),
    ])
    def test_the_extraction_keeps_pairing_signals_and_drops_the_meta_query(
            self, query, expected):
        """Reimplements the shipped filter+regex in Python. The SQL is asserted to
        carry the same two clauses by the test above; this pins the SEMANTICS, which a
        substring assertion on generated SQL cannot."""
        excluded = re.search(r"_dns-sd\._(?:tcp|udp)\.local\.?$", query.lower())
        m = re.search(r"(_[a-z0-9-]+)\._(?:tcp|udp)\.local\.?$", query.lower())
        got = None if excluded else (m.group(1) if m else None)
        assert got == expected

    def test_known_domains_still_leads_when_present(self):
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert "1 rank, domain" in kdom
        assert "ORDER BY rank, n DESC" in kdom

    def test_the_sources_are_unioned_not_joined(self):
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert "UNION ALL" in kdom
        assert " JOIN " not in kdom

    def test_it_survives_losing_known_domains(self):
        cat = _profiling_catalog()
        del cat["known_domains"]
        sql = ec.build_entity_context_sql(DB, DATE, cat)
        assert f"{DB}.known_domains" not in sql
        assert f"{DB}.dns" in _cte(sql, "kdom")

    def test_the_list_is_capped(self):
        kdom = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "kdom")
        assert f", 1, {ec._TOP_N})" in kdom


class TestOwnerNameIsUnchangedByTheFallbacks:
    """Round 2 added a MORE PERMISSIVE mDNS read for announced_domains, one CTE away
    from owner_name's deliberately strict one. Loosening owner_name's rules is the
    regression that would put a staffer's name on up to 60 strangers, so these gates
    assert the two rules did not bleed together."""

    def test_a_bare_service_type_still_yields_no_owner_name(self):
        """The exact case announced_domains now ACCEPTS and owner_name must still
        REFUSE. Same raw record, opposite verdicts, on purpose."""
        for q in ("_companion-link._tcp.local", "_rdlink._tcp.local",
                  "_airplay._tcp.local", "_googlecast._tcp.local"):
            assert not _is_instance_named(q), q
            assert _owner_emitted(q.split(".")[0], 1, query=q) is None, q

    def test_the_rarity_ceiling_is_untouched(self):
        assert ec._OWNER_MAX_IPS == 10
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert f"r.nip <= {ec._OWNER_MAX_IPS}" in own
        assert f"rs.snip <= {ec._OWNER_MAX_IPS}" in own

    def test_the_instance_name_requirement_is_untouched(self):
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "[^_.][^.]*" in own
        assert "NOT LIKE '%._sub.%'" in own

    def test_owner_name_reads_no_new_source(self):
        """dhcp is still corroboration ONLY. Promoting it to a naming source would
        emit an owner for every DHCP hostname, ungated."""
        own = _cte(ec.build_entity_context_sql(DB, DATE, _profiling_catalog()), "own")
        assert "'mdns' src" in own and "'known_names' src" in own
        assert "'dhcp' src" not in own

    def test_the_stopword_list_is_untouched(self):
        for w in ("conference", "apple tv", "chromecast", "printer", "guest"):
            assert w in ec._OWNER_STOPWORDS, w
