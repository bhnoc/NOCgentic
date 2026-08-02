"""Gates for device_links (lambda/device_links.py).

`entity_context` answers "what IS this host". This answers "what ELSE does this
person have" — the phone next to the laptop, the same laptop after it moved
networks and randomized its MAC, the Chromecast two hosts share.

Two properties matter more than anything else here, and both are the kind that
produce confident nonsense rather than an error when they break:

1. POPULARITY GATING. `ecdf4f49dd59effc439639da29186671` is on 1,401 IPs — it is
   Chrome. Ungated, the marquee feature emits a 1,401-way "same person" cluster.
   Same for the bare `_companion-link._tcp.local` browse query on 1,903 IPs.
2. NO FAN-OUT. One row per (ip, dt). Every source must reduce to DISTINCT
   (ip, key) before the self-join, or a 6.98M-row ssl self-join runs hourly.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "lambda"))

import device_links as dl  # noqa: E402

DB = "testdb"
DATE = "2026-08-01"

# The verified live shape of every table this reads. `software`-style surprises are
# why the gates below are column-level: ssl carries ja3 today, but a catalog that
# predates it must skip the method rather than emit SQL that fails.
_CATALOG = {
    "ssl": {"id_orig_h", "ja3", "ja3s", "server_name", "dt"},
    "ssh": {"id_orig_h", "hassh", "hasshserver", "dt"},
    "rdp": {"id_orig_h", "rdfp_hash", "dt"},
    "vpn": {"id_orig_h", "ja3", "ja3s", "dt"},
    "dns": {"id_orig_h", "query", "dt"},
    "known_users": {"host_ip", "user_", "protocol", "dt"},
    "known_devices": {"host_ip", "mac", "vendor_mac", "dt"},
    "dhcp": {"mac", "assigned_addr", "host_name", "client_fqdn", "dt"},
}

# The columns PostCog reads. Named per the spec's device_links table.
_COLUMNS = ("ip", "mac", "dt", "owner_cluster_id", "linked_ips", "linked_macs",
            "link_methods", "link_evidence", "confidence")


def _catalog(**extra):
    cat = {k: set(v) for k, v in _CATALOG.items()}
    for name, cols in extra.items():
        if cols is None:
            cat.pop(name, None)
        else:
            cat[name] = cols
    return cat


def _cte(sql, alias):
    """The text of one CTE, so a gate can assert about that source alone."""
    needle = f"\n{alias} AS ("
    start = sql.index(needle) if needle in sql else sql.index(f"WITH {alias} AS (")
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


def _edge_block(sql, method_literal):
    """One UNION ALL arm of `pairs`, identified by the method it emits."""
    pairs = _cte(sql, "pairs")
    arms = pairs.split("UNION ALL")
    hits = [a for a in arms if method_literal in a]
    assert hits, f"no edge block emits {method_literal}"
    return hits


class TestStockBrowserJa3IsExcluded:
    """`ecdf4f49dd59effc439639da29186671` is on 1,401 IPs. It is Chrome, not a
    person. 175 fingerprints live on 50+ IPs and cover 42,305 ip-slots; if any of
    them reaches the self-join, every Chrome user links to every other Chrome user
    and the whole feature is discredited in front of an analyst."""

    def test_no_band_reaches_the_stock_browser_range(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert dl._FP_MAX_IPS < 1401, "the 1,401-IP Chrome fingerprint would link"
        # Every popularity gate must name a finite ceiling.
        assert "BETWEEN" in sql
        assert "COUNT(DISTINCT ip)" in sql

    def test_every_fingerprint_ceiling_stays_inside_the_gold_band(self):
        """Measured on live data: admitting the 11-50 band dragged the average
        cluster to 9.7 members and pinned 2,340 of 3,274 rows at the truncation
        ceiling, on evidence like "common ja3 (32 IPs share cc2f46d8)" -- a niche
        browser build. No arm may reach past the verified 2-10 band."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        ceilings = [int(m) for m in re.findall(r"BETWEEN \d+ AND (\d+)", sql)]
        assert ceilings, "no popularity gate found at all"
        assert max(ceilings) <= dl._MAX_LINKS, (
            f"a gate admits up to {max(ceilings)} IPs per value; the ja3 gold band "
            f"ends at {dl._FP_MAX_IPS}"
        )

    def test_the_gate_is_applied_before_the_self_join(self):
        """Gating after the join is both wrong and ruinous: the 1,401-IP fingerprint
        would produce ~1.96M pair rows before anything filtered it."""
        for arm in _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                               "'same_ja3'"):
            gate = arm.index("HAVING COUNT(DISTINCT ip) BETWEEN")
            join = arm.index("JOIN ja3 b ON")
            assert gate < join, "popularity is filtered after the self-join"

    def test_ceiling_is_a_tunable_constant(self):
        """The right ceiling is a property of the show's device mix, so it has to be
        adjustable without editing SQL string literals."""
        assert dl._FP_MAX_IPS == 10
        assert dl._FP_MIN_IPS == 2


class TestJa3GoldBand:
    """2-10 IPs: 12,683 fingerprints, 29,317 ip-slots. This is the band where a
    match actually means one device, and it is the highest-leverage signal in the
    table because a ja3 survives the MAC randomization that defeats same_mac."""

    def test_the_gold_band_is_the_high_confidence_band(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        gold = [a for a in _edge_block(sql, "'same_ja3'")
                if f"BETWEEN {dl._FP_MIN_IPS} AND {dl._FP_MAX_IPS}" in a]
        assert gold, "the 2-10 band is not queried"
        assert "'high'" in gold[0]

    def test_a_fingerprint_on_one_ip_cannot_link(self):
        """2.6M fingerprints are on exactly 1 IP. A floor of 1 would join each of
        them to itself-minus-nothing and waste the whole scan."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "BETWEEN 1 AND" not in sql

    def test_the_11_to_50_band_is_not_queried_at_all(self):
        """It was, at 'low', and measurement killed it: 2,340 of 3,274 rows hit the
        truncation ceiling and sampled evidence read "common ja3 (32 IPs share
        cc2f46d8)", which is a browser build rather than a device. Down-weighting was
        not enough because the edges still enlarged the cluster."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert f"BETWEEN {dl._FP_MAX_IPS + 1} AND" not in sql, (
            "the weak fingerprint band is back"
        )
        assert not hasattr(dl, "_FP_WEAK_MAX_IPS"), (
            "the weak-band ceiling is defined again; it should stay deleted"
        )


class TestMdnsParsing:
    """The single most dangerous parsing job in this file. `dns.query` for `.local`
    is either a bare service type (a browse query every Apple device on the network
    emits) or an instance-named record (the actual link). Confusing them links
    1,903 strangers and calls it a personal device pairing."""

    def test_bare_browse_query_cannot_link(self):
        """`_companion-link._tcp.local` is on 1,903 IPs and `_googlecast._tcp.local`
        on 1,418. Both are generic browse queries, so an instance-name prefix is
        mandatory -- a record with nothing before the service type is discarded."""
        comp = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "mdns_comp")
        assert "SUBSTR(fp, 1, 1) <> '_'" in comp, "a bare service type would pass"
        assert "fp <> ''" in comp, "an empty instance name would pass"

    def test_subtype_records_do_not_link(self):
        """`_cc32e753._sub._googlecast._tcp.local` is on 106 IPs. It has a label
        before the service type, so it passes the prefix test, but it is a SUBTYPE
        browse rather than an instance -- 106 unrelated hosts in one cluster."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for alias in ("mdns_comp", "mdns_cast"):
            assert "NOT LIKE '%._sub.%'" in _cte(sql, alias), f"{alias} accepts subtypes"

    def test_a_named_instance_does_link(self):
        """`karan's macbook pro._companion-link._tcp.local` on 2 IPs is a phone and
        its laptop. This is the demo, so the extraction must actually happen."""
        comp = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "mdns_comp")
        assert "STRPOS(q, '._companion-link._tcp.local')" in comp
        assert "SUBSTR(q, 1, STRPOS(" in comp, "the instance label is not extracted"
        assert "'mdns_companion'" in dl.build_device_links_sql(DB, DATE, _catalog())

    def test_named_instances_still_have_an_ip_ceiling(self):
        """`nemus's macbook pro._companion-link._tcp.local` is on 69 IPs: a session
        room AirPlay target, not 69 people's phones. A prefix alone is not enough."""
        assert dl._MDNS_MAX_IPS < 69
        arms = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                           "'mdns_companion'")
        assert f"BETWEEN {dl._FP_MIN_IPS} AND {dl._MDNS_MAX_IPS}" in arms[0]

    def test_parsing_does_not_assume_ascii(self):
        """Instance names carry U+2019 apostrophes ("karan's"). A character-class
        regex over [a-z0-9-] would silently truncate them into different keys, so
        two records for one device would stop matching."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for alias in ("mdns_comp", "mdns_cast"):
            body = _cte(sql, alias)
            assert "REGEXP" not in body.upper(), "regex parsing risks unicode names"
            assert "a-z" not in body, "a character class would mangle apostrophes"

    def test_the_dns_scan_is_narrowed_in_the_database(self):
        """`.local` alone is 7.6M rows/day. The service-type predicate has to run in
        the scan, not after it."""
        comp = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "mdns_comp")
        assert "query LIKE '%.local%'" in comp
        assert "_companion-link._tcp.local%'" in comp

    def test_cast_and_companion_are_separate_methods(self):
        """Two hosts resolving one Chromecast are in the same ROOM; two hosts
        sharing a companion-link instance are the same PERSON. Collapsing them
        would overstate the weaker claim."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "'shared_cast'" in sql
        assert "'mdns_companion'" in sql
        assert dl._CAST_SERVICES != dl._COMPANION_SERVICES


class TestNoFanOut:
    """One row per (ip, dt) is the table's contract. `ssl` is 6.98M rows/day and a
    self-join of it is the most expensive thing in this codebase; this runs hourly."""

    def test_every_source_reduces_to_distinct_ip_key_pairs_first(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for alias in ("ja3", "hassh", "rdfp", "vja3", "kd_mac", "dh_mac", "acct",
                      "mdns_comp", "mdns_cast"):
            assert "SELECT DISTINCT" in _cte(sql, alias), f"{alias} joins raw rows"

    def test_the_ssl_self_join_reads_the_reduced_cte_not_the_table(self):
        """Joining {db}.ssl to itself is 6.98M x 6.98M. Joining the distinct-pairs
        CTE is 29,317 rows against 29,317."""
        for arm in _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                               "'same_ja3'"):
            assert f"{DB}.ssl" not in arm, "the self-join hits the raw table"
            assert "JOIN ja3 b" in arm

    def test_methods_are_unioned_not_joined(self):
        """A join would multiply an IP's rows by the number of methods that fired,
        and would drop any IP a given method never saw."""
        pairs = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "pairs")
        assert "UNION ALL" in pairs

    def test_the_final_select_aggregates_to_one_row_per_ip(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        clusters = _cte(sql, "clusters")
        assert "GROUP BY e.ip" in clusters
        # Nothing may re-expand the cluster after that grouping.
        tail = sql[sql.index("FROM clusters c"):]
        assert "UNNEST" not in tail, "UNNEST after grouping puts an IP on many rows"
        assert "CROSS JOIN" not in tail

    def test_peer_mac_lookup_cannot_multiply_edges(self):
        """known_devices has multiple rows per host, so joining it raw onto the edge
        list would duplicate every edge per MAC observation."""
        macs = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "macs")
        assert "GROUP BY host_ip" in macs
        assert "ARBITRARY(" in macs

    def test_evidence_and_link_lists_are_bounded(self):
        """An IP in a 12-way cluster must not produce a cell nobody will read."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert sql.count("SLICE(") >= 3

    def test_partition_is_pinned_on_every_source(self):
        """Unpinned, each source scans every day in the catalog, every hour."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for alias in ("ja3", "hassh", "mdns_comp", "mdns_cast", "kd_mac", "acct"):
            assert f"dt = '{DATE}'" in _cte(sql, alias), f"{alias} scans all partitions"


class TestLinkMethods:
    """All five methods from the spec, each independently gated."""

    @pytest.mark.parametrize("method", ["same_mac", "same_ja3", "same_hassh",
                                        "mdns_companion", "shared_cast",
                                        "shared_account"])
    def test_method_is_implemented(self, method):
        assert f"'{method}'" in dl.build_device_links_sql(DB, DATE, _catalog())

    def test_hassh_is_present_but_does_not_dominate(self):
        """Only 21 distinct hassh across 108 IPs. Worth wiring up, but it cannot be
        the reason the table exists -- if it were the only method the table would
        cover 0.6% of hosts and read as broken."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "'same_hassh'" in sql
        assert sql.count("UNION ALL") >= 5, "hassh is carrying the whole table"

    def test_shared_account_is_corroboration_not_proof(self):
        """94 rows / 22 IPs, and an account can genuinely be shared between people,
        so it may not claim the same certainty as a device fingerprint."""
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'shared_account'")[0]
        assert "'medium'" in arm
        assert "'high'" not in arm

    def test_accounts_have_their_own_popularity_ceiling(self):
        """A username on many IPs is a service login, not one person roaming."""
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'shared_account'")[0]
        assert f"AND {dl._ACCOUNT_MAX_IPS}" in arm

    def test_mac_linking_ignores_case(self):
        """known_devices and dhcp do not agree on MAC casing, so an unnormalized
        join would miss the very links same_mac exists to find."""
        for alias in ("kd_mac", "dh_mac"):
            assert "LOWER(mac)" in _cte(dl.build_device_links_sql(DB, DATE, _catalog()), alias)


class TestConfidence:
    """Per the spec: same_mac or mdns_companion -> high; rare ja3 -> high;
    shared_cast -> medium-high; shared_account alone -> medium."""

    def test_weakest_edge_sets_the_cluster_confidence(self):
        """A cluster is ONE claim -- "these are one owner's devices" -- so it is only
        as good as its flimsiest member. Taking the max let a single solid mDNS edge
        stamp 'high' on a cluster whose other members joined on weak evidence, which
        is the worst way to be wrong: the analyst reads confident and acts."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        conf = sql[sql.index("CASE WHEN CONTAINS(c.strengths"):]
        assert conf.index("'low'") < conf.index("'medium'") < conf.index("'high'"), (
            "confidence is resolving strongest-wins again"
        )

    def test_shared_cast_is_medium_high(self):
        """Two hosts sharing a Chromecast are in one room, which is a weaker claim
        than being one device -- but stronger than a shared account."""
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'shared_cast'")[0]
        assert "'medium-high'" in arm

    def test_mdns_companion_is_high(self):
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'mdns_companion'")[0]
        assert "'high'" in arm

    def test_every_bucket_is_reachable(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for bucket in ("'high'", "'medium-high'", "'medium'", "'low'"):
            assert bucket in sql


class TestOwnerClusterId:
    """The id is shared by all of one owner's devices and rebuilt hourly. A random
    UUID would churn every row of the table every hour, so anything holding a
    reference -- a PostCog card, an analyst's notes -- would break each rebuild."""

    def test_id_is_a_hash_not_a_uuid(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "MD5(" in sql
        assert "UUID()" not in sql.upper().replace("OWNER_CLUSTER_ID", "")
        assert "RANDOM" not in sql.upper()

    def test_id_is_deterministic_across_two_builds(self):
        """The literal guarantee: same catalog, same day, byte-identical SQL, so the
        same cluster hashes to the same id on every hourly rebuild."""
        first = dl.build_device_links_sql(DB, DATE, _catalog())
        second = dl.build_device_links_sql(DB, DATE, _catalog())
        assert first == second

    def test_id_is_hashed_from_a_canonical_label_not_per_ip_neighbours(self):
        """The id must be the SAME for every device of one owner. If A links B by ja3
        and A links C by MAC, hashing each IP's own neighbour list gives A, B and C
        three different ids for one owner, and the id stops identifying anything."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "MD5(TO_UTF8(LEAST(cn.label, c.ip)))" in sql
        assert "MD5(TO_UTF8(ARRAY_JOIN" not in sql, "hashing per-IP neighbourhoods"

    def test_the_label_is_propagated_across_neighbours(self):
        """A single MIN over direct neighbours is not enough: B and C only agree once
        each has taken the minimum label of everything it can reach."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        labels = _cte(sql, "labels")
        canon = _cte(sql, "canon")
        assert "LEAST(MIN(other_ip), ip)" in labels
        assert "JOIN labels l ON l.ip = s.other_ip" in canon

    def test_edges_are_symmetric_before_clustering(self):
        """The popularity ceiling is evaluated per key, so a key at the boundary can
        survive in one direction only -- leaving A listing B while B ignores A."""
        sym = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "sym")
        assert "SELECT other_ip ip, ip other_ip" in sym
        assert "UNION\n" in sym, "UNION ALL would double every already-symmetric edge"


class TestPartialCatalog:
    def test_returns_none_on_an_empty_catalog(self):
        """A partial catalog must SKIP this step. Writing a table of nulls looks
        like "this person has no other devices", which is a wrong answer, not a
        missing one."""
        assert dl.build_device_links_sql(DB, DATE, {}) is None

    def test_returns_none_when_no_method_can_be_satisfied(self):
        """conn alone joins nothing here: there is no shared key in it."""
        assert dl.build_device_links_sql(DB, DATE, {"conn": {"id_orig_h", "dt"}}) is None

    def test_ja3_alone_is_enough_to_build(self):
        """Sequenced by value: fingerprint linking ships before mDNS, so the table
        has to be useful with ssl as its only source."""
        sql = dl.build_device_links_sql(DB, DATE, {"ssl": {"id_orig_h", "ja3", "dt"}})
        assert sql is not None
        assert "'same_ja3'" in sql

    @pytest.mark.parametrize("table,method", [
        ("ssl", "'same_ja3'"),
        ("ssh", "'same_hassh'"),
        ("dns", "'mdns_companion'"),
        ("known_users", "'shared_account'"),
    ])
    def test_a_missing_table_drops_only_its_own_method(self, table, method):
        cat = _catalog(**{table: None})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert sql is not None
        assert f"{DB}.{table}" not in sql
        assert method not in sql

    def test_every_output_column_survives_a_minimal_catalog(self):
        """PostCog is presence-gated on the column. A vanished column breaks it
        where an empty one just reads as "nothing linked"."""
        sql = dl.build_device_links_sql(DB, DATE, {"ssl": {"id_orig_h", "ja3", "dt"}})
        for col in _COLUMNS:
            assert f" {col}" in sql, f"{col} vanished on a minimal catalog"

    def test_mac_columns_degrade_to_null_without_known_devices(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog(known_devices=None))
        assert "CAST(NULL AS VARCHAR) mac" in sql
        assert "CAST(NULL AS VARCHAR) linked_macs" in sql


class TestColumnLevelGating:
    """Table presence is not enough. An `ssl` that predates ja3 would build a CTAS
    that parses here and fails in Athena, and ONE failed statement loses the whole
    hourly rebuild for every table after it."""

    def test_ssl_without_ja3_is_not_read_for_fingerprints(self):
        cat = _catalog(ssl={"id_orig_h", "server_name", "dt"})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert "'same_ja3'" not in sql or f"{DB}.ssl" not in sql

    def test_ssh_without_hassh_is_not_read(self):
        cat = _catalog(ssh={"id_orig_h", "hasshserver", "dt"})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert f"{DB}.ssh" not in sql

    def test_dns_without_query_is_not_read(self):
        cat = _catalog(dns={"id_orig_h", "dt"})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert f"{DB}.dns" not in sql
        assert "'mdns_companion'" not in sql

    def test_known_devices_without_mac_is_not_read(self):
        cat = _catalog(known_devices={"host_ip", "vendor_mac", "dt"})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert f"{DB}.known_devices" not in sql

    def test_dhcp_without_assigned_addr_is_not_read(self):
        """dhcp keys links on assigned_addr, not on any id_orig_h. Without it there
        is no IP to attach the MAC to."""
        cat = _catalog(dhcp={"mac", "host_name", "dt"})
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert f"{DB}.dhcp" not in sql

    def test_opportunistic_sources_are_skipped_silently(self):
        """rdp and vpn are bonus fingerprints; their absence is the normal case and
        must not affect anything else."""
        cat = _catalog(rdp=None, vpn=None)
        sql = dl.build_device_links_sql(DB, DATE, cat)
        assert sql is not None
        assert "'same_ja3'" in sql, "ssl ja3 stopped working when rdp/vpn went away"


class TestEvidenceIsForHumans:
    """link_evidence is shown verbatim to an analyst; link_methods is the machine
    list. An analyst who cannot audit a link will not trust any of them."""

    def test_evidence_names_the_reason_not_just_the_key(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert "same laptop on another network" in sql
        assert "their other device" in sql
        assert "same room/home" in sql

    def test_ja3_evidence_quotes_how_many_ips_share_the_fingerprint(self):
        """The share is what tells an analyst whether the match is worth acting on:
        3 IPs is a device, 40 is a browser."""
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'same_ja3'")[0]
        assert "CAST(a.share AS VARCHAR)" in arm
        assert "IPs share" in arm

    def test_evidence_is_pipe_delimited(self):
        """PostCog splits on this, so the separator is a contract."""
        clusters = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "clusters")
        assert "' | '" in clusters

    def test_link_methods_is_a_machine_readable_comma_list(self):
        clusters = _cte(dl.build_device_links_sql(DB, DATE, _catalog()), "clusters")
        assert "ARRAY_JOIN(ARRAY_SORT(ARRAY_AGG(DISTINCT e.method)), ',')" in clusters

    def test_fingerprints_are_truncated_in_evidence(self):
        """A full 32-hex ja3 in prose is unreadable; 8 characters is enough for an
        analyst to pivot on manually."""
        arm = _edge_block(dl.build_device_links_sql(DB, DATE, _catalog()),
                          "'same_ja3'")[0]
        assert "SUBSTR(a.fp, 1, 8)" in arm


class TestDialect:
    """Athena/Presto. Reserved words take DOUBLE quotes in a SELECT; backticks are
    DDL-only and are a parse error in a query."""

    def test_ctes_are_declared_before_they_are_used(self):
        """Trino resolves CTEs in declaration order. `edges` reads `macs`, so
        declaring `macs` after it parses fine and then fails at runtime with
        "Table macs does not exist" -- losing the whole hourly rebuild."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert sql.index("\nmacs AS (") < sql.index("\nedges AS (")
        assert sql.index("\npairs AS (") < sql.index("\nsym AS (")
        assert sql.index("\nlabels AS (") < sql.index("\ncanon AS (")

    def test_no_backticks(self):
        assert "`" not in dl.build_device_links_sql(DB, DATE, _catalog())

    def test_where_does_not_reference_a_select_alias(self):
        """Trino cannot resolve a SELECT alias in the WHERE of the same query block.
        The mDNS service predicate lives beside `LOWER(query) q`, so using `q` there
        parses cleanly and then fails at runtime -- losing the whole hourly rebuild."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        for alias in ("mdns_comp", "mdns_cast"):
            body = _cte(sql, alias)
            where = body[body.index("WHERE dt ="):body.index("\n    )")]
            assert "q LIKE" not in where, "WHERE references the `q` SELECT alias"
            assert "LOWER(query) LIKE" in where

    def test_no_mysql_or_postgres_only_functions(self):
        sql = dl.build_device_links_sql(DB, DATE, _catalog()).upper()
        for fn in ("GROUP_CONCAT", "STRING_AGG", "LISTAGG"):
            assert fn not in sql, f"{fn} does not exist in Trino"


class TestDDL:
    def test_table_is_per_day(self):
        assert dl.table_name(DATE) == "device_links_2026_08_01"

    def test_ctas_targets_that_table(self):
        ddl = dl.build_ctas(DB, DATE, _catalog())
        assert ddl.startswith(f"CREATE TABLE {DB}.device_links_2026_08_01 AS")

    def test_ctas_omits_external_location(self):
        """The workgroup sets EnforceWorkGroupConfiguration and rejects a CTAS that
        names its own output path -- the statement fails outright."""
        assert "external_location" not in dl.build_ctas(DB, DATE, _catalog())

    def test_ctas_is_none_when_unsatisfiable(self):
        assert dl.build_ctas(DB, DATE, {}) is None

    def test_dt_is_the_partition_value_not_a_source_column(self):
        """Every source is already filtered to one dt, so carrying dt through a join
        would just be another chance for it to arrive NULL."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert f"'{DATE}' dt" in sql


class TestZeekEmptyMarker:
    """Zeek writes '(empty)' for a present-but-empty SET/VECTOR field, and the raw
    loader types every column as string, so it arrives as a VALUE rather than NULL.

    It is absent from every column this module reads today (0 rows on dt=2026-08-01
    for ssl.ja3, ssh.hassh, known_devices.mac, known_users.user_) but the loader
    does emit it -- 2,376 in-scope IPs carry it in ssl's client-cert columns, and
    entity_context had a real bug from exactly this. Filtered pre-emptively because
    the popularity ceiling CANNOT catch it: a shared "(empty)" fingerprint would sit
    inside the 2-10 IP gold band on a quiet day and link strangers as one owner.
    """

    def test_empty_marker_is_filtered(self):
        assert "(empty)" in dl._EMPTY, "Zeek's '(empty)' marker would be a link key"

    def test_all_three_absent_markers_are_filtered(self):
        for marker in ("''", "'-'", "'(empty)'"):
            assert marker in dl._EMPTY

    def test_every_fingerprint_source_applies_the_filter(self):
        """A source that skips it reintroduces the bug for its own column only,
        which is the hardest version to notice."""
        sql = dl.build_device_links_sql(DB, DATE, _catalog())
        assert sql.count("NOT IN ('', '-', '(empty)')") >= 4
