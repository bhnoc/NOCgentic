"""One row per IP per day: which OTHER IPs belong to the same owner, and why.

`entity_context` answers "what IS this host". This answers "what ELSE does this
person have" — their phone next to their laptop, the same laptop after it moved
from training-net to gen-wifi and randomized its MAC, the Chromecast two hosts
share.

Every method here is a self-join over a shared key, which is the most expensive
shape in this codebase: `ssl` is ~6.98M rows/day and `dns` `.local` alone is
~7.6M. So each source becomes a DISTINCT (ip, key) CTE FIRST and the self-join
runs against that. 29,317 ja3 ip-slots survive the linkability gate below, and
joining 29k against 29k is free. Joining 6.98M against 6.98M is not.

THE LINKABILITY GATE IS THE WHOLE DESIGN. Measured on dt=2026-08-01:

    ja3 on exactly 1 IP   2,600,635 fingerprints  -> cannot link, dropped
    ja3 on 2-10 IPs          12,683 (29,317 slots) -> the gold band, used
    ja3 on 11-50 IPs            288  (6,788 slots) -> weak, low confidence only
    ja3 on 50+ IPs              175 (42,305 slots) -> stock browsers, DROPPED

The top fingerprint `ecdf4f49dd59effc439639da29186671` is on 1,401 IPs. It is
Chrome. Without the ceiling every Chrome user "links" to every other Chrome user
and the marquee feature emits a 1,401-way cluster that means nothing.

The mDNS equivalent trap is instance naming. `dns.query` for `.local` is either
a BARE service type (a browse query, useless) or an INSTANCE-NAMED record (gold):

    _companion-link._tcp.local                      1,903 IPs  browse, useless
    _googlecast._tcp.local                          1,418 IPs  browse, useless
    _cc32e753._sub._googlecast._tcp.local             106 IPs  SUBTYPE, useless
    karan's macbook pro._companion-link._tcp.local      2 IPs  GOLD
    nemus's macbook pro._companion-link._tcp.local     69 IPs  conference AppleTV

So an mDNS link requires a label before the service type that does not itself
start with `_`, must reject `._sub.`, and still needs a per-instance IP ceiling —
a named instance on 69 IPs is a shared session-room device, not a personal
pairing. Instance names arrive lowercased and contain U+2019 apostrophes, so
nothing here may assume ASCII.
"""

from __future__ import annotations

# Fingerprint linkability band, in distinct IPs. The floor is 2 because a
# fingerprint on one IP links nothing. The ceiling is the load-bearing number: at
# 10 we keep 12,683 fingerprints / 29,317 ip-slots and exclude the 175
# stock-browser fingerprints that account for 42,305 slots. Tunable because the
# right ceiling is a property of the show's device mix, not of this code.
_FP_MIN_IPS = 2
_FP_MAX_IPS = 10

# The 11-50 band is DELIBERATELY NOT USED. Admitting it at 'low' was tried and
# measured on dt=2026-08-01: it dragged the average cluster to 9.7 members and
# pinned 2,340 of 3,274 rows at the _MAX_LINKS ceiling, i.e. most clusters were
# truncated rather than resolved. Sampled evidence read "common ja3 (32 IPs share
# cc2f46d8)" — a niche browser build, not a device. A link nobody can trust is
# worse than no link, so the band is dropped rather than down-weighted.

# Max IPs sharing one NAMED mDNS instance. A personal pairing is 2-4 hosts;
# `nemus's macbook pro._companion-link._tcp.local` is on 69 and is somebody's
# AirPlay target in a session room, not 69 people's phones.
_MDNS_MAX_IPS = 8

# Same idea for cast/speaker instances, looser because a household or booth
# legitimately shares one Chromecast across more devices than a phone pairs with.
_CAST_MAX_IPS = 12

# A MAC on more IPs than this is a NAT gateway or a re-used lab NIC, not one
# person's roaming device. Well outside anything a day of DHCP leases produces.
_MAC_MAX_IPS = 8

# `known_users` has 94 rows / 22 IPs, so accounts are corroboration only. An
# account on more IPs than this is a service login, not a person.
_ACCOUNT_MAX_IPS = 6

# Apple Continuity / AirPlay. A named instance here is a device announcing itself
# to its OWNER's other devices, which is exactly the link we want.
_COMPANION_SERVICES: tuple[str, ...] = ("_companion-link", "_airplay", "_raop")

# Shared media endpoints. A named instance is a speaker or TV, so two hosts
# resolving it are in the same room rather than being the same person — a weaker
# claim than a fingerprint match, hence medium-high.
_CAST_SERVICES: tuple[str, ...] = ("_googlecast", "_spotify-connect")

# How many linked IPs / evidence strings to carry. PostCog shows these verbatim;
# a 60-IP cell is not read, it is scrolled past.
_MAX_LINKS = 12

# Zeek writes '-' for an absent field and the raw loader types every column as
# string, so the empty marker has to be filtered as a value, not as NULL.
# '(empty)' is Zeek's marker for a present-but-empty SET/VECTOR field. It is absent
# from every column this module reads today (verified 0 rows on dt=2026-08-01 for
# ssl.ja3, ssh.hassh, known_devices.mac, known_users.user_), but it appears on 2,376
# in-scope IPs in ssl's client-cert columns, so the loader does emit it. Filtered
# pre-emptively: a fingerprint of "(empty)" would be a single shared key, and the
# popularity ceiling cannot save us because it would sit in the 2-10 band on a quiet
# day and link strangers as one owner's devices.
_EMPTY = "('', '-', '(empty)')"


def _present(col: str) -> str:
    return f"{col} IS NOT NULL AND {col} NOT IN {_EMPTY}"


def _fp_source(database: str, date_str: str, table: str, col: str,
               ip_col: str = "id_orig_h") -> str:
    """DISTINCT (ip, fp) for one fingerprint source, before any join.

    This is the cost control. Collapsing 6.98M ssl rows to distinct pairs is one
    aggregation; the self-join then runs against that small set.
    """
    return f"""  SELECT DISTINCT {ip_col} ip, {col} fp
  FROM {database}.{table}
  WHERE dt = '{date_str}' AND {ip_col} IS NOT NULL AND {_present(col)}"""


def _mdns_source(database: str, date_str: str, services: tuple[str, ...]) -> str:
    """DISTINCT (ip, fp, service) for NAMED mDNS instances only.

    STRPOS+SUBSTR rather than a regex: the instance label is simply everything
    before the service type, and these names carry U+2019 apostrophes that make a
    character-class regex a liability for no gain.
    """
    # LOWER(query), not the `q` alias: Trino does not resolve a SELECT alias in the
    # WHERE of the same query block, so the alias form fails at runtime having
    # parsed cleanly.
    svc_pred = " OR ".join(f"LOWER(query) LIKE '%{s}._tcp.local%'" for s in services)
    cut = "\n           ".join(
        f"WHEN STRPOS(q, '.{s}._tcp.local') > 1 "
        f"THEN SUBSTR(q, 1, STRPOS(q, '.{s}._tcp.local') - 1)"
        for s in services
    )
    label = "\n           ".join(
        f"WHEN q LIKE '%{s}._tcp.local%' THEN '{s}'" for s in services
    )
    # Three filters, each earning its place: `._sub.` is a subtype browse
    # (`_cc32e753._sub._googlecast._tcp.local`, 106 IPs) that would otherwise pass
    # the prefix test; a leading `_` means the "instance" is itself a service
    # label; and an empty cut is the bare browse query on 1,903 IPs.
    return f"""  SELECT DISTINCT ip, fp, service FROM (
    SELECT ip,
           CASE {cut}
           END fp,
           CASE {label}
           END service
    FROM (
      SELECT DISTINCT id_orig_h ip, LOWER(query) q
      FROM {database}.dns
      WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL AND {_present('query')}
        AND query LIKE '%.local%' AND ({svc_pred})
        AND query NOT LIKE '%._sub.%'
    )
  )
  WHERE fp IS NOT NULL AND fp <> '' AND SUBSTR(fp, 1, 1) <> '_'"""


def _edges(cte: str, method: str, evidence: str, strength: str,
           min_ips: int = _FP_MIN_IPS, max_ips: int = _FP_MAX_IPS) -> str:
    """Directed (ip, other_ip) edges for one shared key, gated by popularity.

    The gate is applied to the key BEFORE the self-join, so the join never sees a
    1,401-IP stock-browser fingerprint at all. That is the correctness fix and the
    cost fix in one place.

    `share` (how many IPs hold this key) is carried through so the evidence string
    can tell an analyst how much the match is worth.
    """
    return f"""  SELECT a.ip, b.ip other_ip, '{method}' method,
         {evidence} evidence, '{strength}' strength
  FROM (
    SELECT k.*, g.share
    FROM {cte} k
    JOIN (
      SELECT fp, COUNT(DISTINCT ip) share
      FROM {cte}
      GROUP BY fp
      HAVING COUNT(DISTINCT ip) BETWEEN {min_ips} AND {max_ips}
    ) g ON g.fp = k.fp
  ) a
  JOIN {cte} b ON b.fp = a.fp AND b.ip <> a.ip"""


def build_device_links_sql(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """One row per (ip, dt) naming the other IPs that belong to the same owner.

    A UNION ALL of one edge block per method, then a single aggregation to one row
    per IP. Not a chain of joins: the methods are independent evidence, and
    joining them would multiply an IP's rows by the number that fired.

    Returns None when no method can be satisfied, so a partial catalog skips the
    step rather than writing a table of nulls.
    """
    # Column-level gating: an `ssl` that predates ja3 would otherwise build a CTAS
    # that fails, and one failed statement loses the whole hourly rebuild.
    havecol = lambda t, c: all(x in tables.get(t, ()) for x in c)  # noqa: E731

    sources: list[tuple[str, str]] = []
    blocks: list[str] = []

    if havecol("known_devices", ("host_ip", "mac")):
        # A MAC on two IPs is the same NIC, full stop. Still needs the DISTINCT: a
        # renewing host writes the same pair thousands of times.
        sources.append(("kd_mac", f"""  SELECT DISTINCT host_ip ip, LOWER(mac) fp
  FROM {database}.known_devices
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND {_present('mac')}"""))
        blocks.append(_edges(
            "kd_mac", "same_mac",
            "'same MAC ' || a.fp || ' seen on both IPs'", "high",
            max_ips=_MAC_MAX_IPS))

    if havecol("dhcp", ("mac", "assigned_addr")):
        # The second MAC source, and it disagrees with known_devices often enough
        # to be worth both: a host that leased but never talked appears only here.
        sources.append(("dh_mac", f"""  SELECT DISTINCT assigned_addr ip, LOWER(mac) fp
  FROM {database}.dhcp
  WHERE dt = '{date_str}' AND {_present('assigned_addr')} AND {_present('mac')}"""))
        blocks.append(_edges(
            "dh_mac", "same_mac",
            "'same MAC ' || a.fp || ' leased both IPs'", "high",
            max_ips=_MAC_MAX_IPS))

    if havecol("ssl", ("id_orig_h", "ja3")):
        # The highest-leverage method: a ja3 is stable per device across networks,
        # so it survives the MAC randomization that defeats same_mac entirely.
        sources.append(("ja3", _fp_source(database, date_str, "ssl", "ja3")))
        blocks.append(_edges(
            "ja3", "same_ja3",
            "'same laptop on another network — ja3 match (' || CAST(a.share AS VARCHAR)"
            " || ' IPs share ' || SUBSTR(a.fp, 1, 8) || ')'", "high"))

    if havecol("ssh", ("id_orig_h", "hassh")):
        # 21 distinct hassh / 108 IPs, so this contributes little by volume. Kept
        # because a hassh inside the band is rare enough that a match is one box.
        sources.append(("hassh", _fp_source(database, date_str, "ssh", "hassh")))
        blocks.append(_edges(
            "hassh", "same_hassh",
            "'same SSH client — hassh match (' || SUBSTR(a.fp, 1, 8) || ')'", "high"))

    if havecol("rdp", ("id_orig_h", "rdfp_hash")):
        sources.append(("rdfp", _fp_source(database, date_str, "rdp", "rdfp_hash")))
        blocks.append(_edges(
            "rdfp", "same_rdfp",
            "'same RDP client — rdfp match (' || SUBSTR(a.fp, 1, 8) || ')'", "high"))

    if havecol("vpn", ("id_orig_h", "ja3")):
        # Its own method name rather than same_ja3: a VPN client fingerprint and a
        # browser fingerprint are read differently by an analyst, and merging them
        # would make link_methods claim ssl evidence this row does not have.
        sources.append(("vja3", _fp_source(database, date_str, "vpn", "ja3")))
        blocks.append(_edges(
            "vja3", "same_vpn_ja3",
            "'same VPN client — ja3 match (' || SUBSTR(a.fp, 1, 8) || ')'", "high"))

    if havecol("dns", ("id_orig_h", "query")):
        # A named Continuity instance on 2 IPs is a phone and its laptop. The bare
        # browse query on 1,903 IPs never gets here: _mdns_source drops it.
        sources.append(("mdns_comp", _mdns_source(database, date_str, _COMPANION_SERVICES)))
        blocks.append(_edges(
            "mdns_comp", "mdns_companion",
            "'their other device — mDNS ' || a.service || ' instance ' || a.fp"
            " || ' (' || CAST(a.share AS VARCHAR) || ' IPs)'", "high",
            max_ips=_MDNS_MAX_IPS))

        sources.append(("mdns_cast", _mdns_source(database, date_str, _CAST_SERVICES)))
        blocks.append(_edges(
            "mdns_cast", "shared_cast",
            "'same room/home — both resolve ' || a.service || ' ' || a.fp"
            " || ' (' || CAST(a.share AS VARCHAR) || ' IPs)'", "medium-high",
            max_ips=_CAST_MAX_IPS))

    if havecol("known_users", ("host_ip", "user_")):
        # Corroboration only: an account can be shared between people, which makes
        # it weaker evidence than one device's fingerprint.
        sources.append(("acct", f"""  SELECT DISTINCT host_ip ip, LOWER(user_) fp
  FROM {database}.known_users
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND {_present('user_')}"""))
        blocks.append(_edges(
            "acct", "shared_account",
            "'same account ' || a.fp || ' on both IPs'", "medium",
            max_ips=_ACCOUNT_MAX_IPS))

    if not blocks:
        return None

    have_macs = havecol("known_devices", ("host_ip", "mac"))
    mac_cte = ""
    other_mac_sel = "  CAST(NULL AS VARCHAR) other_mac"
    other_mac_join = ""
    mac_agg = "  CAST(NULL AS VARCHAR) linked_macs"
    mac_col = "  CAST(NULL AS VARCHAR) mac"
    mac_final_join = ""
    if have_macs:
        # Declared before `edges`, which reads it: Trino resolves CTEs in order, so
        # defining it later parses and then fails with "Table macs does not exist".
        mac_cte = f""",
macs AS (
  SELECT host_ip ip, ARBITRARY(LOWER(mac)) mac
  FROM {database}.known_devices
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND {_present('mac')}
  GROUP BY host_ip
)"""
        # One row per ip in `macs`, so this LEFT JOIN resolves the peer's MAC
        # without multiplying edges.
        other_mac_sel = "  mm.mac other_mac"
        other_mac_join = "\n  LEFT JOIN macs mm ON mm.ip = e.other_ip"
        mac_agg = ("  ARRAY_JOIN(SLICE(ARRAY_SORT(ARRAY_AGG(DISTINCT e.other_mac)"
                   f" FILTER (WHERE e.other_mac IS NOT NULL)), 1, {_MAX_LINKS}), ' | ')"
                   " linked_macs")
        mac_col = "  m.mac mac"
        mac_final_join = "\nLEFT JOIN macs m ON m.ip = c.ip"

    union = "\n  UNION ALL\n".join(blocks)
    source_ctes = ",\n".join(f"{name} AS (\n{body}\n)" for name, body in sources)

    # Edges are made symmetric before clustering. Most methods produce both
    # directions naturally (the self-join emits a->b and b->a), but the ceiling is
    # evaluated per key, so a key at the boundary can survive for one direction and
    # not the other. Without this, A lists B while B does not list A.
    #
    # owner_cluster_id then hashes the CANONICAL member set, not this IP's own
    # neighbours. In a cluster where A links B by ja3 and A links C by MAC, hashing
    # per-IP neighbourhoods gives A, B and C three different ids for one owner —
    # the id would not identify the cluster, which is its entire job. One round of
    # min-label propagation is enough for the 2-12 member clusters this produces
    # and costs one extra shuffle over a tiny set; true transitive closure needs
    # iteration Athena cannot express in a single statement.
    return f"""WITH {source_ctes}{mac_cte},
pairs AS (
{union}
),
sym AS (
  SELECT ip, other_ip, method, evidence, strength FROM pairs
  UNION
  SELECT other_ip ip, ip other_ip, method, evidence, strength FROM pairs
),
labels AS (
  SELECT ip, LEAST(MIN(other_ip), ip) label
  FROM sym
  GROUP BY ip
),
canon AS (
  SELECT s.ip, MIN(l.label) label
  FROM sym s
  JOIN labels l ON l.ip = s.other_ip
  GROUP BY s.ip
),
edges AS (
  SELECT e.ip, e.other_ip, e.method, e.evidence, e.strength,
{other_mac_sel}
  FROM sym e{other_mac_join}
),
clusters AS (
  SELECT e.ip,
         ARRAY_SORT(ARRAY_AGG(DISTINCT e.other_ip)) members,
         ARRAY_JOIN(ARRAY_SORT(ARRAY_AGG(DISTINCT e.method)), ',') link_methods,
         ARRAY_JOIN(SLICE(ARRAY_SORT(ARRAY_AGG(DISTINCT e.evidence)), 1, {_MAX_LINKS}), ' | ') link_evidence,
         ARRAY_AGG(DISTINCT e.strength) strengths,
{mac_agg}
  FROM edges e
  GROUP BY e.ip
)
SELECT
  c.ip ip,
{mac_col},
  '{date_str}' dt,
  LOWER(TO_HEX(MD5(TO_UTF8(LEAST(cn.label, c.ip))))) owner_cluster_id,
  ARRAY_JOIN(SLICE(c.members, 1, {_MAX_LINKS}), ' | ') linked_ips,
  c.linked_macs linked_macs,
  c.link_methods link_methods,
  c.link_evidence link_evidence,
  -- WEAKEST edge wins, not the strongest. A cluster is a single claim ("these are
  -- one owner's devices"), so it is only as trustworthy as its flimsiest member.
  -- Taking the max let one solid mDNS edge stamp 'high' on a cluster whose other
  -- eleven members joined on weak evidence, which is the worst way to be wrong:
  -- an analyst reads confident and acts on it.
  CASE WHEN CONTAINS(c.strengths, 'low') THEN 'low'
       WHEN CONTAINS(c.strengths, 'medium') THEN 'medium'
       WHEN CONTAINS(c.strengths, 'medium-high') THEN 'medium-high'
       ELSE 'high' END confidence
FROM clusters c
JOIN canon cn ON cn.ip = c.ip{mac_final_join}"""


def table_name(date_str: str) -> str:
    return f"device_links_{date_str.replace('-', '_')}"


def build_ctas(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """CREATE TABLE AS for one partition.

    No `external_location`: the workgroup sets EnforceWorkGroupConfiguration and
    rejects a CTAS that names its own output path. The caller reads the location
    off the existing table before dropping it instead.
    """
    body = build_device_links_sql(database, date_str, tables)
    if not body:
        return None
    return f"CREATE TABLE {database}.{table_name(date_str)} AS\n{body}"
