"""One row per host per day: everything known about an entity, pre-joined.

`uid_lookup` answers "what did this session do". This answers "what IS this host",
so an analyst pivoting off a session gets identity, accounts, exposure and risk in
a single join instead of six.

The pivot it enables:

    uid -> uid_lookup -> orig_h -> entity_context

That second hop exists because the `known_*` inventory tables do NOT carry the
session `uid`. They carry a `kuid`, which appears in no session log and is per
observation rather than per host (one host had 3 kuids across 4 rows), so
`host_ip` is the only real join key.

AGGREGATE FIRST, NEVER JOIN RAW. Measured on live data: `alerts` has up to 11,054
rows for a single host and `known_services` up to 4,433, so a naive
alerts x services LEFT JOIN produced 11,281,985 rows for ONE host. Every source
here collapses to one row per host before anything is joined.
"""

from __future__ import annotations

# Alert-name prefixes that are informational telemetry, not detections. The live
# feed already excludes these (agents/athena-hunter/main.py::alerts_recent), and
# the counts here must agree with what the analyst sees in the sidebar. Without
# this, DNS resolvers dominate: 10.220.199.121 alone logs 11,032 alerts, all of
# them "ET INFO Observed DNS Query".
_NOISE_PREFIXES: tuple[str, ...] = ("ET INFO", "ETPRO INFO")

# How many distinct values to carry in the top-N summary columns. Enough to be
# useful in an answer, small enough that a busy host does not blow up the row.
_TOP_N = 6

# SNI families for org attribution, as (kind, tenant-naming?, SQL predicate).
# Measured on dt=2026-08-01, in-scope only: okta+o365 alone reached 806 hosts.
# Broadening to these families reaches ~1,206 (jamf 583, webex 580, slack 496,
# o365 491, gworkspace 268, intune 246, zoom 195, duo 117, auth0 89, okta 80,
# zscaler 67, edr 52, palo_sase 51, atlassian 49, kandji 36, the rest <25).
#
# `naming` is the half that matters for attribution: a tenant label in an SSO or
# collaboration hostname IS the employer's name, whereas an EDR/MDM/SASE endpoint
# says someone's IT owns the box without naming the company, so it corroborates.
_ORG_SNI: tuple[tuple[str, bool, str], ...] = (
    ("okta", True, "(sni LIKE '%.okta.com' OR sni LIKE '%.oktapreview.com'"
                   " OR sni LIKE '%.okta-emea.com')"),
    ("o365", True, "sni LIKE '%.sharepoint.com'"),
    ("entra", True, "sni LIKE '%.onmicrosoft.com'"),
    ("ping", True, "(sni LIKE '%.pingone.com' OR sni LIKE '%.pingidentity.com')"),
    ("onelogin", True, "sni LIKE '%.onelogin.com'"),
    ("auth0", True, "sni LIKE '%.auth0.com'"),
    ("jumpcloud", True, "sni LIKE '%.jumpcloud.com'"),
    ("slack", True, "sni LIKE '%.slack.com'"),
    ("zoom", True, "(sni LIKE '%.zoom.us' OR sni LIKE '%.zoomgov.com')"),
    ("atlassian", True, "sni LIKE '%.atlassian.net'"),
    ("duo", False, "sni LIKE '%.duosecurity.com'"),
    ("jamf", False, "(sni LIKE '%.jamfcloud.com' OR sni LIKE '%.jamf.com')"),
    ("kandji", False, "sni LIKE '%.kandji.io'"),
    ("intune", False, "(sni LIKE '%.manage.microsoft.com' OR sni LIKE '%intune%')"),
    ("workspaceone", False, "(sni LIKE '%.awmdm.com' OR sni LIKE '%workspaceone%')"),
    ("netskope", False, "(sni LIKE '%.goskope.com' OR sni LIKE '%netskope%')"),
    ("zscaler", False, "(sni LIKE '%zscaler%' OR sni LIKE '%.zscloud.net')"),
    ("cloudflare_zt", False, "sni LIKE '%.cloudflareaccess.com'"),
    ("palo_sase", False, "(sni LIKE '%.prismaaccess.com' OR sni LIKE '%gpcloudservice%')"),
    ("edr", False, "(" + " OR ".join(
        f"sni LIKE '%{s}%'"
        for s in ("crowdstrike", "carbonblack", "conferdeploy", "sentinelone")
    ) + ")"),
    ("webex", False, "sni LIKE '%webex%'"),
    # 268 hosts but only 6 distinct SNIs, so this is one shared Google endpoint that
    # every Workspace tenant hits. It corroborates managed-ness and names no company.
    ("gworkspace", False, "(sni LIKE '%.google.com' AND sni LIKE '%workspace%')"),
    # The company is what FOLLOWS 'autodiscover.', so label 1 is never the tenant.
    ("autodiscover", True, "sni LIKE 'autodiscover.%'"),
)

# The tenant is label 1 of the SNI in every family except autodiscover. Verified
# against the real distinct shapes rather than assumed:
# <t>.gr.global.aa-rt.sharepoint.com (316 hosts), <t>.enterprise.slack.com (119),
# <t>.telemetry.zoom.us (68), <t>.sso.duosecurity.com (55), <t>.web-api.kandji.io
# (27), <t>.jra.services.jamfcloud.com (6).
_TENANT = "SPLIT_PART(sni, '.', 1)"

# autodiscover.<corp>.tld puts the employer in label 2, and the registrable domain is
# a better employer string than a bare label.
_TENANT_OVERRIDE: dict[str, str] = {
    "autodiscover": "REGEXP_EXTRACT(sni, '^autodiscover\\.(.+)$', 1)",
}

# Label 1 is only a company name when it is not one of these. Measured: without
# this denylist, 3 of slack's label-1 values, 4 of zoom's and 2 of okta's are
# infrastructure words, and duo's shapes are dominated by 'sso'/'login' — org_name
# would read "login" or "www" for hundreds of hosts.
_INFRA_LABELS: tuple[str, ...] = (
    "login", "signin", "sign-in", "sso", "www", "auth", "oauth", "id", "idp",
    "identity", "portal", "mail", "outlook", "vpn", "autodiscover", "api", "app",
    "apps", "my", "secure", "account", "accounts", "files", "teams", "admin",
    "cdn", "static", "connect", "gateway", "remote", "web", "service", "services",
    "client", "clients", "device", "devices", "enroll", "enrollment", "mdm", "ds",
    "dl", "ota", "tenant", "default", "test", "dev", "prod", "stage", "staging",
    "global", "edge", "proxy", "gw", "ns1", "ns2", "host", "server", "cloud",
    "telemetry", "asynccomm", "endpointhealth", "devicemanagement", "azureauth",
)

# An owner_name may only be emitted when its label is this rare or rarer, counted in
# distinct IPs on the day. MEASURED, and the whole point of the gate: person-looking
# mDNS labels on 11-50 IPs (max 60) are shared AirPlay/companion-link endpoints in
# session rooms, and every single label above 10 IPs resolved to _airplay or
# _companion-link. Attributing one staffer's name to 60 strangers is the failure this
# prevents. At <=10 the distribution is 116 labels holding 344 IP-mentions.
_OWNER_MAX_IPS = 10

# Labels that name a room, an appliance or a service instead of a person. Bare
# service types are excluded structurally (the instance-name regex requires a first
# label that does not start with '_'), and '._sub.' records are subtype registrations
# that name nobody -- 38,023 of the in-scope .local rows.
_OWNER_STOPWORDS: tuple[str, ...] = (
    "conference", "meeting", "boardroom", "huddle", "training", "classroom",
    "apple tv", "appletv", "chromecast", "google home", "nest", "roku", "firetv",
    "sonos", "echo", "alexa", "printer", "print", "scanner", "mfp", "brother",
    "canon", "epson", "hp ", "lexmark", "xerox", "kiosk", "signage", "display",
    "projector", "camera", "sensor", "thermostat", "guest", "lobby", "reception",
    "shared", "public", "demo", "loaner", "spare", "test", "lab", "noc", "soc",
)

# Zeek writes '-' for an absent field, and the raw loader types every column as
# string, so the empty marker has to be filtered as a value rather than as NULL.
# '(empty)' is Zeek's marker for a present-but-empty SET/VECTOR field and it appears
# on 2,376 in-scope IPs in ssl's client-cert columns alone. It was missing here, so
# every consumer treated the literal text "(empty)" as a real value.
_EMPTY = "('', '-', '(empty)')"


def _noise_filter(column: str = "alert_name") -> str:
    return " AND ".join(
        f"UPPER({column}) NOT LIKE '{p}%'" for p in _NOISE_PREFIXES
    )


def _present(value_col: str) -> str:
    return f"{value_col} IS NOT NULL AND {value_col} NOT IN {_EMPTY}"


# An instance-named mDNS record: label 1 does not begin with '_'. Bare browse queries
# like '_companion-link._tcp.local' are on 1,903 IPs and name nobody, and they fail
# this structurally rather than by a blocklist. 484,407 of the in-scope .local rows
# are that one bare query.
_MDNS_INSTANCE = r"'^[^_.][^.]*\._[a-z0-9-]+\._(tcp|udp)\.local\.?$'"

# The possessive and hostname grammars that actually name a human, in priority order.
# THE APOSTROPHE IS U+2019, NOT ASCII. Measured on the in-scope .local rows: 58,170
# match the unicode form and only 2,992 the ASCII one, so a rule written with '' alone
# silently misses 95% of the evidence. Both are accepted.
_OWNER_STEM_RULES: tuple[str, ...] = (
    r"'^([a-z][a-z-]{1,20})(?:\x{2019}|'')s(?:[ -]|$)'",
    r"'^([a-z][a-z-]{2,20})s-(?:iphone|ipad|macbook|mac|air|pro|laptop|pc|phone|watch|mbp|imac)'",
    r"'^([a-z][a-z-]{2,20})-(?:iphone|ipad|macbook|mbp|imac|pc|laptop)(?:$|-)'",
    r"'^desktop-([a-z0-9]{5,15})$'",
)


def _owner_stem(label_col: str) -> str:
    """First stem rule that fires, or NULL. COALESCE keeps the rules in priority order."""
    arms = ",\n           ".join(
        f"NULLIF(REGEXP_EXTRACT({label_col}, {rule}, 1), '')"
        for rule in _OWNER_STEM_RULES
    )
    return f"COALESCE(\n           {arms}\n         )"


def _not_appliance(label_col: str) -> str:
    return " AND ".join(
        f"{label_col} NOT LIKE '%{w}%'" for w in _OWNER_STOPWORDS
    )


def _not_infra(expr: str) -> str:
    inner = ", ".join(f"'{w}'" for w in _INFRA_LABELS)
    return f"LOWER({expr}) NOT IN ({inner})"


def _dominant(database: str, date_str: str, table: str, value_col: str,
              out_col: str, ip_col: str = "id_orig_h") -> str:
    """The single most-frequent `value_col` per host, already one row per host.

    Top-1 rather than a list because these are cross-network link keys: a device
    running one browser emits a dozen ja3s from its apps, and only the dominant
    one is stable enough to match the same device on another network.
    """
    return f"""(
  SELECT ip, {out_col} FROM (
    SELECT {ip_col} ip, {value_col} {out_col},
           ROW_NUMBER() OVER (PARTITION BY {ip_col} ORDER BY COUNT(*) DESC) rn
    FROM {database}.{table}
    WHERE dt = '{date_str}' AND {ip_col} IS NOT NULL AND {_present(value_col)}
    GROUP BY {ip_col}, {value_col}
  ) WHERE rn = 1
)"""


def _sw_part(col: str) -> str:
    return f"NULLIF(NULLIF(TRY_CAST({col} AS VARCHAR), '-'), '')"


def build_entity_context_sql(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """One row per host_ip for `date_str`, merging every entity-shaped source.

    Uses FULL OUTER JOIN rather than starting from one spine: a host can appear in
    the inventory without alerting, or alert without ever being inventoried, and
    both are worth seeing. Starting from `alerts` would hide quiet hosts; starting
    from `asset_classification` would hide alerting hosts it never classified.

    Returns None if nothing joinable exists, so a partial catalog skips the step
    rather than writing a table of nulls.
    """
    have = lambda t: t in tables  # noqa: E731
    # Column-level too: a catalog where `ssl` exists but predates ja3 would make a
    # CTAS that fails, and one failed statement loses the whole rebuild.
    havecol = lambda t, c: c in tables.get(t, ())  # noqa: E731

    ctes: list[str] = []
    # (cte alias, ip column) in the order they get folded together
    parts: list[tuple[str, str]] = []

    if have("asset_classification") or have("asset_classification_" + date_str.replace("-", "_")):
        # The stable view is rebuilt to point at today's partition, so read that.
        ctes.append(f"""ac AS (
  SELECT ip,
         ARBITRARY(mac) mac, ARBITRARY(vendor_mac) vendor_mac,
         ARBITRARY(hostname) hostname, ARBITRARY(os_name) os_name,
         ARBITRARY(device_type) device_type, ARBITRARY(org_name) org_name,
         ARBITRARY(mgmt_tooling) mgmt_tooling,
         ARBITRARY(randomized_mac) randomized_mac,
         ARBITRARY(network_name) network_name, ARBITRARY(room_name) room_name,
         SUM(connections) connections, SUM(mb_in) mb_in, SUM(mb_out) mb_out,
         MIN(first_seen) first_seen, MAX(last_seen) last_seen,
         ARBITRARY(confidence) id_confidence
  FROM {database}.asset_classification
  GROUP BY ip
)""")
        parts.append(("ac", "ip"))

    if have("alerts") or have("suricata_corelight"):
        # Two counts on purpose. `alert_count` excludes informational noise so it
        # matches the sidebar; `alert_count_all` keeps the raw total so a DNS
        # resolver's volume is still visible if someone asks for it.
        ctes.append(f"""al AS (
  SELECT orig_h ip,
         COUNT(*) alert_count_all,
         SUM(CASE WHEN {_noise_filter()} THEN 1 ELSE 0 END) alert_count,
         SUM(CASE WHEN severity IN ('critical','high') AND {_noise_filter()}
                  THEN 1 ELSE 0 END) high_alert_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT alert_type), 1, {_TOP_N}), ',') alert_types,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT CASE WHEN {_noise_filter()}
                    THEN alert_name END), 1, {_TOP_N}), ' | ') top_alerts,
         MAX(ts_datetime) last_alert_at
  FROM {database}.alerts
  WHERE dt = '{date_str}' AND orig_h IS NOT NULL
  GROUP BY orig_h
)""")
        parts.append(("al", "ip"))

    if have("known_users"):
        # Observed account names. The highest-value identity signal in the data and
        # the most sensitive: an analyst asking "who is on this host" gets a real
        # answer. Sparse by nature (6 hosts today), so expect nulls.
        ctes.append(f"""ku AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT user_), 1, {_TOP_N}), ',') observed_users,
         COUNT(DISTINCT user_) user_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT protocol), 1, {_TOP_N}), ',') user_protocols
  FROM {database}.known_users
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND user_ IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("ku", "ip"))

    if have("known_services"):
        ctes.append(f"""ks AS (
  SELECT host_ip ip,
         COUNT(DISTINCT service) service_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT service), 1, {_TOP_N}), ',') services,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT CAST(port_num AS VARCHAR)), 1, {_TOP_N}), ',') listening_ports
  FROM {database}.known_services
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND service IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("ks", "ip"))

    if have("known_names"):
        ctes.append(f"""kn AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT hostname), 1, {_TOP_N}), ',') observed_hostnames
  FROM {database}.known_names
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND hostname IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("kn", "ip"))

    if have("known_domains"):
        ctes.append(f"""kdom AS (
  SELECT host_ip ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT domain), 1, {_TOP_N}), ',') announced_domains
  FROM {database}.known_domains
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND domain IS NOT NULL
  GROUP BY host_ip
)""")
        parts.append(("kdom", "ip"))

    if have("uid_lookup") or have("conn"):
        # Session reach: how much of the network's activity this host accounts for,
        # and which log types it shows up in. This is the column that makes the
        # uid -> entity pivot worth doing in one query.
        ctes.append(f"""ul AS (
  SELECT orig_h ip,
         COUNT(DISTINCT uid) session_count,
         COUNT(DISTINCT log_type) log_type_count,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT log_type), 1, {_TOP_N + 4}), ',') log_types
  FROM {database}.uid_lookup
  WHERE dt = '{date_str}' AND orig_h IS NOT NULL
  GROUP BY orig_h
)""")
        parts.append(("ul", "ip"))

    if havecol("ssl", "server_name"):
        # org_name already exists (from asset_classification); this is the WHY, so
        # an analyst can see whether "ACME" came from one SNI or four agreeing ones.
        kind_case = "\n               ".join(
            f"WHEN {pred} THEN '{kind}'" for kind, _, pred in _ORG_SNI
        )
        any_org = " OR ".join(f"({pred})" for _, _, pred in _ORG_SNI)
        tenant_case = "\n               ".join(
            f"WHEN {pred} THEN {_TENANT_OVERRIDE.get(kind, _TENANT)}"
            for kind, naming, pred in _ORG_SNI if naming
        )
        naming_kinds = ", ".join(f"'{k}'" for k, n, _ in _ORG_SNI if n)
        # A tenant that survived the denylist is the employer string; a family without
        # one only proves someone's IT owns the box, so it corroborates.
        named = f"COUNT(DISTINCT CASE WHEN tenant IS NOT NULL THEN kind END)"
        ctes.append(f"""org AS (
  SELECT ip,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT ev), 1, {_TOP_N}), ' | ') org_reasons,
         CASE WHEN {named} >= 2 THEN 'high'
              WHEN {named} = 1 AND COUNT(DISTINCT kind) >= 2 THEN 'high'
              WHEN {named} = 1 THEN 'medium'
              ELSE 'low' END org_confidence,
         MAX_BY(tenant, CASE WHEN tenant IS NULL THEN 0 ELSE n END) org_tenant,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT CASE WHEN tenant IS NOT NULL
                    THEN kind END), 1, {_TOP_N}), ',') org_tenant_sources
  FROM (
    SELECT ip, kind, tenant, n,
           kind || ':' || COALESCE(tenant || '@', '') || sni ev
    FROM (
      SELECT ip, kind, sni, COUNT(*) n,
             CASE WHEN kind IN ({naming_kinds}) AND {_not_infra('raw_tenant')}
                       AND LENGTH(raw_tenant) >= 3
                       AND NOT REGEXP_LIKE(raw_tenant, '^[0-9]+$')
                  THEN raw_tenant END tenant
      FROM (
        SELECT id_orig_h ip, sni,
               CASE {kind_case}
               END kind,
               CASE {tenant_case}
               END raw_tenant
        FROM (
          SELECT id_orig_h, LOWER(server_name) sni
          FROM {database}.ssl
          WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL
            AND {_present('server_name')}
        ) WHERE ({any_org})
      ) WHERE kind IS NOT NULL
      GROUP BY ip, kind, sni, raw_tenant
    )
  )
  GROUP BY ip
)""")
        parts.append(("org", "ip"))

    own_labels = []
    if havecol("dns", "query"):
        # Only INSTANCE-NAMED mDNS records. 3.66M in-scope .local rows, of which
        # 484,407 are the bare '_companion-link._tcp.local' browse query on 1,903 IPs
        # that names nobody, and 38,023 are '._sub.' subtype registrations.
        own_labels.append(f"""    SELECT id_orig_h ip, 'mdns' src,
           LOWER(REGEXP_EXTRACT(query, '^(.*)\\._[a-z0-9-]+\\._(?:tcp|udp)\\.local\\.?$', 1)) label
    FROM {database}.dns
    WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL AND {_present('query')}
      AND query LIKE '%.local%' AND query NOT LIKE '%._sub.%'
      AND REGEXP_LIKE(query, {_MDNS_INSTANCE})""")
    if havecol("known_names", "hostname"):
        own_labels.append(f"""    SELECT host_ip ip, 'known_names' src,
           LOWER(REGEXP_REPLACE(hostname, '\\.local\\.?$', '')) label
    FROM {database}.known_names
    WHERE dt = '{date_str}' AND host_ip IS NOT NULL AND {_present('hostname')}""")
    if own_labels:
        # Corroboration: a stem that also matches this IP's DHCP hostname was set by
        # the device itself, not just announced, so it is the one thing that lifts a
        # single-IP label to 'high'.
        if havecol("dhcp", "host_name") and havecol("dhcp", "assigned_addr"):
            dhcp_stem = f"""  dhcp_stem AS (
    SELECT assigned_addr ip, {_owner_stem('LOWER(host_name)')} stem
    FROM {database}.dhcp
    WHERE dt = '{date_str}' AND {_present('assigned_addr')} AND {_present('host_name')}
    GROUP BY assigned_addr, host_name
  ),"""
            dhcp_join = "LEFT JOIN dhcp_stem d ON d.ip = s.ip AND d.stem = s.stem"
            corroborated = "MAX(CASE WHEN d.stem IS NOT NULL THEN 1 ELSE 0 END)"
        else:
            dhcp_stem, dhcp_join, corroborated = "", "", "0"
        union = "\n    UNION ALL\n".join(own_labels)
        # owner_name is emitted ONLY when the label is rare. See _OWNER_MAX_IPS: every
        # person-looking label above that ceiling was a shared AirPlay/companion-link
        # endpoint, so the gate is the difference between naming an owner and libelling
        # up to 60 strangers with one staffer's name.
        ctes.append(f"""own AS (
  WITH lab AS (
{union}
  ),
  stems AS (
    SELECT ip, src, label, {_owner_stem('label')} stem
    FROM lab
    WHERE label IS NOT NULL AND label <> '' AND {_not_appliance('label')}
    GROUP BY ip, src, label
  ),
  s AS (SELECT * FROM stems WHERE stem IS NOT NULL),
  rare AS (SELECT label, COUNT(DISTINCT ip) nip FROM s GROUP BY label),
  -- The ceiling has to bind the value actually emitted. Gating labels alone was
  -- measured to leak: two labels that are individually rare ("<first>’s mbp" and
  -- "<first>s-iphone") share one stem, so 3 stems still reached up to 14 IPs. A
  -- stem on many IPs is either a shared endpoint or a common given name, and
  -- neither identifies a person.
  rare_stem AS (SELECT stem, COUNT(DISTINCT ip) snip FROM s GROUP BY stem),
{dhcp_stem}
  scored AS (
    SELECT s.ip, s.stem, s.label, s.src, r.nip, rs.snip, {corroborated} corroborated
    FROM s
    JOIN rare r ON r.label = s.label
    JOIN rare_stem rs ON rs.stem = s.stem
    {dhcp_join}
    WHERE r.nip <= {_OWNER_MAX_IPS} AND rs.snip <= {_OWNER_MAX_IPS}
    GROUP BY s.ip, s.stem, s.label, s.src, r.nip, rs.snip
  )
  SELECT ip,
         MAX_BY(stem, score) owner_name,
         MAX_BY(src || ':' || label || ' (' || CAST(nip AS VARCHAR) || ' ip, stem '
                || CAST(snip AS VARCHAR) || ' ip)', score) owner_name_source,
         CASE WHEN MAX(score) >= 300 THEN 'high'
              WHEN MAX(score) >= 200 THEN 'medium'
              ELSE 'low' END owner_name_confidence
  FROM (
    SELECT ip, stem, label, src, nip, snip,
           CASE WHEN snip = 1 THEN 200 WHEN snip <= 3 THEN 100 ELSE 0 END
           + CASE WHEN corroborated = 1 THEN 150 ELSE 0 END
           + CASE WHEN src = 'known_names' THEN 50 ELSE 0 END score
    FROM scored
  )
  GROUP BY ip
)""")
        parts.append(("own", "ip"))

    if havecol("conn", "remote_country"):
        # NOT the `geo` table: it has 4 rows. Destination country majority share off
        # conn is the only geo signal with real coverage.
        #
        # THE ISO2 GUARD IS LOAD-BEARING. `remote_country` is a VARCHAR the loader
        # does not validate, and on dt=2026-08-01 only 6.96M of 44.3M in-scope rows
        # hold an actual country code. The rest are 40-char hex hashes (22.1M rows /
        # 3,249 IPs) and stringified floats. Without the regexp the majority share is
        # usually a hash, so home_region shipped a hex blob as a "country" at medium
        # or high confidence. Reject anything that is not two uppercase letters.
        #
        # No timezone term. A UTC peak hour was tried and measured: it moves 4.12h
        # between consecutive days for the same host and 0 of 96 APAC-ccTLD hosts
        # peaked in the APAC business day, because it tracks the venue's schedule
        # rather than where anyone lives. An unfalsifiable residency claim about a
        # real attendee is worse than no claim.
        #
        # One pass over a 40M-row table: group by (ip, country) once and derive the
        # share with a window function instead of scanning twice.
        ctes.append(f"""home AS (
  SELECT ip, home_region,
         CASE WHEN pct >= 60 THEN 'high'
              WHEN pct >= 35 THEN 'medium'
              ELSE 'low' END home_confidence,
         'geo:' || CAST(pct AS VARCHAR) || '% conns to ' || home_region home_reasons
  FROM (
    SELECT ip,
           MAX_BY(country, country_c) home_region,
           CAST(ROUND(100.0 * MAX(country_c) / ARBITRARY(total_c)) AS INTEGER) pct
    FROM (
      SELECT ip, country,
             SUM(c) OVER (PARTITION BY ip, country) country_c,
             SUM(c) OVER (PARTITION BY ip) total_c
      FROM (
        SELECT id_orig_h ip, remote_country country, COUNT(*) c
        FROM {database}.conn
        WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL
          AND {_present('remote_country')}
          AND REGEXP_LIKE(remote_country, '^[A-Z]{{2}}$')
        GROUP BY id_orig_h, remote_country
      )
    )
    GROUP BY ip
  )
)""")
        parts.append(("home", "ip"))

    if havecol("dns", "query"):
        # A laptop still configured for its employer's AD appends that domain to every
        # short name it looks up, so wpad / _ldap._tcp / _msdcs queries leak the
        # employer's internal domain. Measured in-scope: 206 hosts, 485 domains
        # (wpad 160, _msdcs 143, _ldap 72). Genuinely additive rather than a rederivation
        # of the SNI signal -- these are overwhelmingly NXDOMAIN, so no TLS handshake
        # ever happens and no server_name can ever name them.
        #
        # _msdcs and _ldap are Active Directory itself and only a domain member emits
        # them; wpad is a plain search-suffix artifact any DHCP client will emit, so it
        # is the weaker of the two.
        ad_ranked = "MAX(CASE WHEN kind IN ('msdcs','ldap') THEN 2 ELSE 1 END)"
        ctes.append(f"""idom AS (
  SELECT ip,
         MAX_BY(dom, rank) internal_domain,
         ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT kind || ':' || dom), 1, {_TOP_N}), ' | ')
           internal_domain_reasons,
         CASE WHEN {ad_ranked} = 2 THEN 'high' ELSE 'medium' END internal_domain_confidence
  FROM (
    SELECT ip, dom, kind, COUNT(*) rank
    FROM (
      SELECT ip, kind,
             COALESCE(
               REGEXP_EXTRACT(q, '^_(?:ldap|kerberos)\\._tcp\\.(?:dc\\._msdcs\\.|[a-z0-9-]+\\._sites\\.(?:dc\\._msdcs\\.)?)?([a-z0-9-]+(?:\\.[a-z0-9-]+)+)\\.?$', 1),
               REGEXP_EXTRACT(q, '_msdcs\\.([a-z0-9-]+(?:\\.[a-z0-9-]+)+)\\.?$', 1),
               REGEXP_EXTRACT(q, '^wpad\\.([a-z0-9-]+(?:\\.[a-z0-9-]+)+)\\.?$', 1)
             ) dom
      FROM (
        SELECT id_orig_h ip, LOWER(query) q,
               CASE WHEN REGEXP_LIKE(LOWER(query), '_msdcs\\.') THEN 'msdcs'
                    WHEN LOWER(query) LIKE 'wpad.%' THEN 'wpad'
                    ELSE 'ldap' END kind
        FROM {database}.dns
        WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL AND {_present('query')}
          AND REGEXP_LIKE(LOWER(query),
              '^(wpad\\.|_ldap\\._tcp\\.|_kerberos\\._tcp\\.)|_msdcs\\.')
      )
    )
    WHERE dom IS NOT NULL AND dom <> ''
      AND NOT REGEXP_LIKE(dom, '(^|\\.)(local|arpa|lan|home|internal|localdomain|localhost)$')
      AND dom NOT LIKE '%blackhat%'
    GROUP BY ip, dom, kind
  )
  GROUP BY ip
)""")
        parts.append(("idom", "ip"))

    if havecol("ssl", "client_issuer") and havecol("ssl", "client_subject"):
        # mTLS enrolment, not SNI guessing: a client certificate was ISSUED to this
        # device by whoever manages it. Measured in-scope on 375 hosts having any
        # client-cert field, 216 with an issuer O=, of which 105 hosts / 48 orgs are
        # employer-specific CAs and 106 a SASE vendor's inspection CA.
        #
        # THE RAW client_subject IS NEVER STORED. Measured, it carries a person's name,
        # work email, employer and office in a single string: 28 in-scope hosts have an
        # emailAddress= in it and 175 an O=. Only a SHA-256 of the DN ships, so an
        # analyst can still prove two sightings are the same certificate and pivot on
        # it, without entity_context becoming a directory of attendees' work emails.
        # The issuer organisation is kept because it names the employer or its MDM, not
        # the human, and the class is deliberately coarse.
        vend = {
            "mdm": ("jamf", "kandji", "microsoft", "intune", "apple", "airwatch",
                    "workspace one", "vmware", "mosyle", "addigy", "jumpcloud"),
            "sase": ("zscaler", "netskope", "palo alto", "cloudflare", "cisco",
                     "fortinet", "forcepoint"),
            "public_ca": ("digicert", "sectigo", "globalsign", "entrust",
                          "let''s encrypt", "godaddy", "amazon", "verisign",
                          "thawte", "comodo"),
        }
        cls_case = "\n                    ".join(
            f"WHEN REGEXP_LIKE(io, '{'|'.join(v)}') THEN '{k}'"
            for k, v in vend.items()
        )
        ctes.append(f"""mtls AS (
  SELECT ip,
         MAX_BY(io, n) client_cert_issuer_org,
         MAX_BY(cls, n) client_cert_class,
         MAX_BY(dn_hash, n) client_cert_subject_hash,
         'mtls:' || MAX_BY(cls, n) || COALESCE(':' || MAX_BY(io, n), '')
           client_cert_reasons
  FROM (
    SELECT ip, io, dn_hash, n,
           CASE WHEN io IS NULL THEN 'unnamed_issuer'
                {cls_case}
                ELSE 'employer_specific' END cls
    FROM (
      SELECT id_orig_h ip,
             NULLIF(LOWER(TRIM(REGEXP_EXTRACT(client_issuer,
               '(?i)(?:^|,)\\s*O=([^,]+)', 1))), '') io,
             CASE WHEN {_present('client_subject')}
                  THEN LOWER(TO_HEX(SHA256(TO_UTF8(client_subject)))) END dn_hash,
             COUNT(*) n
      FROM {database}.ssl
      WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL
        AND ({_present('client_issuer')} OR {_present('client_subject')})
      GROUP BY id_orig_h, client_issuer, client_subject
    )
  )
  GROUP BY ip
)""")
        parts.append(("mtls", "ip"))

    if havecol("ssl", "ja3"):
        ctes.append("j3 AS " + _dominant(database, date_str, "ssl", "ja3", "client_ja3"))
        parts.append(("j3", "ip"))

    if havecol("ssh", "hassh"):
        # 108 hosts today. Kept anyway: an SSH client fingerprint is rare enough that
        # a match across two IPs is near-certainly the same device.
        ctes.append("hsh AS " + _dominant(database, date_str, "ssh", "hassh", "client_hassh"))
        parts.append(("hsh", "ip"))

    if havecol("software", "host"):
        # `software` keys on `host`, NOT id_orig_h. Nothing else in the catalog does
        # this, and joining on id_orig_h silently yields an all-null column.
        # `host` is quoted because reserved words only take backticks in DDL.
        #
        # version_minor2/minor3 are browser build numbers that roll daily, so they
        # would churn this cell without telling an analyst anything.
        ver = (f"COALESCE(' ' || {_sw_part('version_major')}, '')"
               f" || COALESCE('.' || {_sw_part('version_minor')}, '')"
               f" || COALESCE(' ' || {_sw_part('version_addl')}, '')")
        ctes.append(f"""sw AS (
  SELECT ip, ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT product), 1, {_TOP_N}), '; ') os_versions
  FROM (
    SELECT "host" ip, TRIM(name || {ver}) product
    FROM {database}.software
    WHERE dt = '{date_str}' AND "host" IS NOT NULL AND {_present('name')}
    GROUP BY "host", name, version_major, version_minor, version_addl
  )
  GROUP BY ip
)""")
        parts.append(("sw", "ip"))

    du_sources = []
    if havecol("ntlm", "username") and havecol("ntlm", "domainname"):
        # Normalized to kerberos' user@REALM shape rather than DOMAIN\user: a lone
        # backslash in a Trino string literal is not escape-processed, and every
        # consumer downstream would have to guess whether it was doubled.
        du_sources.append(f"""    SELECT id_orig_h ip, username || '@' || domainname principal
    FROM {database}.ntlm
    WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL AND {_present('username')}
      AND {_present('domainname')}""")
    if havecol("kerberos", "client"):
        du_sources.append(f"""    SELECT id_orig_h ip, client principal
    FROM {database}.kerberos
    WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL AND {_present('client')}""")
    if du_sources:
        # 1 ntlm row and 20 kerberos rows at this show, so this is opportunistic: a
        # populated cell is a gift, an empty one is the norm and not a bug.
        union = "\n    UNION ALL\n".join(du_sources)
        ctes.append(f"""du AS (
  SELECT ip, ARRAY_JOIN(SLICE(ARRAY_AGG(DISTINCT principal), 1, 3), ',') domain_user
  FROM (
{union}
  )
  GROUP BY ip
)""")
        parts.append(("du", "ip"))

    if not parts:
        return None

    # FULL OUTER so a host present in any single source still gets a row.
    first = parts[0][0]
    coalesce_chain = ", ".join(f"{a}.ip" for a, _ in parts)
    ip_expr = f"COALESCE({coalesce_chain})" if len(parts) > 1 else f"{first}.ip"

    joins = ""
    for alias, _ in parts[1:]:
        prior = ", ".join(f"{a}.ip" for a, _ in parts[:parts.index((alias, "ip"))])
        joins += f"\nFULL OUTER JOIN {alias} ON {alias}.ip = COALESCE({prior})"

    select_cols = [f"  {ip_expr} ip"]
    known_aliases = {a for a, _ in parts}
    for alias, cols in (
        ("ac", ["mac", "vendor_mac", "hostname", "os_name", "device_type", "org_name",
                "mgmt_tooling", "randomized_mac", "network_name", "room_name",
                "connections", "mb_in", "mb_out", "first_seen", "last_seen",
                "id_confidence"]),
        ("al", ["alert_count", "alert_count_all", "high_alert_count", "alert_types",
                "top_alerts", "last_alert_at"]),
        ("ku", ["observed_users", "user_count", "user_protocols"]),
        ("ks", ["service_count", "services", "listening_ports"]),
        ("kn", ["observed_hostnames"]),
        ("kdom", ["announced_domains"]),
        ("ul", ["session_count", "log_type_count", "log_types"]),
        ("org", ["org_confidence", "org_reasons", "org_tenant", "org_tenant_sources"]),
        ("own", ["owner_name", "owner_name_source", "owner_name_confidence"]),
        ("idom", ["internal_domain", "internal_domain_confidence",
                  "internal_domain_reasons"]),
        ("mtls", ["client_cert_issuer_org", "client_cert_class",
                  "client_cert_subject_hash", "client_cert_reasons"]),
        ("home", ["home_region", "home_confidence", "home_reasons"]),
        ("j3", ["client_ja3"]),
        ("hsh", ["client_hassh"]),
        ("sw", ["os_versions"]),
        ("du", ["domain_user"]),
    ):
        for c in cols:
            select_cols.append(f"  {alias}.{c} {c}" if alias in known_aliases
                               else f"  CAST(NULL AS VARCHAR) {c}")
    select_cols.append(f"  '{date_str}' dt")

    return ("WITH " + ",\n".join(ctes) + "\nSELECT\n" + ",\n".join(select_cols)
            + f"\nFROM {first}" + joins)


def table_name(date_str: str) -> str:
    return f"entity_context_{date_str.replace('-', '_')}"


def build_ctas(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """CREATE TABLE AS for one partition.

    Materialized, not a view: this is seven aggregations over the largest tables in
    the catalog, so evaluating it per query would be slow and expensive. The hourly
    rebuild keeps it current and reads stay cheap.
    """
    body = build_entity_context_sql(database, date_str, tables)
    if not body:
        return None
    return f"CREATE TABLE {database}.{table_name(date_str)} AS\n{body}"
