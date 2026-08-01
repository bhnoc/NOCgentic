"""Batch asset classification, ported from PostCog's per-IP profiler.

PostCog's `profiler.py` answers "what is this one host?" interactively: an analyst
gives it an IP, it fires ~15 Athena queries, and a human reads the result. That
shape does not work as a table. Running it per host over a conference network is
thousands of round trips.

This does the same inference set-based: one CTAS that classifies every host on a
partition at once. Same signals, same precedence, no per-IP fan-out.

What it produces (per ip, per dt):

    mac, vendor_mac       from known_devices / dhcp
    hostname              DHCP host_name
    os_name               HTTP User-Agent family
    device_type           phone / tablet / computer / iot, from UA + vendor
    org_name              SharePoint / Okta tenant, or academic domain
    randomized_mac        locally-administered bit, so "unknown vendor" is explained
    mgmt_tooling          Jamf / Kandji / CrowdStrike / etc, indicates a managed device
    connections, mb_in, mb_out, first_seen, last_seen
    network_name, room_name, ssid
    confidence            how much evidence actually backed the classification

The old `asset_classification` was an EXTERNAL_TABLE over Parquet in a bucket in
the retired account, with a producer nobody could find. This replaces it with
something whose logic is in git.

COVERAGE REALITY, measured 2026-08-01: only 270 of 18,900 hosts on the network emit
an HTTP User-Agent, because almost everything is TLS-only now. So os_name and
device_type resolve for ~1.5% of hosts and the rest are legitimately 'unknown',
with traffic stats and (where DHCP/known_devices saw them) mac/hostname/vendor
still populated. That is a limit of the evidence, not a bug in the join: do not
"fix" it by loosening the rules, which would just produce confident nonsense.
Better coverage needs a non-UA signal (JA3/JA4 fingerprinting off ssl, or DHCP
fingerprint via dhcp_fp_lite), which is a separate piece of work.
"""

from __future__ import annotations

# Byte columns are VARCHAR in the show catalog and Zeek writes '-' for empty, so
# TRY_CAST (NULL on junk, SUM skips NULLs) instead of summing varchar. Learned the
# hard way in PostCog: summing directly returned nothing at all.
_BYTES = "TRY_CAST({col} AS DOUBLE)"

# User-Agent to OS.
#
# Order matters twice over: 'iphone' must be tested before 'macintosh' (iOS UAs
# say "like Mac OS X"), and the narrow tokens must come before the broad ones.
#
# The needles are matched as SUBSTRINGS, which is a trap. 'cros' (ChromeOS) is a
# substring of "Microsoft-CryptoAPI", so a Windows box reported ChromeOS in the
# first run of this. Any needle short enough to appear inside an unrelated product
# name needs a delimiter baked in: ' cros' with the leading space is how the real
# ChromeOS UA writes it ("X11; CrOS x86_64").
_OS_RULES: tuple[tuple[str, str], ...] = (
    ("iphone", "iOS"),
    ("ipad", "iPadOS"),
    ("ipod", "iOS"),
    ("android", "Android"),
    ("; cros ", "ChromeOS"),
    ("cfnetwork", "Apple"),
    ("darwin", "Apple"),
    ("macintosh", "macOS"),
    ("mac os x", "macOS"),
    ("windows nt", "Windows"),
    ("microsoft-cryptoapi", "Windows"),
    ("windows-update-agent", "Windows"),
    ("linux", "Linux"),
    ("ubuntu", "Linux"),
    ("debian", "Linux"),
)

# Device class from the same UA evidence, coarser on purpose: a booth demo box and
# a laptop are both 'computer' and the distinction is not inferable from traffic.
#
# Kept in step with _OS_RULES: an OS needle with no device counterpart produced
# os_name set and device_type 'unknown', which reads as a data gap rather than the
# rule-table gap it actually was.
_DEVICE_RULES: tuple[tuple[str, str], ...] = (
    ("iphone", "phone"),
    ("ipod", "phone"),
    ("ipad", "tablet"),
    ("android", "phone"),
    ("; cros ", "computer"),
    ("macintosh", "computer"),
    ("mac os x", "computer"),
    ("darwin", "computer"),
    ("cfnetwork", "computer"),
    ("windows nt", "computer"),
    ("microsoft-cryptoapi", "computer"),
    ("windows-update-agent", "computer"),
    ("linux", "computer"),
    ("ubuntu", "computer"),
    ("debian", "computer"),
    ("curl", "tool"),
    ("wget", "tool"),
    ("python-requests", "tool"),
    ("go-http-client", "tool"),
)

# SNI substrings that indicate a centrally managed endpoint. Not a threat signal:
# it says someone's IT owns this device, which changes how you treat a finding on it.
_MGMT_SNI: tuple[str, ...] = (
    "jamf", "kandji", "crowdstrike", "carbonblack", "conferdeploy",
    "1password", "duosecurity", "netskope", "intune", "workspaceone",
)


def _case_from_rules(expr: str, rules: tuple[tuple[str, str], ...], default: str) -> str:
    """Build a CASE that lowercases once and tests substrings in order."""
    whens = "\n".join(
        f"      WHEN LOWER({expr}) LIKE '%{needle}%' THEN '{label}'"
        for needle, label in rules
    )
    return f"CASE\n{whens}\n      ELSE '{default}'\n    END"


def build_asset_classification_sql(database: str, date_str: str, tables: dict[str, set]) -> str | None:
    """One CTAS that classifies every host seen on `date_str`.

    Returns None if the tables it needs are absent, so a partial catalog skips the
    step instead of writing a table full of nulls.

    `conn` is the spine: every host that talked appears there. Everything else is a
    LEFT JOIN of enrichment, so a host with no HTTP traffic still gets a row with
    its traffic stats rather than vanishing.
    """
    if "conn" not in tables:
        return None

    have = lambda t: t in tables  # noqa: E731

    os_case = _case_from_rules("ua.user_agent", _OS_RULES, "unknown")
    device_case = _case_from_rules("ua.user_agent", _DEVICE_RULES, "unknown")
    mgmt_pred = " OR ".join(f"LOWER(server_name) LIKE '%{s}%'" for s in _MGMT_SNI)

    # Host-side traffic totals. A responder-only host (a booth box that only
    # receives) has zero rows as id_orig_h, so filtering one direction reports it
    # as absent. Count both and attribute bytes from THIS host's perspective.
    parts = [f"""
WITH hosts AS (
  SELECT ip, dt,
         COUNT(*) AS connections,
         ROUND(SUM(mb_out) / 1048576.0, 3) AS mb_out,
         ROUND(SUM(mb_in) / 1048576.0, 3) AS mb_in,
         MIN(ts_datetime) AS first_seen,
         MAX(ts_datetime) AS last_seen,
         ARBITRARY(network_name) AS network_name,
         ARBITRARY(room_name) AS room_name
  FROM (
    SELECT id_orig_h AS ip, dt, ts_datetime,
           {_BYTES.format(col='orig_bytes')} AS mb_out,
           {_BYTES.format(col='resp_bytes')} AS mb_in,
           id_orig_network_name AS network_name,
           {'id_orig_room_name' if 'id_orig_room_name' in tables['conn'] else 'CAST(NULL AS VARCHAR)'} AS room_name
    FROM {database}.conn WHERE dt = '{date_str}' AND id_orig_h IS NOT NULL
    UNION ALL
    SELECT id_resp_h AS ip, dt, ts_datetime,
           {_BYTES.format(col='resp_bytes')} AS mb_out,
           {_BYTES.format(col='orig_bytes')} AS mb_in,
           {'id_resp_network_name' if 'id_resp_network_name' in tables['conn'] else 'CAST(NULL AS VARCHAR)'} AS network_name,
           {'id_resp_room_name' if 'id_resp_room_name' in tables['conn'] else 'CAST(NULL AS VARCHAR)'} AS room_name
    FROM {database}.conn WHERE dt = '{date_str}' AND id_resp_h IS NOT NULL
  )
  GROUP BY ip, dt
)"""]

    # Identity. known_devices is the richer source (it resolves the OUI vendor);
    # dhcp adds the self-reported hostname.
    if have("known_devices"):
        parts.append(f""",
dev AS (
  SELECT host_ip AS ip,
         ARBITRARY(mac) AS mac,
         ARBITRARY(vendor_mac) AS vendor_mac
  FROM {database}.known_devices
  WHERE dt = '{date_str}' AND host_ip IS NOT NULL
  GROUP BY host_ip
)""")
    if have("dhcp"):
        parts.append(f""",
dh AS (
  SELECT ARBITRARY(host_name) AS hostname, mac, assigned_addr AS ip
  FROM {database}.dhcp
  WHERE dt = '{date_str}' AND assigned_addr IS NOT NULL
  GROUP BY mac, assigned_addr
)""")

    # Platform. Take the single most-used UA per host: a browser plus a dozen app
    # agents is normal, and the dominant one is the best OS signal.
    if have("http"):
        parts.append(f""",
ua AS (
  SELECT ip, user_agent FROM (
    SELECT id_orig_h AS ip, user_agent,
           ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC) AS rn
    FROM {database}.http
    WHERE dt = '{date_str}' AND user_agent IS NOT NULL AND user_agent <> ''
    GROUP BY id_orig_h, user_agent
  ) WHERE rn = 1
)""")

    # Organization, from SSO/enterprise SNI. A SharePoint or Okta tenant name is
    # the strongest attribution signal on a conference network.
    if have("ssl"):
        parts.append(f""",
org AS (
  SELECT ip, org_name FROM (
    SELECT id_orig_h AS ip,
           CASE
             WHEN server_name LIKE '%.sharepoint.com'
               THEN REPLACE(REPLACE(server_name, '.sharepoint.com', ''), '-my', '')
             WHEN server_name LIKE '%.okta.com'
               THEN REPLACE(server_name, '.okta.com', '')
           END AS org_name,
           ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC) AS rn
    FROM {database}.ssl
    WHERE dt = '{date_str}'
      AND (server_name LIKE '%.sharepoint.com' OR server_name LIKE '%.okta.com')
    GROUP BY id_orig_h, server_name
  ) WHERE rn = 1 AND org_name IS NOT NULL AND org_name <> ''
),
mgmt AS (
  SELECT id_orig_h AS ip,
         ARRAY_JOIN(ARRAY_AGG(DISTINCT server_name), ',') AS mgmt_tooling
  FROM {database}.ssl
  WHERE dt = '{date_str}' AND ({mgmt_pred})
  GROUP BY id_orig_h
)""")

    select = [
        "  h.ip AS ip",
        "  h.connections AS connections",
        "  h.mb_out AS mb_out",
        "  h.mb_in AS mb_in",
        "  h.first_seen AS first_seen",
        "  h.last_seen AS last_seen",
        "  h.network_name AS network_name",
        "  h.room_name AS room_name",
    ]
    joins = []

    if have("known_devices"):
        select += ["  d.mac AS mac", "  d.vendor_mac AS vendor_mac"]
        joins.append("LEFT JOIN dev d ON d.ip = h.ip")
    else:
        select += ["  CAST(NULL AS VARCHAR) AS mac", "  CAST(NULL AS VARCHAR) AS vendor_mac"]

    if have("dhcp"):
        select.append("  dhh.hostname AS hostname")
        joins.append("LEFT JOIN dh dhh ON dhh.ip = h.ip")
    else:
        select.append("  CAST(NULL AS VARCHAR) AS hostname")

    if have("http"):
        select += [f"  {os_case} AS os_name", f"  {device_case} AS device_type",
                   "  ua.user_agent AS user_agent"]
        joins.append("LEFT JOIN ua ON ua.ip = h.ip")
    else:
        select += ["  'unknown' AS os_name", "  'unknown' AS device_type",
                   "  CAST(NULL AS VARCHAR) AS user_agent"]

    if have("ssl"):
        select += ["  o.org_name AS org_name", "  m.mgmt_tooling AS mgmt_tooling"]
        joins += ["LEFT JOIN org o ON o.ip = h.ip", "LEFT JOIN mgmt m ON m.ip = h.ip"]
    else:
        select += ["  CAST(NULL AS VARCHAR) AS org_name",
                   "  CAST(NULL AS VARCHAR) AS mgmt_tooling"]

    # A randomized (locally-administered) MAC has bit 1 of the first octet set, so
    # the second hex character is 2/6/A/E. Worth surfacing: it explains an unknown
    # vendor as privacy behaviour rather than a gap in our data.
    if have("known_devices"):
        select.append(
            "  CASE WHEN d.mac IS NULL THEN false\n"
            "       WHEN LOWER(SUBSTR(d.mac, 2, 1)) IN ('2','6','a','e') THEN true\n"
            "       ELSE false END AS randomized_mac"
        )
    else:
        select.append("  false AS randomized_mac")

    # Confidence reflects how many independent signals actually landed, so a
    # consumer can tell a well-attributed host from a bare traffic row.
    conf_terms = ["h.connections > 0"]
    if have("known_devices"):
        conf_terms.append("d.mac IS NOT NULL")
    if have("http"):
        conf_terms.append("ua.user_agent IS NOT NULL")
    if have("ssl"):
        conf_terms.append("o.org_name IS NOT NULL")
    if have("dhcp"):
        conf_terms.append("dhh.hostname IS NOT NULL")
    score = " + ".join(f"(CASE WHEN {t} THEN 1 ELSE 0 END)" for t in conf_terms)
    select.append(
        f"  CASE WHEN ({score}) >= 4 THEN 'high'\n"
        f"       WHEN ({score}) >= 2 THEN 'medium'\n"
        f"       ELSE 'low' END AS confidence"
    )
    select.append(f"  '{date_str}' AS dt")

    body = "".join(parts) + "\nSELECT\n" + ",\n".join(select) + "\nFROM hosts h\n" + "\n".join(joins)
    return body


def table_name(date_str: str) -> str:
    return f"asset_classification_{date_str.replace('-', '_')}"


def build_ctas(database: str, date_str: str, tables: dict[str, set],
               s3_location: str | None = None) -> str | None:
    """CREATE TABLE AS for one partition.

    A view will not do here: the inference is several joins and window functions
    over conn/http/ssl, so evaluating it per query would be slow and expensive.
    Materializing one partition per day keeps reads cheap.

    `s3_location` must be given for a repeatable rebuild. Without it Athena picks a
    random UUID path under the workgroup's output location, and `DROP TABLE` only
    removes the catalog entry: the data stays behind, so the next CTAS fails with
    TABLE_ALREADY_EXISTS pointing at an orphaned prefix nobody can find. Pinning a
    deterministic path means the caller can delete exactly what it is about to
    rewrite.
    """
    body = build_asset_classification_sql(database, date_str, tables)
    if not body:
        return None
    table = f"{database}.{table_name(date_str)}"
    external = f"WITH (external_location = '{s3_location}')\n" if s3_location else ""
    return f"CREATE TABLE {table}\n{external}AS\n{body}"
