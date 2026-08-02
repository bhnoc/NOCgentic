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

COVERAGE REALITY, measured 2026-08-01: only 270 of 18,900 hosts emit an HTTP
User-Agent, because almost everything is TLS-only now. A UA alone therefore
classified ~1.5% of hosts. Three non-UA sources now fill the gap:

    software (14,789 rows / 2,929 hosts)  ~10x the UA population, and it carries
                                          real OS/app name strings, not a hash
    dhcp host_name (2,557 IPs)            self-reported names like "Jamess-iPhone"
                                          or "DESKTOP-A1B2C3"
    dhcp option-55 PRL (3,151 in-scope    the parameter-request-list a client asks
    IPs reachable via the mac bridge)     for. OS FAMILY only, but it does not
                                          depend on the host emitting anything

Measured by executing this CTAS against dt=2026-08-01, in-scope only
(ip LIKE '10.220.%' OR ip LIKE '192.168.1%'), 4,951 hosts:

    before dhcp_prl   2,189 of 4,951 (44.2%)
    after  dhcp_prl   2,916 of 4,951 (58.9%)

    by source: user_agent 1,176 | software 704 | dhcp_hostname 309 | dhcp_prl 727

The +727 is what PRL adds NET of the three stronger tiers, i.e. after they have
taken every host they can claim. 646 of those 727 are hosts with a RANDOMIZED mac,
where the OUI vendor hint says nothing at all — that is the population no other
signal in this module reaches. By family: Apple 658, Windows 37, Linux 34.

That is BELOW the 1,255-1,389 a QA sweep projected, and the gap is not a join bug —
it was measured. 3,150 in-scope hosts do bridge to a PRL, but 2,172 of them were
already resolved by a stronger tier (PRL correlates with the hosts we could already
see), and 253 carry a list we refused to name: see the rejected fourth signature in
_PRL_OS_RULES. The sweep counted hosts with a fingerprint, not hosts a fingerprint
would newly classify.

Mind the denominator. The `conn` spine unions both directions, so it emits 112,900
rows, most of them external servers we never classify. Quote coverage against
in-scope hosts or the number looks far worse than it is.

The rest are still legitimately 'unknown' with traffic stats and (where
DHCP/known_devices saw them) mac/hostname/vendor populated. That remainder is a
limit of the evidence, not a bug in the join: do not "fix" it by loosening the rules, which
would just produce confident nonsense.

Because these signals are NOT equally trustworthy, every inferred value carries
its provenance in `os_source` / `device_source` ('user_agent' | 'software' |
'dhcp_hostname' | 'dhcp_prl' | 'unknown'). A UA always wins; the others only fill
a NULL, in that order. A consumer that needs hard evidence filters on the source
column, and one that needs a version excludes 'dhcp_prl' — see _PRL_OS_RULES.

ja3 is deliberately NOT used for OS inference. 7,358 IPs carry one, but a
fingerprint is only an OS signal against a curated mapping we do not have, and
the top fingerprint alone spans 1,401 IPs. Guessing an OS from it would be
exactly the confident nonsense the rest of this module avoids. TTL/window/MSS
p0f-style fingerprinting is not available at all: no ttl, window, mss, df or ja4
column exists anywhere in this catalog, which is why option-55 is the tier that
got built instead.
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

# Non-UA evidence is matched against a NORMALIZED string, not the raw value: every
# run of non-alphanumerics collapses to a single delimiter and the whole value is
# padded with one, so every needle can carry its own boundary. That is what stops
# the 'cros' inside "Microsoft-CryptoAPI" class of bug at the source instead of
# case by case: "Microsoft-CryptoAPI" becomes ' microsoft cryptoapi ', so a needle
# spelled ' cros ' cannot fire on it.
_SW_NORM = "' ' || REGEXP_REPLACE(LOWER({col}), '[^a-z0-9]+', ' ') || ' '"
_HOST_NORM = "'-' || REGEXP_REPLACE(LOWER({col}), '[^a-z0-9]+', '-') || '-'"

# `software.name` to OS. 310 distinct names on this network, and unlike a ja3 these
# are real strings, which is why software is preferred over any fingerprint.
#
# Needles are written against the space-delimited normalized name. A leading space
# with no trailing one is a deliberate prefix match ('  iphone' also catching
# "iPhone OS"); both delimiters mean the token must stand alone, which is required
# for anything short enough to hide inside an unrelated product: ' ios ' would
# otherwise match "biosensor" and ' macos' would match "macromedia".
_SOFTWARE_OS_RULES: tuple[tuple[str, str], ...] = (
    (" iphone", "iOS"),
    (" ipad", "iPadOS"),
    (" ipod", "iOS"),
    (" ios ", "iOS"),
    (" dalvik", "Android"),
    (" android", "Android"),
    (" cros ", "ChromeOS"),
    (" chromeos ", "ChromeOS"),
    (" cfnetwork", "Apple"),
    (" darwin", "Apple"),
    (" macintosh ", "macOS"),
    (" mac os x ", "macOS"),
    (" macos", "macOS"),
    (" microsoft cryptoapi ", "Windows"),
    (" windows", "Windows"),
    (" winhttp ", "Windows"),
    (" msie ", "Windows"),
    (" microsoft iis ", "Windows"),
    (" ubuntu ", "Linux"),
    (" debian ", "Linux"),
    (" centos ", "Linux"),
    (" fedora ", "Linux"),
    (" raspbian ", "Linux"),
    (" linux ", "Linux"),
)

# Device class from the same names, kept needle-for-needle in step with the OS
# table for the reason recorded above _DEVICE_RULES. ' ios ' resolves to phone
# because an iPad announcing a bare "iOS" is the rarer case; an iPad that says so
# is caught by the ' ipad' rule above it.
_SOFTWARE_DEVICE_RULES: tuple[tuple[str, str], ...] = (
    (" iphone", "phone"),
    (" ipad", "tablet"),
    (" ipod", "phone"),
    (" ios ", "phone"),
    (" dalvik", "phone"),
    (" android", "phone"),
    (" cros ", "computer"),
    (" chromeos ", "computer"),
    (" cfnetwork", "computer"),
    (" darwin", "computer"),
    (" macintosh ", "computer"),
    (" mac os x ", "computer"),
    (" macos", "computer"),
    (" microsoft cryptoapi ", "computer"),
    (" windows", "computer"),
    (" winhttp ", "computer"),
    (" msie ", "computer"),
    (" microsoft iis ", "computer"),
    (" ubuntu ", "computer"),
    (" debian ", "computer"),
    (" centos ", "computer"),
    (" fedora ", "computer"),
    (" raspbian ", "computer"),
    (" linux ", "computer"),
    (" curl ", "tool"),
    (" libcurl ", "tool"),
    (" wget ", "tool"),
    (" python requests ", "tool"),
    (" python urllib ", "tool"),
    (" go http client ", "tool"),
)

# DHCP-reported hostname to OS. Weakest of the three sources because the string is
# self-reported and freely editable, but "DESKTOP-A1B2C3" and "Jamess-iPhone" are
# vendor defaults and cover 2,557 IPs.
#
# Needles run against the hyphen-delimited normalized name. Hostnames are mostly
# PEOPLE'S NAMES, so any needle that is also a name prefix must be closed at both
# ends: '-kali' fires on "Kalisha-Laptop", '-kali-' does not. Same reasoning for
# '-win-' ("Darwin-PC", "Twin-Laptop") and '-imac-'.
#
# A leading '^' anchors to the start of the name. The generic form-factor words are
# only OS evidence as a vendor default at the front ("DESKTOP-A1B2C3" is Windows'
# own naming); "Kalisha-Laptop" is a person naming a machine that is as likely a
# MacBook, so it yields device_type but deliberately no OS.
_DHCP_OS_RULES: tuple[tuple[str, str], ...] = (
    ("-iphone", "iOS"),
    ("-ipad", "iPadOS"),
    ("-ipod", "iOS"),
    ("-macbook", "macOS"),
    ("-imac-", "macOS"),
    ("-mac-mini", "macOS"),
    ("-mac-pro", "macOS"),
    ("-pixelbook", "ChromeOS"),
    ("-chromebook", "ChromeOS"),
    ("-android", "Android"),
    ("-galaxy", "Android"),
    ("-pixel", "Android"),
    ("^-desktop-", "Windows"),
    ("^-laptop-", "Windows"),
    ("^-win-", "Windows"),
    ("-ubuntu", "Linux"),
    ("-debian", "Linux"),
    ("-fedora", "Linux"),
    ("-raspberrypi", "Linux"),
    ("-kali-", "Linux"),
    ("-apple-tv", "tvOS"),
    ("-appletv", "tvOS"),
)

# Device rules may go beyond the OS table (a ThinkPad is certainly a computer but
# says nothing about its OS, and claiming one would be the invented confidence
# this module exists to avoid). The reverse is not allowed: see the sync test.
_DHCP_DEVICE_RULES: tuple[tuple[str, str], ...] = (
    ("-iphone", "phone"),
    ("-ipad", "tablet"),
    ("-ipod", "phone"),
    ("-macbook", "computer"),
    ("-imac-", "computer"),
    ("-mac-mini", "computer"),
    ("-mac-pro", "computer"),
    ("-pixelbook", "computer"),
    ("-chromebook", "computer"),
    ("-android", "phone"),
    ("-galaxy", "phone"),
    ("-pixel", "phone"),
    ("^-desktop-", "computer"),
    ("^-laptop-", "computer"),
    ("^-win-", "computer"),
    ("-desktop-", "computer"),
    ("-laptop-", "computer"),
    ("-ubuntu", "computer"),
    ("-debian", "computer"),
    ("-fedora", "computer"),
    ("-raspberrypi", "computer"),
    ("-kali-", "computer"),
    ("-apple-tv", "iot"),
    ("-appletv", "iot"),
    ("-thinkpad", "computer"),
    ("-chromecast", "iot"),
    ("-roku", "iot"),
    ("-sonos", "iot"),
    ("-printer", "iot"),
)

# DHCP option-55 (parameter request list) to OS FAMILY.
#
# `prl` in dhcp_fp_lite is comma-separated decimals with NO spaces, verified against
# live values, e.g. "1,121,3,6,15,108,114,119,162,252". Note it is NOT sorted: the
# order is the client's own, which is precisely what makes it a fingerprint.
#
# THE SUBSTRING TRAP, PRL EDITION. The 'cros'-in-"Microsoft-CryptoAPI" bug has a
# nastier form here because every value is digits and commas: '1,3,6' is a substring
# of '11,3,6' and of '1,3,60', and '1,3,6,15,31,33,43,44,46,47,119,121,249,252' is
# itself a prefix of the '...,252,114' Windows variant. So the value is padded to
# ',prl,' and every needle carries its own commas, exactly as _SW_NORM pads with
# spaces. Every needle here is a PREFIX match anchored with '^': the leading options
# of the list are the stable part of the signature, and the tail varies by version
# and by which options the client stack happens to append.
#
# EMPIRICALLY DERIVED, not from memory. Each signature was cross-tabulated against
# hosts whose OS the UA/software/dhcp_hostname tiers already resolved, restricted to
# IPs held by exactly one mac so the bridge cannot contaminate the label. Measured
# purity on 2026-08-01:
#
#   ^,1,121,3,6,15,                          Apple    852/886 = 96.2%
#   ^,1,3,6,15,31,33,43,44,46,47,            Windows  753/760 = 99.1%
#   ^,1,2,6,12,15,26,28,121,                 Linux    228/247 = 92.3%
#
# A FOURTH signature was REJECTED. ',1,3,6,15,26,28,51,58,59,' looks like the
# obvious Android list and 71 Android hosts carry it, but so do 206 Linux hosts
# (Chrome on X11) — 25% purity for Android, 74% for Linux, and no clean split. It
# is a shared dhclient/AOSP-derived list, not an Android signature, so it ships as
# nothing. A signature we cannot corroborate must not ship, which means this module
# currently names NO Android from PRL at all.
#
# The labels are FAMILIES ('Apple', not 'macOS'; 'Windows'; 'Linux'). Option-55 does
# not carry a version and cannot distinguish an iPhone from a MacBook, so this tier
# says 'Apple' and lets the stronger tiers say 'iOS'. Claiming more would be the
# invented precision the rest of the module refuses.
_PRL_OS_RULES: tuple[tuple[str, str], ...] = (
    ("^,1,121,3,6,15,", "Apple"),
    ("^,1,3,6,15,31,33,43,44,46,47,", "Windows"),
    ("^,1,2,6,12,15,26,28,121,", "Linux"),
)

# Deliberately NOT kept needle-for-needle with _PRL_OS_RULES, and the sync test
# exempts this table. An OS family is not a form factor: 'Apple' spans an iPhone, an
# iPad and a Mac Pro, and 'Linux' spans a laptop and a Raspberry Pi. Only the
# Windows list narrows to a form factor in practice, and even that is a desktop OS
# claim rather than a device observation, so this table is EMPTY and PRL contributes
# nothing to device_type. A phone-vs-computer guess from option-55 would be
# precisely the confident nonsense the module exists to avoid.
_PRL_DEVICE_RULES: tuple[tuple[str, str], ...] = ()

# Pad to ',prl,' so a needle can carry its own commas at both ends. Digits and
# commas only -- anything else in the value is junk and is stripped, which also
# collapses the spaces a future sensor build might start emitting.
_PRL_NORM = "',' || REGEXP_REPLACE({col}, '[^0-9,]+', '') || ','"

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


def _like(expr: str, needle: str) -> str:
    """One LIKE test, honouring a leading '^' as an anchor.

    Anchoring matters where a needle is only evidence as a vendor-default PREFIX:
    "DESKTOP-A1B2C3" is a Windows default and "Kalisha-Desktop" is a human naming
    an iMac, and only the position tells them apart.
    """
    if needle.startswith("^"):
        return f"{expr} LIKE '{needle[1:]}%'"
    return f"{expr} LIKE '%{needle}%'"


def _case_from_norm(expr: str, rules: tuple[tuple[str, str], ...],
                    default: str = "NULL") -> str:
    """Same, over an already-normalized (lowercased, delimited) expression.

    Defaults to NULL rather than 'unknown' so the caller can COALESCE sources in
    precedence order: 'unknown' from a weak source would shadow a later match.
    """
    whens = "\n".join(
        f"           WHEN {_like(expr, needle)} THEN '{label}'"
        for needle, label in rules
    )
    return f"CASE\n{whens}\n           ELSE {default}\n         END"


def _rank_from_norm(expr: str, rules: tuple[tuple[str, str], ...]) -> str:
    """Which rule matched, as its position in the table.

    A host reports several software names ("Windows-Update-Agent", "Chrome"), so the
    aggregate has to choose. Rule order already encodes specificity, so the earliest
    matching rule wins and no separate scoring table can drift out of step with it.
    """
    whens = "\n".join(
        f"           WHEN {_like(expr, needle)} THEN {i}"
        for i, (needle, _) in enumerate(rules)
    )
    return f"CASE\n{whens}\n           ELSE NULL\n         END"


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
    # Column-level too. A `software` without `name` or an `ssl` without ja3 would
    # build a CTAS that fails, and one failed statement loses the whole hourly
    # rebuild, so gate on the columns actually referenced.
    havecol = lambda t, c: c in tables.get(t, ())  # noqa: E731

    use_sw = havecol("software", "host") and havecol("software", "name")
    use_dhcp_name = havecol("dhcp", "assigned_addr") and havecol("dhcp", "host_name")
    # dhcp_fp_lite keys on `mac` and carries no IP at all, so this tier needs the
    # `dhcp` lease table as a bridge and is gated on BOTH tables' columns. Missing
    # any one of them degrades to no PRL tier rather than a CTAS that fails.
    use_prl = (havecol("dhcp_fp_lite", "mac") and havecol("dhcp_fp_lite", "prl")
               and havecol("dhcp", "mac") and havecol("dhcp", "assigned_addr"))

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
    if use_dhcp_name:
        # One row per ip, not per (mac, ip): a lease reassigned during the day gave
        # an IP two rows here, which fanned out the join and double-counted nothing
        # visible but silently duplicated the host in the output.
        #
        # The dominant hostname rather than an arbitrary one, for the same reason the
        # dominant UA is taken: a DHCP-renewing phone and a stale lease can both
        # appear, and the frequent name is the current occupant.
        dhcp_os_case = _case_from_norm("d0.hostname_norm", _DHCP_OS_RULES)
        dhcp_device_case = _case_from_norm("d0.hostname_norm", _DHCP_DEVICE_RULES)
        parts.append(f""",
dh AS (
  SELECT d0.ip AS ip,
         d0.hostname AS hostname,
         {dhcp_os_case} AS dhcp_os,
         {dhcp_device_case} AS dhcp_device
  FROM (
    SELECT ip, hostname, {_HOST_NORM.format(col='hostname')} AS hostname_norm
    FROM (
      SELECT assigned_addr AS ip, host_name AS hostname,
             ROW_NUMBER() OVER (PARTITION BY assigned_addr ORDER BY COUNT(*) DESC) AS rn
      FROM {database}.dhcp
      WHERE dt = '{date_str}' AND assigned_addr IS NOT NULL
        AND host_name IS NOT NULL AND host_name NOT IN ('', '-')
      GROUP BY assigned_addr, host_name
    ) WHERE rn = 1
  ) d0
)""")

    # DHCP option-55. The only tier here that does not need the host to emit
    # anything identifying: every DHCP client sends a parameter request list.
    #
    # THE BRIDGE. dhcp_fp_lite has columns (ts_datetime, mac, prl) and no IP at all,
    # so it must be joined to an IP by mac. Two candidates were measured on
    # 2026-08-01:
    #
    #   dhcp.assigned_addr     3,216 of 3,223 fingerprinted macs matched -> 3,151 in-scope IPs
    #   known_devices.host_ip  3,140 of 3,223 matched                    -> 3,095 in-scope IPs
    #
    # `dhcp` wins and is used alone. It reaches strictly more hosts, unioning the two
    # adds ZERO further in-scope IPs (3,151 either way), and it is the same table the
    # lease comes from, so the mac->ip mapping is the DHCP server's own record of who
    # held that address rather than a second inference layered on a first. A second
    # bridge would add a fan-out surface for no coverage.
    #
    # FAN-OUT is real on BOTH sides, which is why this is a two-stage collapse: one
    # mac held up to 7 addresses in the day, one address was held by up to 3 macs, and
    # 151 IPs bridge to more than one distinct PRL. The fingerprint is reduced to one
    # row per mac FIRST (dominant prl), then the bridged result to one row per ip
    # (dominant prl again, weighted by how many leases carried it). Joining either
    # side raw would duplicate hosts in the output -- the exact bug the `dh` CTE above
    # already had once.
    #
    # The alias is `fpr`, not `prl`: a CTE named for the column it selects makes
    # `prl.prl` read like a typo in a file where an all-null column is the failure
    # mode nobody notices.
    if use_prl:
        prl_os_case = _case_from_norm("p0.prl_norm", _PRL_OS_RULES)
        parts.append(f""",
fpr AS (
  SELECT p0.ip AS ip,
         {prl_os_case} AS prl_os
  FROM (
    SELECT ip, prl_norm FROM (
      SELECT l.ip AS ip,
             {_PRL_NORM.format(col='f.prl')} AS prl_norm,
             ROW_NUMBER() OVER (PARTITION BY l.ip
                                ORDER BY SUM(l.leases) DESC, f.prl) AS rn
      FROM (
        SELECT mac, prl FROM (
          SELECT mac, prl,
                 ROW_NUMBER() OVER (PARTITION BY mac ORDER BY COUNT(*) DESC, prl) AS rn
          FROM {database}.dhcp_fp_lite
          WHERE dt = '{date_str}' AND mac IS NOT NULL AND mac NOT IN ('', '-')
            AND prl IS NOT NULL AND prl NOT IN ('', '-')
          GROUP BY mac, prl
        ) WHERE rn = 1
      ) f
      JOIN (
        SELECT mac, assigned_addr AS ip, COUNT(*) AS leases
        FROM {database}.dhcp
        WHERE dt = '{date_str}' AND mac IS NOT NULL AND mac NOT IN ('', '-')
          AND assigned_addr IS NOT NULL AND assigned_addr NOT IN ('', '-')
        GROUP BY mac, assigned_addr
      ) l ON l.mac = f.mac
      GROUP BY l.ip, f.prl
    ) WHERE rn = 1
  ) p0
)""")

    # Platform. Take the single most-used UA per host: a browser plus a dozen app
    # agents is normal, and the dominant one is the best OS signal.
    #
    # The rules are applied HERE rather than in the outer SELECT so each CASE is
    # written once. Both the value and its provenance reference the result, and two
    # copies of a 20-branch CASE that must stay identical is a diff waiting to rot.
    if have("http"):
        parts.append(f""",
ua AS (
  SELECT ip, user_agent,
         NULLIF({os_case}, 'unknown') AS ua_os,
         NULLIF({device_case}, 'unknown') AS ua_device
  FROM (
    SELECT id_orig_h AS ip, user_agent,
           ROW_NUMBER() OVER (PARTITION BY id_orig_h ORDER BY COUNT(*) DESC) AS rn
    FROM {database}.http
    WHERE dt = '{date_str}' AND user_agent IS NOT NULL AND user_agent <> ''
    GROUP BY id_orig_h, user_agent
  ) ua WHERE rn = 1
)""")

    # ~10x the UA population (2,929 hosts vs 270), which is the whole point of this
    # source. Two traps live here:
    #
    # `software` keys on `host`, a VARCHAR ip -- NOT id_orig_h. Joining on id_orig_h
    # parses fine and yields an all-null column. `host` is a Trino reserved word, so
    # it needs DOUBLE quotes; backticks are DDL-only and fail here.
    #
    # ~5 rows per host, so it MUST collapse to one row before the join. MIN_BY over
    # the rule index picks the most specific match rather than an arbitrary row.
    if use_sw:
        sw_os_rank = _rank_from_norm("s0.name_norm", _SOFTWARE_OS_RULES)
        sw_dev_rank = _rank_from_norm("s0.name_norm", _SOFTWARE_DEVICE_RULES)
        sw_os_label = _case_from_norm("s0.name_norm", _SOFTWARE_OS_RULES)
        sw_dev_label = _case_from_norm("s0.name_norm", _SOFTWARE_DEVICE_RULES)
        parts.append(f""",
sw AS (
  SELECT ip,
         MIN_BY(sw_os, os_rank) AS sw_os,
         MIN_BY(sw_device, device_rank) AS sw_device
  FROM (
    SELECT s0.ip AS ip,
           {sw_os_label} AS sw_os,
           {sw_os_rank} AS os_rank,
           {sw_dev_label} AS sw_device,
           {sw_dev_rank} AS device_rank
    FROM (
      SELECT "host" AS ip, {_SW_NORM.format(col='name')} AS name_norm
      FROM {database}.software
      WHERE dt = '{date_str}' AND "host" IS NOT NULL
        AND name IS NOT NULL AND name NOT IN ('', '-')
      GROUP BY "host", name
    ) s0
  )
  WHERE os_rank IS NOT NULL OR device_rank IS NOT NULL
  GROUP BY ip
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

    if use_dhcp_name:
        select.append("  dhh.hostname AS hostname")
        joins.append("LEFT JOIN dh dhh ON dhh.ip = h.ip")
    else:
        select.append("  CAST(NULL AS VARCHAR) AS hostname")

    # PRECEDENCE, strongest first: a UA is a direct claim by the client stack, a
    # software name is observed on the wire, a DHCP hostname is a label a human
    # typed. NULLIF drops the UA rules' 'unknown' sentinel so a weaker source can
    # fill the hole -- without it 'unknown' is a value and COALESCE stops there.
    #
    # The source column is derived from the SAME expressions in the SAME order, so
    # it cannot claim a provenance that did not produce the value.
    os_terms: list[tuple[str, str]] = []
    device_terms: list[tuple[str, str]] = []
    if have("http"):
        joins.append("LEFT JOIN ua ON ua.ip = h.ip")
        os_terms.append(("ua.ua_os", "user_agent"))
        device_terms.append(("ua.ua_device", "user_agent"))
    if use_sw:
        joins.append("LEFT JOIN sw ON sw.ip = h.ip")
        os_terms.append(("sw.sw_os", "software"))
        device_terms.append(("sw.sw_device", "software"))
    if use_dhcp_name:
        os_terms.append(("dhh.dhcp_os", "dhcp_hostname"))
        device_terms.append(("dhh.dhcp_device", "dhcp_hostname"))
    # LAST, unconditionally. option-55 gives a FAMILY ('Apple'), so it must never
    # displace a tier that named an actual OS ('iOS'): appended here it can only
    # fill a NULL the three stronger tiers left behind. It contributes no
    # device_type at all -- see _PRL_DEVICE_RULES.
    if use_prl:
        joins.append("LEFT JOIN fpr ON fpr.ip = h.ip")
        os_terms.append(("fpr.prl_os", "dhcp_prl"))

    for column, source_column, terms in (
        ("os_name", "os_source", os_terms),
        ("device_type", "device_source", device_terms),
    ):
        if terms:
            value = "COALESCE(" + ", ".join(e for e, _ in terms) + ", 'unknown')"
            provenance = "CASE\n" + "\n".join(
                f"       WHEN {e} IS NOT NULL THEN '{label}'" for e, label in terms
            ) + f"\n       ELSE 'unknown'\n     END"
            select += [f"  {value} AS {column}", f"  {provenance} AS {source_column}"]
        else:
            select += [f"  'unknown' AS {column}", f"  'unknown' AS {source_column}"]

    select.append("  ua.user_agent AS user_agent" if have("http")
                  else "  CAST(NULL AS VARCHAR) AS user_agent")

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
    #
    # The two new sources are NOT worth a full point each. software is observed
    # rather than self-reported so it scores like the other enrichments; a DHCP
    # hostname is a string a human typed and is already counted once for existing
    # at all, so a platform guess derived from it adds nothing further. Otherwise
    # every DHCP host would climb a tier on one weak signal counted twice.
    #
    # PRL is excluded for the same reason and more strongly: it is the weakest tier,
    # it names a family rather than an OS, and it is derived from the very same DHCP
    # conversation the hostname came from. Counting it would lift ~3,100 hosts a
    # confidence tier on one option-55 list.
    conf_terms = ["h.connections > 0"]
    if have("known_devices"):
        conf_terms.append("d.mac IS NOT NULL")
    if have("http"):
        conf_terms.append("ua.user_agent IS NOT NULL")
    if have("ssl"):
        conf_terms.append("o.org_name IS NOT NULL")
    if use_dhcp_name:
        conf_terms.append("dhh.hostname IS NOT NULL")
    if use_sw:
        conf_terms.append("sw.sw_os IS NOT NULL")
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
