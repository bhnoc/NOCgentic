# Obfuscation map — RIVERTIDE Azure background logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw`,
`_path = dns` and `_path = http`) for the corp-cloud-on-training-VLAN thread.
Shipped captures live in `rivertide-azure-background.obfuscated.json` and
`nodes[*].logs` on hunt `rivertide-azure-background`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host `10.220.125.36` | `10.44.33.36` |
| Venue DNS resolvers `172.16.16.x` | `10.44.0.53` |
| Proxy / tunnel egress IPs (public) | `203.0.113.66` (RFC 5737 TEST-NET-3) |
| Org / SharePoint tenant | RIVERTIDE / `share.rivertide.example` |
| Hostname `USPF5VS4TX` | `RT-WIN-US-36` |
| MAC `9c:65:eb:bd:f9:ac` | omit (not needed for lesson) |
| Class label (Physical Penetration / RFID / …) | Physical Access Lab |
| Room / SSID crumbs | omit |
| `flexeraitamscus.azure.intra.pepsico.com` (+ regional flexera variants) | `flexops.azure.intra.rivertide.example` |
| `pep-hpacbadgeprintcto-prod-scus-01-lb.azure.intra.pepsico.com` | `badgeprint.azure.intra.rivertide.example` |
| `pepdirectprod01.postgres.database.azure.com` | `rivdirect.postgres.azure.intra.rivertide.example` (**never** real `azure.com`) |
| Search-suffix NXDOMAIN noise (`.pep.pvt`, `.walkers.co.uk`, …) | omit or collapse into base fiction FQDN |
| Zscaler / ZTunnel | EdgeTunnel |
| UA `… ZTunnel/1.0` | `Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0` |
| `www.zscaler.com` | `www.edgetunnel.example` |
| `gateway.zscalertwo.net` / realm `zscalertwo.net` | `gateway.edgetunnel-two.example` / realm `edgetunnel-two.example` |
| `sitereview.zscaler.com` / `pac.zscalertwo.net` | `sitereview.edgetunnel.example` / `pac.edgetunnel-two.example` |
| `/zcc_conn_test` | `/et_conn_test` |
| Microsoft / Cisco keepalive CONNECT targets from the wire | `keepalive.cloud-portal.example` (generic SaaS check-in) |
| Zeek connection UIDs | `Cfict0006601`… |
| Alert / case ids from live queue | `A-6644` |

Sensor facts retained (fiction-scrubbed):

- Classroom IP on Physical Access Lab VLAN heavily queries RIVERTIDE Azure /
  intranet-looking names over **~37m** (`17:03:14`–`17:40:28` UTC on
  2026-08-01), matching the drill’s “~40m” briefing rounding.
- Aggregated DNS hits (search-suffix variants rolled into base names):
  flexops-family **19**, badgeprint **15**, rivdirect postgres **13**;
  EdgeTunnel DNS markers `gateway` **34**, `sitereview` **28**.
- HTTP shows repeated `CONNECT` with EdgeTunnel UA, Digest
  `Proxy-Authorization` realm `edgetunnel-two.example`, and background
  connects to EdgeTunnel portals plus generic cloud keepalives — managed
  endpoint chatter, not a tight DB listener scan.
- Entity profile: Windows hostname `RT-WIN-US-36`, org RIVERTIDE (high
  confidence), SharePoint crumb `share.rivertide.example`. No cleartext
  interactive username on the wire.
- Class syllabus (badges / RFID / door controllers) does not assign RIVERTIDE
  Azure labs — mismatch noted; still BH Benign with proxy + tenant DNS.

XQL gaps / caveats (author notes, not player copy):

- Unfiltered top-DNS for the IP over 168h was polluted with unrelated Apple /
  iPhone names (likely DHCP reuse or multi-device attribution). Hunt pack uses
  Azure / intranet / EdgeTunnel-filtered DNS only.
- `Proxy_Authorization` is not a first-class XQL field — realm and Digest
  material come from `client_headers` inside `_raw_log`.
- Corelight `host` on these HTTP rows is the sensor feed name; CONNECT
  destinations are taken from `uri` / `Host` header.
- Many corp intranet A queries return `NXDOMAIN` on venue resolvers (search
  suffixes + no corp DNS). That is expected background noise, not “name does
  not exist at the tenant.”
- ZTunnel HTTP sample capped at 60–80 rows; UA rollup shows **232** ZTunnel
  hits in the wider window — pack shows representative timed samples.
- Slack mentioned `mus.cisco.com`; that exact CONNECT dest did not appear in
  the capped pull (Microsoft DSP / EdgeTunnel portals did).
