# Obfuscation map — singleton C2 DDNS logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw` with
`_path` dns / conn / x509) for the Social Engineering Lab DDNS beacon thread.
Shipped captures live in `northlab-singleton-c2.obfuscated.json` and
`nodes[*].logs` on hunt `northlab-singleton-c2`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host `10.220.107.21` | `10.44.31.21` |
| DDNS `worksodsirius.ydns.eu` (malware family name omitted in ship) | `starbright.ddns.example` |
| Resolved A / conn dest `91.92.42.141` | `203.0.113.141` (RFC 5737 TEST-NET-3) |
| TCP follow-up port | `4061` (sensor fact retained) |
| DNS appliance addresses (`172.16.16.x`) | `10.44.0.53` |
| Class / VLAN label (full course title + room SSID) | Social Engineering Lab (omit real SSID) |
| Zeek vlan id | `4431` |
| Host netbios/mdns label | `desktop-lab31a.local` |
| x509 `O=Mythic C2` | `O=RailBeacon C2` |
| TLS training SNI on other sessions | omitted (not the DDNS/S0 story) |
| Suricata / ET Mythic rule names | `ET MALWARE RailBeacon Framework SSL/TLS Certificate Observed` |
| Zeek connection UIDs | `Cfict0003101`… |
| Alert id | `A-6610` |

Sensor facts retained (numbers from XQL on the live IOC, then fiction-scrubbed):

- `947` DNS A lookups for the DDNS name from the singleton host across
  **2026-08-02 → 2026-08-04** (~3 calendar days)
- `8067` TCP sessions to the resolved A on `:4061`, all sampled rows
  `conn_state=S0` (SYN, no SYN-ACK)
- Peer search for the same DDNS query from any other `id.orig_h` → **0**
- x509 row at `2026-08-04T17:08:14.807151Z` with self-signed C2-framework
  issuer shape (fiction: RailBeacon)

Close remains **True Positive**: multi-day singleton DDNS + dead-air C2
callbacks outside syllabus sanction. VLAN label alone is not BH Benign.
