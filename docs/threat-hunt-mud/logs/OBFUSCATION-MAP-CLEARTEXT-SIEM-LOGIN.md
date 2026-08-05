# Obfuscation map — cleartext SIEM login logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw`) for
the cleartext classroom SIEM login thread. Shipped captures live in
`northlab-cleartext-siem-login.obfuscated.json` and `nodes[*].logs` on hunt
`northlab-cleartext-siem-login`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host from Slack/XQL | `10.44.22.11` |
| Peer classroom hosts `.12` / `.13` / `.15` / `.16` | `10.44.22.12` / `.13` / `.15` / `.16` |
| Cloud VPS destination IP | `203.0.113.40` (RFC 5737 TEST-NET-3) |
| HTTP Host / VPS label | `logdeck-lab.cloud-vps.example` |
| Class / room labels | Malware Traffic Lab (omit real room SSID) |
| Product / server banner | LogDeck / `LogDeckd` |
| `/…/splunkd/…` path prefix | `/…/logdeckd/…` |
| `Splunk_Security_Essentials` | `LogDeck_Security_Essentials` |
| `splunk_app_for_splunk_o11y_cloud` | `logdeck_app_for_logdeck_o11y_cloud` |
| Username `admin` | `labadmin` |
| Username `ekoparty2019` | `course-feed` |
| Real instructor email | `instructor+lab@northlab.example` |
| Cleartext password values | `password=[REDACTED]` |
| Zeek connection UIDs | `Cfict0000101`… |

Sensor fact retained: HTTP/8001 cleartext SIEM UI logins from a classroom
VLAN host to a cloud VPS, three distinct usernames in an ~8m window
(18:41–18:49), credentials in POST bodies, Security Essentials / appsbrowser
crumbs on the destination, peer hosts on the same VLAN also reaching the
same `:8001` LogDeck UI.
