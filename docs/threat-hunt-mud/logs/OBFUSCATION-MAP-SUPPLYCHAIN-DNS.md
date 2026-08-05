# Obfuscation map — supply-chain DNS logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw` with
`_path=dns` / `suricata_corelight` / `ssl`) for the WirePipe (TeamPCP) DNS
thread. Shipped captures live in `fakecorp-supplychain-dns.obfuscated.json`
and `nodes[*].logs` on hunt `fakecorp-supplychain-dns`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host `192.168.129.12` | `10.44.30.12` |
| Resolver `172.16.16.16` (OpenDNS/Umbrella) | `10.44.16.16` (conference DNS VA) |
| `checkmarx.zone` (NOERROR) | `wirepipe.zone` |
| `models.litellm.cloud` (NXDOMAIN) | `models.litewire.cloud` |
| `sfrclak.com` (NXDOMAIN) | `sfrlake.example` |
| TeamPCP / litellm supply-chain campaign label | WirePipe supply-chain |
| ET sig `…TeamPCP litellm… (checkmarx .zone)` | `ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (wirepipe .zone)` |
| ET sig `…TeamPCP litellm… (litellm .cloud)` | `ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (litewire .cloud)` |
| ET sig `plain-crypto-js RAT… (sfrclak .com)` | `ET MALWARE plain-cipher-js RAT C2 Domain in DNS Lookup (sfrlake .example)` |
| Org Mend / `*.mend.io` SaaS | GLASSLINE / `*.glassline.example` |
| `saas.mend.io` / `login-saas.mend.io` / `mend-resources.mend.io` | `saas.glassline.example` / `login-saas.glassline.example` / `resources.glassline.example` |
| Microsoft Intune / `*.manage.microsoft.com` / `checkin.dm.microsoft.com` | GLASSLINE MDM / `agents.manage.glassline-mdm.example` / `checkin.dm.glassline-mdm.example` |
| `login.microsoftonline.com` | `login.glassline-id.example` |
| Grammarly telemetry hosts | Writely / `*.writely.example` (context only; omit if unused) |
| Live cloud destination IPs (AWS/Azure/CF) | `203.0.113.50–59` / `198.51.100.40–49` (RFC 5737) |
| Zeek / Suricata UIDs | `Cfict0000201`… |
| People / booth registration / Case ID-10317 | omitted |
| Alert id | `A-6602` |

Sensor fact retained: two DNS bursts ~2h apart (15:45 and 17:40) from a
general Wi-Fi Windows host; `wirepipe.zone` resolves NOERROR while sibling
campaign names NXDOMAIN; matching ET MALWARE Suricata DNS signatures fire on
each lookup; SaaS/MDM TLS crumbs present GLASSLINE identity; no peer hosts on
training VLANs resolve the same IOC set.
