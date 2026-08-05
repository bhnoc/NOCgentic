# Obfuscation map — batch 2 hunts

Slack threads leave the building as fiction. This map is for authors only;
shipped MUD copy must never contain the **Real** column.

| Hunt id | Real thread theme (do not ship) | Fiction in MUD |
| --- | --- | --- |
| `northlab-cleartext-siem-login` | Cleartext classroom SIEM UI logins to cloud VPS `:8001`; peer students on same dest | LogDeck / `logdeckd` / `LogDeck_Security_Essentials`; `10.44.22.11` + peers `.12/.13/.15/.16`; dest `203.0.113.40`; alert A-5521 — see `logs/OBFUSCATION-MAP-CLEARTEXT-SIEM-LOGIN.md` |
| `fakecorp-supplychain-dns` | Named supply-chain / RAT DNS on general Wi-Fi; managed booth laptop | WirePipe / `wirepipe.zone` / `litewire.cloud` / `sfrlake.example`; GLASSLINE MDM; `10.44.30.12`; alert A-6602 |
| `northlab-singleton-c2` | DDNS / C2 with false “class” auto-clear; singleton beacon | `starbright.ddns.example`; Social Engineering Lab VLAN; `10.44.31.21`; alert A-6610 |
| `stagecast-license-pii-http` | Vendor license HTTP POST with PII | StageCast / `activate.stagecast.example`; Riley Quill (invented); `10.44.32.40`; alert A-6621 |
| `noc-log4j-sensor-test` | Outbound Log4j probes from NOC wired to a known HTTP test host | `alwayshttp.example`; NOC wired `10.44.1.14`; alert A-6633 |
| `rivertide-azure-background` | Corp Azure/intranet DNS on mismatched training VLAN + enterprise proxy | RIVERTIDE / `*.azure.intra.rivertide.example` (incl. `rivdirect.postgres.azure.intra.rivertide.example` — never real `azure.com`); EdgeTunnel; Physical Access Lab; `10.44.33.36`; alert A-6644 |

Hard rules applied:

- No real org, vendor, person, Slack handle, or prod case id in narration
- No “almost real” domains (use `.example` / invented TLDs)
- Conference RFC1918 reinvented under `10.44.0.0/16`
- Registration / phone / LinkedIn side quests omitted
