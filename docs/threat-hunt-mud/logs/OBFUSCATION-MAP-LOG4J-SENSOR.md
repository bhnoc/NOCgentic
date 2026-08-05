# Obfuscation map — NOC Log4j sensor-test logs

Pulled from conference Corelight + NGFW via `cortex xql` for the outbound
Log4j → cleartext HTTP test-host thread. Shipped captures live in
`noc-log4j-sensor-test.obfuscated.json` and (after merge)
`nodes[*].logs` on hunt `noc-log4j-sensor-test`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host `10.220.250.14` (MacBook Air, NOC Wired) | `10.44.1.14` |
| Network label `NOC Wired` / room crumbs | `NOC wired` (omit real room) |
| Destination host `httpforever.com` | `alwayshttp.example` |
| Destination IP `172.67.132.115` (CDN edge) | `203.0.113.80` (RFC 5737 TEST-NET-3) |
| JNDI probe path `…/jimmy_said_hello` | `…/noc_stack_check` |
| People / Slack handles / case `10417` | Omit; alert `A-6633` |
| Zeek / Suricata UIDs | `Cfict0000201`… |
| Suricata `suri_id` / community_id | Fiction or omit |

Sensor fact retained: outbound Log4j-style JNDI User-Agent over cleartext HTTP
from a NOC-wired host to a known HTTP connectivity-test domain; Zeek notice
`CVE_2021_44228::LOG4J_ATTEMPT_HEADER`, three Suricata ET outbound Log4j
signatures, and one NGFW Critical threat (`Apache Log4j Remote Code Execution
Vulnerability`, action drop) all fire in the same minute (`23:20` UTC on
2026-08-03). No inbound exploitation or lateral movement in the window.
Close lesson: dual-engine coverage of a sanctioned sensor test → **BH Benign**.
