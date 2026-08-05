# Threat Hunt log captures

Obfuscated sensor excerpts opened from **Evidence chips** (and timeline
markers) in the MUD. There is no separate View logs control — ship `logs` on
every evidence-bearing room so chips stay clickable.

| File | Hunt | Source system |
| --- | --- | --- |
| `fakecorp-cleartext-mcp.obfuscated.json` | `fakecorp-cleartext-mcp` | Corelight `corelight_http_raw` (+ DNS rollup) via `cortex xql` |
| `northlab-cleartext-siem-login.obfuscated.json` | `northlab-cleartext-siem-login` | Corelight `corelight_http_raw` via `cortex xql` |
| `fakecorp-supplychain-dns.obfuscated.json` | `fakecorp-supplychain-dns` | Corelight DNS + Suricata ET via `cortex xql` |
| `northlab-singleton-c2.obfuscated.json` | `northlab-singleton-c2` | Corelight DNS / SSL / conn via `cortex xql` |
| `stagecast-license-pii-http.obfuscated.json` | `stagecast-license-pii-http` | Corelight `corelight_http_raw` via `cortex xql` |
| `noc-log4j-sensor-test.obfuscated.json` | `noc-log4j-sensor-test` | Corelight HTTP + Suricata + NGFW via `cortex xql` |
| `rivertide-azure-background.obfuscated.json` | `rivertide-azure-background` | Corelight DNS + HTTP / EdgeTunnel via `cortex xql` |

## Rules

1. Pull real rows with the conference cortex/XSIAM tooling.
2. Scrub before any file that may leave the building: bearer tokens → `mcpk_[REDACTED]`, reinvent RFC1918 under `10.44.0.0/16`, rename orgs/hosts/URIs to the hunt fiction map.
3. Never store real source IPs, people, or live tokens in these JSON files.
4. Ship the same captures onto `nodes[*].logs` in `packages/web-server/static/threat-hunt-config.js`.
5. Avoid four-octet strings that look like public IPs in UAs (`Chrome/150.0.0.0`); prefer `Chrome/150.0`. Loopback in JNDI samples → fiction host (`noc-loopback.example`) so OPSEC IP checks stay clean.
