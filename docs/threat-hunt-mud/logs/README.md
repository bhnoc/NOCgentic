# Threat Hunt log captures

Obfuscated sensor excerpts shown in the MUD **Logs** rail.

| File | Hunt | Source system |
| --- | --- | --- |
| `fakecorp-cleartext-mcp.obfuscated.json` | `fakecorp-cleartext-mcp` | Corelight `corelight_http_raw` (+ DNS rollup) via `cortex xql` |

## Rules

1. Pull real rows with the conference cortex/XSIAM tooling.
2. Scrub before any file that may leave the building: bearer tokens → `mcpk_[REDACTED]`, reinvent RFC1918 under `10.44.0.0/16`, rename orgs/hosts/URIs to the hunt fiction map.
3. Never store real source IPs, people, or live tokens in these JSON files.
4. Ship the same captures onto `nodes[*].logs` in `packages/web-server/static/threat-hunt-config.js`.
