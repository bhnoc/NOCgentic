# Obfuscation map — cleartext MCP logs

Pulled from conference Corelight via `cortex xql` (`corelight_http_raw` + DNS).
Shipped captures live in `fakecorp-cleartext-mcp.obfuscated.json` and
`nodes[*].logs` on hunt `fakecorp-cleartext-mcp`.

| Real (do not ship) | Fiction |
| --- | --- |
| Source host from Slack/XQL | `10.44.18.72` |
| Cloud destination IPs | `203.0.113.11–15` (RFC 5737 TEST-NET-3) |
| Cloud MCP ALB hostname | `mcp-alb.cloud-vendor.example` |
| Zeek connection UIDs | `Cfict0000001`… |
| `/google-secops/mcp` | `/vaultwatch/mcp` |
| `/recorded-future/mcp` | `/redline-intel/mcp` |
| `/falcon/mcp` | `/talon/mcp` |
| `/opencti/mcp` | `/graph-ti/mcp` |
| `/silentpush/mcp` | `/pulsefeed/mcp` |
| `/okta/mcp` | `/badgeauth/mcp` |
| `/obsidian/mcp` | `/notekeep/mcp` |
| Org / MDM / kerberos DNS | `FAKE CORP` / `fakecorp-mdm.example` / `*.fakecorp.example` |
| `Bearer mcpk_…` | `Bearer mcpk_[REDACTED]` |
| Agent CLI user-agents | `agent-cli` / `lab-mcp-client` |

Sensor fact retained: HTTP/80 cleartext JSON-RPC MCP to a cloud ALB, seven
path prefixes, auth headers present, tools/list + initialize traffic, corp-looking
DNS alongside the exposure, no class-peer match on the path set.
