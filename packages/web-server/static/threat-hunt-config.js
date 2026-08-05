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
window.THREAT_HUNTS = [{
  id: 'fakecorp-cleartext-mcp',
  meta: {
    title: 'Cleartext MCP, FAKE CORP asset',
    briefing: 'Alert A-4418 is open: cleartext HTTP from 10.44.18.72 to cloud vendor ranges, 7 distinct /…/mcp paths in 18 minutes, including a full security-tooling stack. Tool listings advertise write access on several servers. Pivot through the evidence, separate corp-normal from incident-worthy, and post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  // ELI5 hover tips — keys match narration case-insensitively; longer phrases win.
  glossary: {
    'MCP': 'A simple way for an AI or app to plug into other tools (like a universal adapter). Here those tools are security products.',
    'cleartext': 'Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.',
    'HTTP': 'The basic language of the web. Alone (without TLS) it is not private.',
    'TLS': 'The lock on a web connection (the S in HTTPS). "No TLS" means the traffic is not locked.',
    'DNS': 'The phone book of the internet: turns names like fakecorp.example into addresses computers dial.',
    'MDM': 'Company device management — software that enrolls and controls a laptop or phone for IT.',
    'SSID': 'The Wi-Fi network name you pick in the list (for example the training lab network).',
    'VLAN': 'A sliced-off piece of the network, like a separate hallway in the same building.',
    'EDR': 'Endpoint security software that watches a computer for suspicious behavior.',
    'JSON-RPC': 'A simple ask-and-answer message format apps use to call functions over the network.',
    'endpoint': 'A device or service on the network that can send or receive traffic — here, the source host.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'write access': 'Permission to change or delete things, not just look. More dangerous if exposed.',
    'tool listings': 'The menu of actions an MCP server says it can do — including whether those actions can change data.',
    'cloud vendor ranges': 'Blocks of internet addresses that belong to big cloud providers (not the conference Wi-Fi itself).',
    'security-orchestration': 'Wiring many security tools together so one client can drive several of them.',
    'security stack': 'The set of security products in use — detection, intel, identity, and similar tools.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'resolver': 'The DNS server that answers "what address is this name?" for clients on the network.',
    'auth material': 'Secrets used to prove identity — tokens, keys, or passwords. Bad to send in the clear.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed traffic',
      tag: '[zeek]',
      narration: 'A-4418 · High · Cleartext MCP · 10.44.18.72 → cloud vendor ranges · HTTP (no TLS) · 214 requests, 7 MCP paths over 18m. Paths include /vaultwatch/mcp, /talon/mcp, /redline-intel/mcp, /graph-ti/mcp, /pulsefeed/mcp, /badgeauth/mcp, /notekeep/mcp. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-cleartext-stack', label: 'cleartext · 7 MCP paths', detail: 'Unencrypted HTTP carries a complete security-orchestration client surface, not a single health check.' }
      ],
      exits: [
        { to: 'http-conn', label: 'Inspect the HTTP sessions' },
        { to: 'dns-logs', label: 'Pivot to resolver logs' },
        { to: 'device-profile', label: 'Profile the source host' }
      ]
    },
    'http-conn': {
      name: 'HTTP sessions',
      tag: '[http]',
      narration: 'Session bodies stay in the clear: JSON-RPC style MCP calls, tool listings, and auth material in headers. Destinations resolve into cloud vendor ranges. One client process enumerates vault, EDR, threat-intel, graph TI, pulse feed, badge auth, and note-keep MCP servers in sequence. Several tool descriptors advertise write access (create, update, delete), not read-only probes.',
      evidence: [
        { id: 'ev-live-stack', label: 'live stack · write tools advertised', detail: 'Cleartext MCP listings expose a live security stack; multiple tools advertise write access, so the exposure is not read-only.' }
      ],
      exits: [
        { to: 'dns-logs', label: 'Pivot to resolver logs' },
        { to: 'device-profile', label: 'Profile the source host' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'dns-logs': {
      name: 'Resolver logs',
      tag: '[dns-01]',
      narration: 'Resolver window for 10.44.18.72 shows fakecorp-mdm.example, badgeauth.fakecorp.example, collab.fakecorp.example, and several cloud vendor names. Query mix matches a managed FAKE CORP endpoint on conference Wi-Fi. Corp-looking DNS is normal for that asset class; it does not clear the cleartext MCP exposure.',
      evidence: [
        { id: 'ev-dns-corp', label: 'DNS · fakecorp.* pattern', detail: 'Name resolution looks like a managed FAKE CORP endpoint. Normal for the asset class; not a close code by itself.' }
      ],
      exits: [
        { to: 'device-profile', label: 'Profile the source host' },
        { to: 'class-context', label: 'Search class traffic' },
        { to: 'http-conn', label: 'Inspect the HTTP sessions' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'device-profile': {
      name: 'Device profile',
      tag: '[asset]',
      narration: 'Host identity: FAKECORP-L4P · managed enterprise browser · enrolled at fakecorp-mdm.example. Org label FAKE CORP. An open endpoint on the conference network with FAKE CORP MDM signals; provenance beyond that is not established here.',
      evidence: [
        { id: 'ev-managed', label: 'managed endpoint · FAKE CORP MDM', detail: 'Source presents as a managed FAKE CORP endpoint. Identity explains the DNS pattern; it does not sanction cleartext security-stack MCP on the floor.' }
      ],
      exits: [
        { to: 'class-context', label: 'Search class traffic' },
        { to: 'dns-logs', label: 'Pivot to resolver logs' },
        { to: 'http-conn', label: 'Inspect the HTTP sessions' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'class-context': {
      name: 'Class traffic',
      tag: '[ops]',
      narration: 'Training VLAN and exploit-lab SSID samples in the same 18m show no peer hosts enumerating the same cleartext MCP security stack. Pattern is unique to 10.44.18.72, not shared class traffic.',
      evidence: [
        { id: 'ev-not-class', label: 'no class peers · not lab SSID', detail: 'Sanctioned training MCP would show peers on the lab SSID. This host is alone; BH Benign does not fit.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 4 },
        { to: 'device-profile', label: 'Return to device profile' },
        { to: 'dns-logs', label: 'Pivot to resolver logs' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: cleartext live security-stack MCP with advertised write tools, FAKE CORP MDM signals on an open conference endpoint, corp DNS that explains identity but not exposure, and no training-VLAN peer pattern. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', correct: true, resultNote: 'Cleartext exposure of a live security-orchestration stack with advertised write tools on the conference network is a confirmed incident that requires escalation and IR. Close True Positive.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The HTTP sessions and MCP paths are real; the alert was not a product failure.' },
        { id: 'bh-benign', label: 'BH Benign', resultNote: 'BH Benign fits sanctioned or non-hostile class traffic. No lab-SSID peers share this MCP stack; MDM signals alone do not make the exposure acceptable.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed True Positive',
      narration: 'A-4418 closed True Positive. On-site IR contacts the FAKE CORP asset owner; cleartext MCP client traffic is treated as a live security-stack exposure. Handover notes the path set and source 10.44.18.72.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows a live cleartext security-stack exposure outside class sanction. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}, {
  id: 'northlab-cleartext-siem-login',
  meta: {
    title: 'Cleartext SIEM login, classroom VLAN',
    briefing: 'Alert A-5521 is open: cleartext HTTP from 10.44.22.11 to a cloud VPS, LogDeck SIEM UI login paths, credentials from 3 attempts visible on the wire. Source sits on a Malware Traffic Lab classroom VLAN. Pivot through the evidence, separate ugly cleartext from unsanctioned incident, and post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'SIEM': 'A search box over security logs — like a library catalog for network and host events.',
    'LogDeck': 'A fictional classroom SIEM product name used in this drill (stands in for a real log UI).',
    'cleartext': 'Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.',
    'HTTP': 'The basic language of the web. Alone (without TLS) it is not private.',
    'TLS': 'The lock on a web connection (the S in HTTPS). "No TLS" means the traffic is not locked.',
    'VLAN': 'A sliced-off piece of the network, like a separate hallway in the same building.',
    'cloud VPS': 'A rented virtual server on the public internet, not a conference lab appliance.',
    'classroom VLAN': 'The network slice assigned to a training room — peers here often share class tooling.',
    'credentials': 'Login secrets (username and password). Bad to send in the clear.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'login paths': 'The web URLs used to sign into a service — here, the SIEM account pages.',
    'peer hosts': 'Other devices on the same classroom network doing similar traffic.',
    'Zeek': 'A network monitor that turns packets into searchable connection and protocol logs.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed traffic',
      tag: '[zeek]',
      narration: 'A-5521 · High · Cleartext SIEM login · 10.44.22.11 → cloud VPS · HTTP (no TLS) · port 8001 · 3 login attempts in 6m. URIs include /en-GB/account/login and /en-GB/logdeckd/__raw/services/appsbrowser/account:login. Source VLAN label: Malware Traffic Lab. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-cleartext-login', label: 'cleartext · SIEM login paths', detail: 'Unencrypted HTTP carries LogDeck account login traffic from a classroom VLAN host to a cloud VPS.' }
      ],
      exits: [
        { to: 'http-login', label: 'Inspect the login sessions' },
        { to: 'dest-context', label: 'Profile the destination' },
        { to: 'class-peers', label: 'Search class peer traffic' }
      ]
    },
    'http-login': {
      name: 'Login sessions',
      tag: '[http]',
      narration: 'Session bodies stay in the clear: username and password fields for labadmin (success), course-feed (success), and instructor+lab@northlab.example (403). Three attempts, credentials readable on the wire. Destinations resolve into cloud VPS address space, not a conference appliance.',
      evidence: [
        { id: 'ev-creds-clear', label: 'credentials in clear · 3 attempts', detail: 'Login secrets are visible in cleartext HTTP. The exposure is real; the close code still depends on whether the SIEM is sanctioned class tooling.' }
      ],
      exits: [
        { to: 'dest-context', label: 'Profile the destination' },
        { to: 'class-peers', label: 'Search class peer traffic' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'dest-context': {
      name: 'Destination profile',
      tag: '[asset]',
      narration: 'Cloud VPS listener on 8001 presents a LogDeck web UI. Post-body and URI crumbs reference LogDeck Security Essentials and a classroom observability app pack. Pattern matches a temporary SIEM stood up for training, not a corporate production tenant. Staging for class does not by itself prove the login traffic is sanctioned.',
      evidence: [
        { id: 'ev-class-tooling', label: 'LogDeck · class tooling signals', detail: 'Destination looks like a short-lived classroom SIEM with security-lab app packs. Context for BH Benign; not a close without peer confirmation.' }
      ],
      exits: [
        { to: 'class-peers', label: 'Search class peer traffic' },
        { to: 'http-login', label: 'Inspect the login sessions' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'class-peers': {
      name: 'Class peer traffic',
      tag: '[ops]',
      narration: 'Same Malware Traffic Lab VLAN window shows peer hosts 10.44.22.12, 10.44.22.13, and 10.44.22.15 also reaching the same cloud VPS:8001 LogDeck UI, at lower volume than 10.44.22.11. Pattern is shared class traffic, not a singleton hostile login spray. Instructor-operated malware-traffic labs commonly drive Zeek into a classroom SIEM over HTTP for the week.',
      evidence: [
        { id: 'ev-class-peers', label: 'class peers · same LogDeck dest', detail: 'Multiple classroom VLAN hosts share the cleartext LogDeck destination. Sanctioned training pattern supports BH Benign over True Positive IR.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'dest-context', label: 'Return to destination profile' },
        { to: 'http-login', label: 'Inspect the login sessions' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: cleartext LogDeck credentials on the wire, a cloud VPS SIEM with classroom app-pack signals, and multiple Malware Traffic Lab VLAN peers on the same destination. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', resultNote: 'True Positive fits unsanctioned credential exposure that needs IR now. Peer hosts and classroom tooling show this SIEM is shared lab infrastructure; escalate as leaky class hygiene later, not as an active intrusion close.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The cleartext logins and credential fields are real; the alert was not a product failure.' },
        { id: 'bh-benign', label: 'BH Benign', correct: true, resultNote: 'BH Benign fits sanctioned class traffic. Cleartext credentials are ugly and worth a courtesy note, but shared classroom VLAN peers on a training LogDeck earn BH Benign rather than True Positive IR.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed BH Benign',
      narration: 'A-5521 closed BH Benign. Cleartext classroom SIEM logins are logged for instructor awareness; no intrusion IR ticket is opened. Handover notes source 10.44.22.11 and peer reuse of the same LogDeck VPS.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows shared Malware Traffic Lab LogDeck traffic. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}];
