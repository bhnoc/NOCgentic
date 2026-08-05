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
}, {
  // Obfuscation map (Slack -> fiction): supply-chain DNS / managed booth laptop -> WirePipe.zone + GLASSLINE MDM.
  // Real campaign names, vendors, people, and prod case ids never appear in copy.
  id: 'fakecorp-supplychain-dns',
  meta: {
    title: 'Supply-chain DNS, managed laptop',
    briefing: 'Alert A-6602 is open: ET malware signatures for WirePipe supply-chain domains from 10.44.30.12 on general Wi-Fi. One domain resolves; related lookups NXDOMAIN. Pivot through DNS, detections, and asset context, then post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'DNS': 'The phone book of the internet: turns names into addresses computers dial.',
    'ET malware': 'Emerging Threats rules — signature alerts that a look-up or session matched known-bad patterns.',
    'supply-chain': 'Attackers poison a tool many orgs already trust, so the bad code arrives through a normal update path.',
    'WirePipe': 'Fictional compromised tooling name used in this drill (stands in for a real supply-chain campaign).',
    'NXDOMAIN': 'DNS answer meaning "that name does not exist" — like a wrong number with no forwarding.',
    'MDM': 'Company device management — software that enrolls and controls a laptop or phone for IT.',
    'SaaS': 'Software run in a vendor cloud that the laptop talks to for normal work.',
    'Suricata': 'An IDS that watches packets and fires named rules when traffic matches known attacks.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'general Wi-Fi': 'Open attendee wireless — not a training classroom VLAN.',
    'RAT': 'Remote access trojan — malware that lets an attacker control a machine from afar.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed DNS',
      tag: '[dns]',
      narration: 'A-6602 · High · Supply-chain DNS · 10.44.30.12 on general Wi-Fi · query wirepipe.zone NOERROR · models.litewire.cloud NXDOMAIN · sfrlake.example NXDOMAIN · window 12m. ET malware rules name WirePipe supply-chain and a related RAT domain. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-dns-ioc', label: 'DNS · wirepipe.zone resolves', detail: 'Named supply-chain domain resolves on the conference resolver; sibling campaign names return NXDOMAIN in the same bursts.' }
      ],
      exits: [
        { to: 'detections', label: 'Open detection rules' },
        { to: 'device-profile', label: 'Profile the source host' },
        { to: 'class-context', label: 'Search class traffic' }
      ]
    },
    'detections': {
      name: 'Detection stack',
      tag: '[ids]',
      narration: 'Suricata window for 10.44.30.12 shows ET malware hits on WirePipe supply-chain DNS and repeated RAT-domain lookups. Hits are signature-true on the wire. Campaign public write-ups are months old; age does not erase a live resolve of a named C2/supply-chain indicator on the floor.',
      evidence: [
        { id: 'ev-et-hits', label: 'ET malware · WirePipe + RAT DNS', detail: 'IDS rules fire on real queries. Old campaign timelines do not convert a live resolve into ambient noise.' }
      ],
      exits: [
        { to: 'device-profile', label: 'Profile the source host' },
        { to: 'class-context', label: 'Search class traffic' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'device-profile': {
      name: 'Device profile',
      tag: '[asset]',
      narration: 'Host presents as a managed Windows endpoint under GLASSLINE MDM with SaaS tenants for glassline.example. Corp-looking management traffic is normal for that asset class. MDM and SaaS context explain identity; they do not clear ET malware DNS to WirePipe infrastructure.',
      evidence: [
        { id: 'ev-mdm-corp', label: 'managed · GLASSLINE MDM', detail: 'Source looks like a managed GLASSLINE laptop. Identity context only; not a BH Benign for supply-chain DNS.' }
      ],
      exits: [
        { to: 'class-context', label: 'Search class traffic' },
        { to: 'detections', label: 'Open detection rules' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'class-context': {
      name: 'Class traffic',
      tag: '[ops]',
      narration: 'Training VLAN and lab SSID samples in the same window show no peer hosts resolving wirepipe.zone or the sibling NXDOMAIN names. Pattern is unique to 10.44.30.12 on general Wi-Fi, not shared coursework.',
      evidence: [
        { id: 'ev-no-peers-sc', label: 'no class peers · general Wi-Fi', detail: 'Sanctioned lab malware DNS would show classroom peers. This host is alone on attendee Wi-Fi; BH Benign does not fit.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'device-profile', label: 'Return to device profile' },
        { to: 'detections', label: 'Open detection rules' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: live resolve of a named WirePipe supply-chain domain, ET malware hits including related RAT DNS, GLASSLINE MDM that explains the laptop but not the IOC, and no classroom peer pattern. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', correct: true, resultNote: 'Live supply-chain and RAT DNS on the floor is a confirmed finding that needs owner contact and IR follow-up, even when the public campaign is old. Close True Positive.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The DNS queries and ET hits are real; the alert was not a product failure.' },
        { id: 'bh-benign', label: 'BH Benign', resultNote: 'BH Benign fits sanctioned class or non-hostile expected traffic. No lab peers share this WirePipe DNS; MDM alone does not sanction malware-domain resolves.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed True Positive',
      narration: 'A-6602 closed True Positive. On-site IR contacts the GLASSLINE asset owner about WirePipe supply-chain DNS from 10.44.30.12. Handover notes the resolve and sibling NXDOMAIN lookups.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows live supply-chain DNS outside class sanction. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}, {
  // Obfuscation map: singleton DDNS/C2 with false class temptation -> starbright.ddns.example, Social Engineering Lab VLAN.
  id: 'northlab-singleton-c2',
  meta: {
    title: 'Singleton C2 DNS, class temptation',
    briefing: 'Alert A-6610 is open: dynamic DNS name starbright.ddns.example from 10.44.31.21 on a Social Engineering Lab VLAN, plus C2-like TLS and a multi-day beacon pattern. First-pass tooling calls class traffic. Pivot, test that claim, and post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'dynamic DNS': 'A hostname that can point at changing IPs — handy for labs, also common in malware callbacks.',
    'C2': 'Command and control — the remote brain malware calls home to for instructions.',
    'beacon': 'A regular check-in pattern from a host to a remote address, like a heartbeat.',
    'DDNS': 'Short for dynamic DNS — a moving hostname often used for callbacks.',
    'VLAN': 'A sliced-off piece of the network, like a separate hallway in the same building.',
    'classroom VLAN': 'The network slice assigned to a training room — peers here often share class tooling.',
    'Suricata': 'An IDS that watches packets and fires named rules when traffic matches known attacks.',
    'TLS': 'The lock on a web connection (the S in HTTPS).',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'peer hosts': 'Other devices on the same classroom network doing similar traffic.',
    'syllabus': 'The course plan — what the class is supposed to touch on the wire.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed DNS',
      tag: '[dns]',
      narration: 'A-6610 · High · Dynamic DNS C2 · 10.44.31.21 → starbright.ddns.example · Social Engineering Lab VLAN label · first auto-summary says likely coursework. Resolver shows repeated A lookups across ~3 days, not a single lab spike. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-ddns-c2', label: 'DDNS · starbright.ddns.example', detail: 'Host repeatedly resolves a dynamic DNS name tied in intel to remote-access malware families. VLAN label alone is not a close.' }
      ],
      exits: [
        { to: 'c2-sessions', label: 'Inspect follow-up sessions' },
        { to: 'auto-class', label: 'Review the class hypothesis' },
        { to: 'class-peers', label: 'Search class peer traffic' }
      ]
    },
    'c2-sessions': {
      name: 'Follow-up sessions',
      tag: '[ssl]',
      narration: 'After DNS, 10.44.31.21 opens TLS and raw TCP toward infrastructure linked to the same intel cluster. Beacon spacing is steady across multiple days. Packed executable download notices appear once. Traffic is not constrained to a published lab appliance address.',
      evidence: [
        { id: 'ev-beacon', label: 'multi-day beacon · C2-like TLS', detail: 'Callback pattern spans days with C2-like TLS. Duration and destinations argue prior compromise over a one-hour lab block.' }
      ],
      exits: [
        { to: 'auto-class', label: 'Review the class hypothesis' },
        { to: 'class-peers', label: 'Search class peer traffic' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'auto-class': {
      name: 'Class hypothesis',
      tag: '[ops]',
      narration: 'First-pass tooling maps the VLAN to Social Engineering Lab and suggests BH Benign coursework. Syllabus samples list phishing-kit and browser labs; they do not list starbright.ddns.example or multi-day external beacons. VLAN membership is a hint to check peers, not a close code.',
      evidence: [
        { id: 'ev-class-claim', label: 'auto-class claim · not in syllabus', detail: 'Tooling guessed coursework from the VLAN label. Syllabus does not cover this DDNS destination; the claim still needs peer proof.' }
      ],
      exits: [
        { to: 'class-peers', label: 'Search class peer traffic' },
        { to: 'c2-sessions', label: 'Inspect follow-up sessions' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'class-peers': {
      name: 'Class peer traffic',
      tag: '[ops]',
      narration: 'Same Social Engineering Lab VLAN window shows zero peer hosts resolving starbright.ddns.example or talking to the same follow-up destinations. Pattern is unique to 10.44.31.21. Missing peers kill the auto-class BH Benign path.',
      evidence: [
        { id: 'ev-no-peers-c2', label: 'no class peers · singleton C2', detail: 'Sanctioned class C2 would show peers on the lab VLAN. This host is alone; BH Benign does not fit.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'auto-class', label: 'Return to class hypothesis' },
        { to: 'c2-sessions', label: 'Inspect follow-up sessions' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: multi-day DDNS and C2-like sessions, an auto-class claim the syllabus does not support, and zero classroom peers on the same destination. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', correct: true, resultNote: 'Known C2/DDNS with a multi-day beacon and no class peers is a confirmed compromised-or-infected endpoint finding. Close True Positive and pursue owner contact.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The DNS and session evidence are real; the alert was not a product failure.' },
        { id: 'bh-benign', label: 'BH Benign', resultNote: 'BH Benign fits sanctioned class traffic. VLAN label alone is not enough when peers and syllabus coverage are absent.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed True Positive',
      narration: 'A-6610 closed True Positive. On-site IR treats 10.44.31.21 as a likely prior compromise with active DDNS callbacks. Handover notes the missing class-peer pattern.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows singleton C2 outside proven class sanction. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}, {
  // Obfuscation map: vendor license cleartext PII -> StageCast / activate.stagecast.example (no real AV vendor or people).
  id: 'stagecast-license-pii-http',
  meta: {
    title: 'Cleartext license PII, vendor app',
    briefing: 'Alert A-6621 is open: cleartext HTTP license activation from 10.44.32.40 to activate.stagecast.example, POST body carries name, email, and device serial. Pivot through the wire, app identity, and expected-vendor pattern, then post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'cleartext': 'Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.',
    'HTTP': 'The basic language of the web. Alone (without TLS) it is not private.',
    'PII': 'Personal information that can identify someone — name, email, and similar fields.',
    'POST body': 'The data a browser or app sends in an HTTP request — here, the license form fields.',
    'license activation': 'The app phoning home to prove it is allowed to run — often older products still use plain HTTP.',
    'StageCast': 'Fictional media/playback vendor used in this drill (stands in for a real licensor).',
    'serial': 'A device or product ID string — useful to IT, sensitive if leaked in the clear.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'vendor-normal': 'Ugly or leaky behavior that is still how this product is designed to operate.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed traffic',
      tag: '[http]',
      narration: 'A-6621 · Medium · Cleartext license POST · 10.44.32.40 → activate.stagecast.example · HTTP (no TLS) · URI /activate.php · general Wi-Fi. Alert highlights name, email, and serial fields in the POST body. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-license-http', label: 'cleartext · /activate.php', detail: 'Unencrypted HTTP carries a license activation POST to a vendor activation host.' }
      ],
      exits: [
        { to: 'post-body', label: 'Inspect the POST body' },
        { to: 'app-profile', label: 'Profile the client application' },
        { to: 'vendor-pattern', label: 'Compare vendor-normal pattern' }
      ]
    },
    'post-body': {
      name: 'POST body',
      tag: '[http]',
      narration: 'POST fields stay in the clear: FirstName=Riley, LastName=Quill, Email=rquill@stagecast.example, Company=StageCast, SerialNumber=SC-77419, computerName=STAGE-MAC-12. Values identify a person and device. Exposure is real hygiene debt; compromise still has to be proven separately.',
      evidence: [
        { id: 'ev-pii-fields', label: 'PII in clear · name email serial', detail: 'License form leaks personal and device identifiers on attendee Wi-Fi. Ugly and note-worthy; not automatically an intrusion.' }
      ],
      exits: [
        { to: 'app-profile', label: 'Profile the client application' },
        { to: 'vendor-pattern', label: 'Compare vendor-normal pattern' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'app-profile': {
      name: 'Client application',
      tag: '[asset]',
      narration: 'User-agent and process crumbs match StageCast Playback Console performing a scheduled license check. Destination activate.stagecast.example is the vendor activation endpoint documented for that product line. Flow is client-initiated registration, not an inbound exploit chain.',
      evidence: [
        { id: 'ev-stagecast-app', label: 'StageCast · license client', detail: 'Traffic matches the vendor playback app calling its own activation service, not a random phishing POST.' }
      ],
      exits: [
        { to: 'vendor-pattern', label: 'Compare vendor-normal pattern' },
        { to: 'post-body', label: 'Inspect the POST body' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'vendor-pattern': {
      name: 'Vendor-normal check',
      tag: '[ops]',
      narration: 'Same activation host appears in prior show weeks for StageCast floor devices with identical URI and field layout. No second-stage payload, no odd redirect chain, no lateral sweep from 10.44.32.40 in the window. Pattern is known vendor licensing over legacy HTTP.',
      evidence: [
        { id: 'ev-vendor-normal', label: 'vendor-normal · recurring activation', detail: 'Recurring StageCast activation shape without follow-on malice supports BH Benign over True Positive IR.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'app-profile', label: 'Return to client application' },
        { to: 'post-body', label: 'Inspect the POST body' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: cleartext license PII, a StageCast client talking to its activation host, and a recurring vendor-normal pattern without follow-on compromise. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', resultNote: 'True Positive fits active intrusion or hostile exfil needing IR now. This is a designed vendor license POST; track as hygiene outreach, not intrusion close.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The cleartext PII fields are real; the alert correctly saw sensitive data on the wire.' },
        { id: 'bh-benign', label: 'BH Benign', correct: true, resultNote: 'BH Benign fits known vendor operational behavior. Cleartext PII is worth a courtesy note to the vendor/owner, but the close for compromise is BH Benign.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed BH Benign',
      narration: 'A-6621 closed BH Benign. Cleartext StageCast licensing is logged as vendor hygiene; no intrusion IR ticket is opened. Handover notes source 10.44.32.40 and activate.stagecast.example.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows known vendor license activation. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}, {
  // Obfuscation map: NOC Log4j sensor test -> alwayshttp.example test domain, NOC wired 10.44.1.14 (no real engineer names).
  id: 'noc-log4j-sensor-test',
  meta: {
    title: 'Outbound Log4j, NOC sensor test',
    briefing: 'Alert A-6633 is open: Suricata and NGFW both fire on outbound Log4j-style exploit probes from 10.44.1.14 on NOC wired toward alwayshttp.example. Pivot through destination reputation, source network, and detection overlap, then post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'Log4j': 'A famous Java logging bug class — exploit probes try to trigger remote class loading over lookups.',
    'Suricata': 'An IDS that watches packets and fires named rules when traffic matches known attacks.',
    'NGFW': 'Next-gen firewall — blocks and alerts on application-layer threats, not just ports.',
    'NOC wired': 'The wired network used by the operations floor — staff and test gear, not guest Wi-Fi.',
    'alwayshttp.example': 'Fictional cleartext HTTP test site used in this drill (stands in for a known benign HTTP echo host).',
    'sensor validation': 'Intentionally firing known-bad payloads at a safe target to prove detectors still work.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'cleartext': 'Sent with no encryption — anyone on the path can read it, like a postcard instead of a sealed letter.',
    'HTTP': 'The basic language of the web. Alone (without TLS) it is not private.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed traffic',
      tag: '[alert]',
      narration: 'A-6633 · High · Outbound Log4j probe · 10.44.1.14 → alwayshttp.example · HTTP cleartext · Suricata and NGFW threat logs both alert in the same minute. Source network label: NOC wired. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-log4j-alert', label: 'Log4j probe · dual detections', detail: 'Outbound Log4j-style exploit content is detected by two independent engines in the same window.' }
      ],
      exits: [
        { to: 'dest-rep', label: 'Check destination reputation' },
        { to: 'source-net', label: 'Check source network' },
        { to: 'detect-overlap', label: 'Compare detection overlap' }
      ]
    },
    'dest-rep': {
      name: 'Destination reputation',
      tag: '[intel]',
      narration: 'alwayshttp.example is a known cleartext HTTP echo/test host used for connectivity checks. It is not a malware staging domain in current intel. Destination choice matches sensor-validation practice: safe, boring, and deliberately plaintext.',
      evidence: [
        { id: 'ev-test-dest', label: 'dest · known HTTP test host', detail: 'Target is a benign cleartext test site, not attacker infrastructure.' }
      ],
      exits: [
        { to: 'source-net', label: 'Check source network' },
        { to: 'detect-overlap', label: 'Compare detection overlap' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'source-net': {
      name: 'Source network',
      tag: '[ops]',
      narration: '10.44.1.14 sits on NOC wired, not guest or classroom Wi-Fi. Asset inventory lists the MAC as NOC test laptop pool. Guest IR playbooks do not apply the same way to staff validation hosts on this segment.',
      evidence: [
        { id: 'ev-noc-wired', label: 'source · NOC wired test pool', detail: 'Source network and inventory point to operations test gear, not a random attendee endpoint.' }
      ],
      exits: [
        { to: 'detect-overlap', label: 'Compare detection overlap' },
        { to: 'dest-rep', label: 'Check destination reputation' },
        { to: 'observed-logs', label: 'Return to observed traffic' }
      ]
    },
    'detect-overlap': {
      name: 'Detection overlap',
      tag: '[ids]',
      narration: 'Suricata (NDR path) and NGFW threat logs both fire on the same outbound probe content to alwayshttp.example. Overlap is the desired outcome of a multi-vendor sensor test. No inbound exploitation, no lateral movement from 10.44.1.14 in the window.',
      evidence: [
        { id: 'ev-dual-stack', label: 'Suricata + NGFW · test success', detail: 'Dual-engine alert on a NOC-wired host to a known test destination reads as sensor validation, not guest compromise.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'source-net', label: 'Return to source network' },
        { to: 'dest-rep', label: 'Check destination reputation' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: real Log4j-style outbound probes, a known HTTP test destination, a NOC wired test-pool source, and dual-engine detection that proves the stack is watching cleartext HTTP. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', resultNote: 'True Positive fits hostile Log4j activity needing guest IR. Source and destination here match sanctioned sensor validation; escalate only if the host is not actually NOC test gear.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The probes and signatures are real; detectors did their job.' },
        { id: 'bh-benign', label: 'BH Benign', correct: true, resultNote: 'BH Benign fits expected NOC sensor-validation traffic: exploit-shaped probes from NOC wired to a known cleartext test host with dual-engine coverage.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed BH Benign',
      narration: 'A-6633 closed BH Benign as NOC sensor validation. Detectors are confirmed working on cleartext HTTP Log4j content. Handover notes source 10.44.1.14 and alwayshttp.example.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows NOC-wired testing toward a known HTTP test host. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}, {
  // Obfuscation map: corp cloud background on mismatched class VLAN -> RIVERTIDE Azure/intranet names + EdgeTunnel (no real beverage corp).
  id: 'rivertide-azure-background',
  meta: {
    title: 'Corp cloud DNS, mismatched class',
    briefing: 'Alert A-6644 is open: classroom IP 10.44.33.36 heavily queries RIVERTIDE Azure and intranet-looking names while sitting on a Physical Access Lab VLAN. Pivot through DNS, proxy/tunnel background, and class alignment, then post the correct BH close code. Target: under 3 minutes.',
    targetSeconds: 180
  },
  glossary: {
    'DNS': 'The phone book of the internet: turns names into addresses computers dial.',
    'Azure': 'A major cloud provider — companies often put internal apps and databases there.',
    'intranet': 'Internal company names that usually only resolve for employees — odd to see on a show floor unless a corp laptop is present.',
    'EdgeTunnel': 'Fictional enterprise secure-web/proxy agent used in this drill (stands in for a real cloud proxy).',
    'RIVERTIDE': 'Fictional corporation used in this drill for corp-looking background traffic.',
    'VLAN': 'A sliced-off piece of the network, like a separate hallway in the same building.',
    'classroom VLAN': 'The network slice assigned to a training room — peers here often share class tooling.',
    'Pivot': 'Jump to another log source using what you already found — follow the breadcrumb.',
    'BH close code': 'How Black Hat SOC marks why an alert was closed — the official label for the outcome.',
    'True Positive': 'Real bad or real impact that needed incident response. The alert was right and serious.',
    'False Positive': 'The alert was wrong — it looked bad but the detection was a mistake.',
    'BH Benign': 'Something that looked alarming but is allowed here (for example sanctioned class traffic).',
    'close code': 'The final label on an alert that says what kind of finding it turned out to be.',
    'IR': 'Incident response — the people and steps used when something real needs handling now.',
    'managed endpoint': 'A company-controlled laptop that keeps checking in with corporate cloud services.'
  },
  startNode: 'observed-logs',
  nodes: {
    'observed-logs': {
      name: 'Observed DNS',
      tag: '[dns]',
      narration: 'A-6644 · Medium · Heavy corp cloud DNS · 10.44.33.36 on Physical Access Lab VLAN · names include flexops.azure.intra.rivertide.example, badgeprint.azure.intra.rivertide.example, rivdirect.postgres.database.azure.com · high query volume over 40m. Class topic does not mention RIVERTIDE cloud labs. Three surfaces are available for pivot.',
      evidence: [
        { id: 'ev-corp-dns', label: 'DNS · rivertide.azure.intra.*', detail: 'Host heavily resolves internal-looking RIVERTIDE Azure and database names from a classroom VLAN.' }
      ],
      exits: [
        { to: 'proxy-background', label: 'Inspect proxy and tunnel traffic' },
        { to: 'asset-org', label: 'Profile org signals' },
        { to: 'class-align', label: 'Check class alignment' }
      ]
    },
    'proxy-background': {
      name: 'Proxy background',
      tag: '[http]',
      narration: 'HTTP CONNECT and agent beacons match EdgeTunnel enterprise proxy behavior: repeated cloud policy checks, certificate pin updates, and portal keepalives. Volume is background-managed-endpoint chatter, not a tight scan of a single database listener.',
      evidence: [
        { id: 'ev-edge-tunnel', label: 'EdgeTunnel · corp proxy chatter', detail: 'Traffic shape matches a corporate secure-web agent keeping a managed laptop compliant, not interactive DB abuse.' }
      ],
      exits: [
        { to: 'asset-org', label: 'Profile org signals' },
        { to: 'class-align', label: 'Check class alignment' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'asset-org': {
      name: 'Org signals',
      tag: '[asset]',
      narration: 'Device hostname and tenant crumbs label the endpoint RIVERTIDE with high confidence. SharePoint and SaaS hosts under rivertide.example appear alongside the Azure intranet names. Pattern is a corporate laptop on guest training Wi-Fi, not an anonymous VPS implant.',
      evidence: [
        { id: 'ev-rivertide-asset', label: 'managed endpoint · RIVERTIDE', detail: 'Org identity explains why internal Azure names appear. Provenance beyond tenant signals is not established here.' }
      ],
      exits: [
        { to: 'class-align', label: 'Check class alignment' },
        { to: 'proxy-background', label: 'Inspect proxy and tunnel traffic' },
        { to: 'observed-logs', label: 'Return to observed DNS' }
      ]
    },
    'class-align': {
      name: 'Class alignment',
      tag: '[ops]',
      narration: 'Physical Access Lab syllabus covers badges, RFID, and door controllers. It does not assign RIVERTIDE Azure labs. Misalignment explains the analyst gut-check, but EdgeTunnel plus tenant DNS still reads as corp laptop background. No exploit payload, no credential spray, no peer-less C2 pattern in this window.',
      evidence: [
        { id: 'ev-mismatch-ok', label: 'class mismatch · still corp-normal', detail: 'Wrong class topic raises eyebrows; combined with managed RIVERTIDE + EdgeTunnel it does not earn True Positive by itself.' }
      ],
      exits: [
        { to: 'decision', label: 'Move to close codes', requiresEvidence: 3 },
        { to: 'asset-org', label: 'Return to org signals' },
        { to: 'proxy-background', label: 'Inspect proxy and tunnel traffic' }
      ]
    },
    'decision': {
      name: 'Close codes',
      tag: '[decision]',
      narration: 'Evidence is on the table: heavy RIVERTIDE Azure/intranet DNS, EdgeTunnel corporate proxy chatter, managed-endpoint org signals, and a class-topic mismatch without hostile follow-on. One BH close code fits.',
      isDecision: true,
      actions: [
        { id: 'true-positive', label: 'True Positive', resultNote: 'True Positive fits hostile probing of production cloud. Here the names and proxy agents match a RIVERTIDE managed laptop backgrounding to its own tenant.' },
        { id: 'false-positive', label: 'False Positive', resultNote: 'False Positive fits a wrong detector assertion. The DNS volume and destinations are real; the question is intent and sanction, not detector failure.' },
        { id: 'bh-benign', label: 'BH Benign', correct: true, resultNote: 'BH Benign fits expected corporate laptop background on a training VLAN. Class mismatch is noted; EdgeTunnel and tenant DNS clear this as non-hostile guest behavior.' }
      ]
    }
  },
  endings: {
    win: {
      title: 'Closed BH Benign',
      narration: 'A-6644 closed BH Benign. RIVERTIDE Azure/intranet DNS from 10.44.33.36 is treated as managed laptop background on a mismatched training VLAN. No intrusion IR ticket is opened.'
    },
    lose: {
      title: 'Wrong close code',
      narration: 'The queue records the chosen close code against evidence that still shows corp-normal EdgeTunnel and RIVERTIDE tenant traffic. The correct first close is below.'
    },
    timeout: {
      title: 'Window closed',
      narration: 'The queue moved on before a close code landed. The evidence trail remains below for review.'
    }
  }
}];
