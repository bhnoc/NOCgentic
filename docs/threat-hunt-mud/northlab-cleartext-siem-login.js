/**
 * Threat hunt as code — classroom cleartext SIEM login.
 *
 * Inverse lesson of fakecorp-cleartext-mcp: cleartext credentials look like
 * True Positive, but shared classroom VLAN peers on a training SIEM earn
 * BH Benign. Live registry: packages/web-server/static/threat-hunt-config.js
 * (window.THREAT_HUNTS).
 */
window.THREATHUNT_NORTHLAB_CLEARTEXT_SIEM_LOGIN = {
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
};
