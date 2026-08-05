# Hunter narrative — Host Sweep that wasn't

**Package:** `sth-20260801-host-sweep-fp`  
**Event:** Black Hat / NOC training · live Cortex XSIAM  
**Original hunter:** CLI Hunter  

---

## Situation

The open queue was loud: Large HTTPS uploads, ZGrab scanner detections, and a medium **Host Sweep** sitting at the top of triage. The mission question was simple and harsh:

> What is the most credible threat *right now*, and can multi-source evidence prove it?

There was no dual-RAT gold case waiting in the *new* top-N. The honest answer might be: **nothing malicious — but prove it.**

---

## Steps taken

### 1. Triage under noise

`cases browse` and `triage` ranked **{{CASE_PRIMARY}}** highest. I did not open the busiest Large Upload. Host Sweep is a binary bet: real recon, or a detection that teaches juniors how zone protection lies.

### 2. Open the case

`investigate incident {{CASE_PRIMARY}}` showed NGFW zone-protection alerts from **{{HOST_A}}** to **{{DNS_QUAD9}}** and **{{DNS_GOOGLE}}** on port **53**, path **{{ZONE_FROM}} → {{ZONE_TO}}**. That is not a sweep of a training `/24`. It is a laptop talking to the public internet’s DNS.

### 3. Who is this host?

`host identify --deep --with-related` returned **no agent**, confidence medium, type **apple_or_macos_client**, hostname **{{HOSTNAME_A}}**, and MAC/user **{{MAC_A}}** (privacy MAC). `bh ip` was empty — not on venue training `10.220/16` map. Related incidents were mostly Blackhat Monitored Thread noise.

Lesson: **agentless is a constraint, not a verdict.**

### 4. Corroborate traffic

DNS top: Kandji MDM, Apple services, WhatsApp, Spotify, **Corelight enterprise Slack**, **BH NOC Slack**, Telstra + Gmail IMAP, VS Code CDN. Outbound: mostly 443. Threats: informational TLS ECH / post-quantum cipher notes. Enrich on Google DNS: many hosts use it.

Lesson: **SaaS/MDM profile + public DNS remotes = FP disproof**, not “unknown APT.”

### 5. Disposition

**False positive**, confidence ~0.85. Recommend resolve with a comment that cites remotes + identity + DNS profile. **Do not isolate.** No mutation was executed without a human.

---

## Key evidence (tokenized)

| Source | What it showed |
|--------|----------------|
| Case alerts | Host Sweep → public DNS :53 |
| Host identity | Agentless Mac, MAC-as-user, no BH room |
| Related | Monitored-thread spam, not malware series |
| XQL DNS / apps | Org Slack + MDM + consumer SaaS |
| NGFW threats | Informational only |

---

## Decision

| Field | Value |
|-------|--------|
| Disposition | **false_positive** (recommended) |
| Severity for action | low / info |
| Confidence | 0.85 |
| Containment | none |

---

## Lessons for juniors

1. **Score ≠ malice.** Rank #1 can still be the best *teaching* FP.  
2. **Read the remote IP.** Public resolvers kill most “host sweep” stories.  
3. **Identity before isolate.** No agent + privacy MAC is common on event Wi‑Fi.  
4. **Multi-source or it didn’t happen.** Case + host + DNS + related + threats.  
5. **Name humility.** If telemetry only has a MAC, say “unknown person,” don’t invent one.  
6. **Mutations wait.** Write the disproof first; resolve only with human OK.

---

## What would change my mind

- Same host sweeping **internal** `10.220.x` ranges  
- Rare ports / known C2 domains in DNS top  
- Agent present with malicious process chain  
- Sole-source malware domain with high hit volume (e.g. landmark Spike DNS patterns)

---

*End of narrative — see `path.json` for learner steps and `shadow.json` for step-level reasoning.*
