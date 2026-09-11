# Threat Hunting Frameworks Reference

## MITRE ATT&CK

**What it is**: Knowledge base of real-world adversary tactics, techniques, and procedures (TTPs) organized by attack phase.

**Structure**: 14 Tactics → 200+ Techniques → Sub-techniques
- Tactics = adversary goals (why)
- Techniques = methods to achieve goals (how)
- Sub-techniques = specific implementations

**Use in network hunting**:
- Map network observables to specific techniques
- Identify which ATT&CK techniques your current log coverage can detect
- Use ATT&CK Navigator to visualize detection gaps
- Prioritize hunts based on threat actor profiles (groups using relevant techniques)

**Key resources**:
- [attack.mitre.org](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [MITRE CAR — Cyber Analytics Repository](https://car.mitre.org/) (analytics library)
- [MITRE CALDERA](https://github.com/mitre/caldera) (adversary emulation)

---

## Cyber Kill Chain (Lockheed Martin)

**7 phases**: Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions on Objectives

**Use in network hunting**: Identify which kill chain phase an indicator belongs to; earlier-phase detection = lower attacker dwell time.

| Phase | Network-Observable Events |
|-------|--------------------------|
| Reconnaissance | Port scans, WHOIS lookups, web crawling |
| Delivery | Phishing email delivery, malware download |
| Exploitation | Exploit traffic, protocol anomalies |
| Installation | Dropper download, script execution via HTTP |
| C2 | Beaconing, DNS tunneling, HTTPS C2 |
| Actions on Objectives | Lateral movement, data exfiltration, encryption |

---

## Diamond Model of Intrusion Analysis

**4 elements**: Adversary ↔ Infrastructure ↔ Capability ↔ Victim

**Use in network hunting**:
- Start from network IOC (Infrastructure) → pivot to adversary and capabilities
- JARM hash = infrastructure fingerprint → find other servers with same configuration
- TLS certificate = capability indicator → find other domains on same cert
- Enables adversary attribution from network evidence

**Pivoting logic**:
```
Victim (your network)
  ↕
Infrastructure (C2 IP, domain, cert)
  ↕
Capability (malware, C2 framework, exploit)
  ↕
Adversary (threat actor group)
```

---

## Pyramid of Pain (David Bianco)

Ranked indicator types by how much pain removing them causes an adversary:

```
          ╔═══════════════════════╗
          ║   TTPs (Tactics,      ║  ← VERY PAINFUL (hardest to change)
          ║   Techniques,         ║
          ║   Procedures)         ║
          ╠═══════════════════════╣
          ║   Tools               ║  ← Painful
          ╠═══════════════════════╣
          ║   Network/Host        ║  ← Annoying
          ║   Artifacts           ║
          ╠═══════════════════════╣
          ║   Domain Names        ║  ← Simple
          ╠═══════════════════════╣
          ║   IP Addresses        ║  ← Easy
          ╠═══════════════════════╣
          ║   Hash Values         ║  ← Trivial
          ╚═══════════════════════╝
```

**Use in network hunting**: Hunt for TTPs and behavioral patterns (top of pyramid) rather than just IOCs (bottom). RITA's beaconing detection hunts TTPs, not just known-bad IPs.

---

## Hunting Maturity Model (Sqrrl/HMM)

5-level capability framework for threat hunting programs:

| Level | Name | Characteristics |
|-------|------|-----------------|
| HMM0 | Initial | Relies solely on automated alerting; no proactive hunting |
| HMM1 | Minimal | Uses IOC searches; no documented procedures |
| HMM2 | Procedural | Documented hunt procedures; hypothesis-driven; regular cadence |
| HMM3 | Innovative | Custom analytics; data science; automation; feedback loop |
| HMM4 | Leading | Machine learning; automated hypothesis generation; continuous hunting |

---

## Detection Maturity Level (DML)

8-level reference model from lower to higher detection sophistication:

| Level | Detects | Example |
|-------|---------|---------|
| DML0 | Nothing | No detection capability |
| DML1 | File hash | SHA256 of known malware |
| DML2 | IP/domain | Known-bad C2 IP |
| DML3 | Network artifact | Specific URI pattern |
| DML4 | Host artifact | Registry key |
| DML5 | Tool | C2 framework identified |
| DML6 | Technique | Beaconing behavior detected |
| DML7 | Tactics | Full adversary campaign detected |

---

## OSSEM (Open Security Events Metadata)

**What it is**: Community-driven effort to standardize security event schemas across sources (Windows, Linux, network, cloud).

**Use in network hunting**: Ensures your Zeek/Suricata fields are normalized consistently when fed into SIEM; enables cross-source correlation with standardized field names.

**Key schemas**:
- Network (flow, dns, http, tls, smtp, ftp)
- Endpoint (process, file, network connection)
- Authentication

---

## OCSF (Open Cybersecurity Schema Framework)

**What it is**: Open standard for cybersecurity event data schema (backed by AWS, Splunk, IBM, others).

**Use in network hunting**: Normalize Zeek/Suricata/NDR output into OCSF-compliant format for cloud SIEM integration (Chronicle, Security Lake).

---

## TTP-Based Hunting (MITRE Method)

Methodology from MITRE's TTP-Based Hunting whitepaper:

```
1. THREAT PROFILE      Identify relevant adversaries and their TTPs
2. DATA COLLECTION     Map available data sources to expected evidence
3. TTP PRIORITIZATION  Rank TTPs by: data availability, threat relevance, coverage gap
4. HUNT PLANNING       Create hypothesis and query for each prioritized TTP
5. EXECUTION           Run hunts in priority order
6. DETECTION CREATION  Convert successful hunts to detection rules
7. MEASUREMENT         Track coverage %, MTTD, false positive rate
```

---

## Hunt Hypothesis Types

| Type | Method | Example |
|------|--------|---------|
| **Intel-based** | Start with TI report or IOC | "Hunt for TTPs used by APT29 in recent report" |
| **Situational** | Based on recent news or industry incidents | "Hunt for MOVEit-style SQL injection patterns" |
| **Domain-expertise** | Analyst knowledge of what's suspicious | "I've never hunted for ICMP tunneling in this environment" |
| **Data-driven** | Anomaly detection triggers hunt | "ML flagged unusual DNS volume from host X" |
| **Crown-jewel** | Focus on highest-value assets | "Any access to finance servers outside business hours" |
