# Threat Hunt Catalog

Skills, playbooks, and frameworks for threat hunting in Zeek, Suricata, and raw PCAP data.  
Served to analysts as the **Playbooks** tab of the BH AI SOC UI (`/api/v1/catalog`);
`finding-playbook-map.json` links alert topics and zeek-detector findings to playbooks.
Operator notes: [`docs/hunt-catalog.md`](../docs/hunt-catalog.md).  
Incorporates content from SigmaHQ, Elastic detection-rules, OTRF ThreatHunter-Playbook, MITRE BZAR, MITRE CAR, FalconForce FalconFriday, and travisbgreen/hunting-rules.

## Structure

```
threathunt-catalog/
├── skills/
│   ├── 01-zeek-skills.md               Zeek log types, detection techniques, packages
│   ├── 02-suricata-skills.md           Suricata log types, techniques, rulesets
│   ├── 03-pcap-analysis-skills.md      PCAP tools, techniques, tshark command reference
│   ├── 04-analyst-competencies.md      Core skill domains, certs, training
│   └── 05-tools-ecosystem.md           Full tool ecosystem map
├── playbooks/
│   ├── PB-01-c2-beaconing.md           Beaconing detection (RITA, statistical)
│   ├── PB-02-dns-tunneling-dga.md      DNS tunneling and DGA detection
│   ├── PB-03-lateral-movement.md       Lateral movement (SMB, RDP, WMI, Kerberos)
│   ├── PB-04-data-exfiltration.md      Data exfiltration detection
│   ├── PB-05-kerberos-attacks.md       Kerberoasting, Golden/Silver Ticket, PtH
│   ├── PB-06-tls-fingerprinting.md     JA3/JA4/JARM/HASSH/RDFP fingerprinting
│   ├── PB-07-file-extraction.md        File carving, YARA scanning, artifact forensics
│   ├── PB-08-enrichment-ioc.md         IOC enrichment and infrastructure pivoting
│   ├── PB-09-anomaly-detection.md      ML/statistical baseline deviation hunting
│   ├── PB-10-c2-framework-detection.md Cobalt Strike, Sliver, Brute Ratel, Havoc, Mythic
│   ├── PB-11-ransomware.md             Ransomware network indicators and response
│   ├── PB-12-port-scan-recon.md        Port/host scan and reconnaissance detection
│   ├── PB-13-user-agent-hunt.md        Anomalous user-agent and HTTP pattern hunting
│   ├── PB-14-protocol-anomaly.md       Protocol violation and weird traffic detection
│   ├── PB-15-ioc-sweep.md             Retrospective IOC sweep playbook
│   └── PB-16-otrf-network-techniques.md  OTRF ThreatHunter-Playbook: 13 network-observable ATT&CK techniques
├── frameworks/
│   ├── hunt-methodology.md             Hunt process, hypothesis types, operationalization
│   ├── mitre-attck-network-mapping.md  All 14 ATT&CK tactics → network indicators
│   ├── frameworks-reference.md         ATT&CK, Kill Chain, Diamond, Pyramid of Pain, HMM
│   └── network-analytics-catalog.md   MITRE CAR (19 network analytics), Palantir ADS (5 templates), Red Canary top techniques
├── community-detections/
│   ├── elastic-network-rules.md        60 Elastic detection-rules network rules with ES|QL/KQL queries
│   ├── sigma-network-rules.md          53 SigmaHQ network rules (Zeek, DNS, firewall; 44 ATT&CK techniques)
│   ├── bzar-attck-zeek-analytics.md    MITRE BZAR Zeek package: DCE/RPC and SMB ATT&CK analytics
│   ├── falconforce-network-hunts.md    FalconForce FalconFriday: 10 network hunt translations (KQL → Zeek)
│   └── suricata-hunting-rules-community.md  travisbgreen/hunting-rules catalog + custom rule patterns
└── references/
    ├── rulesets-and-repos.md           Curated rulesets and GitHub repos
    ├── datasets-and-labs.md            Practice datasets and lab environments
    ├── sigma-network-rules.md          Full SigmaHQ network rule listing (21 Zeek rules, 7 DNS, 7 Fortinet…)
    └── sources.md                      All research sources with URLs
```

## Quick Reference: Choosing Your Starting Point

| I want to... | Start here |
|---|---|
| Understand what Zeek logs to hunt in | `skills/01-zeek-skills.md` |
| Hunt with Suricata rules and eve.json | `skills/02-suricata-skills.md` |
| Analyze a PCAP file for threats | `skills/03-pcap-analysis-skills.md` |
| Detect C2 beaconing | `playbooks/PB-01-c2-beaconing.md` |
| Hunt for lateral movement | `playbooks/PB-03-lateral-movement.md` |
| Hunt ATT&CK techniques with network artifacts (OTRF) | `playbooks/PB-16-otrf-network-techniques.md` |
| Identify a specific C2 framework | `playbooks/PB-10-c2-framework-detection.md` |
| Enrich a suspicious IP/domain | `playbooks/PB-08-enrichment-ioc.md` |
| Use Elastic ES\|QL network detection rules | `community-detections/elastic-network-rules.md` |
| Apply SigmaHQ Zeek rules (DCE/RPC, SMB, DNS, Kerberos) | `community-detections/sigma-network-rules.md` (via `references/`) |
| Use MITRE BZAR Zeek analytics | `community-detections/bzar-attck-zeek-analytics.md` |
| Deploy Suricata behavioral hunting rules | `community-detections/suricata-hunting-rules-community.md` |
| Translate Windows MDE hunts to Zeek | `community-detections/falconforce-network-hunts.md` |
| Use MITRE CAR / Palantir ADS analytics | `frameworks/network-analytics-catalog.md` |
| Map a finding to ATT&CK | `frameworks/mitre-attck-network-mapping.md` |
| Build or improve a hunt program | `frameworks/hunt-methodology.md` |
| Find practice datasets | `references/datasets-and-labs.md` |

## Key Principles

1. **Zeek answers "what happened"; Suricata answers "did anything known-bad happen?"** — run both.
2. **PCAP is ground truth** — convert to Zeek logs (`zeek -r capture.pcap`) or replay through Suricata (`suricata -r capture.pcap`) for retrospective analysis.
3. **Hypothesis first** — every hunt starts with a testable theory about adversary behavior, mapped to a specific ATT&CK technique.
4. **Enrich everything** — raw IOCs (IP, domain, hash) are low-signal until enriched through reputation, passive DNS, and certificate pivoting.
5. **Operationalize** — every successful hunt should produce a detection rule (Sigma, Suricata rule, Zeek script) that fires automatically next time.
