# Rulesets & Repositories

## Suricata Rulesets

| Ruleset | Maintainer | URL | Cost | Focus |
|---------|-----------|-----|------|-------|
| **ET Open** | Proofpoint (Emerging Threats) | rules.emergingthreats.net | Free | Broad coverage: malware, exploits, C2, phishing |
| **ET Pro** | Proofpoint | pro.emergingthreats.net | Paid | ET Open + enhanced + faster updates |
| **OISF/suricata-update** | OISF | suricata.readthedocs.io/en/latest/rule-management | Free (tool) | Rule management; pulls from multiple free sources |
| **Secureworks CTU** | Secureworks | Via ET bundle | Free | Malware and targeted threat coverage |
| **Stamus Open Lateral Movement** | Stamus Networks | ti.stamus-networks.io/open | Free | Windows LotL and lateral movement techniques |
| **PAW Patrules** | Community | github.com/paulgb/patrules | Free | Suspicious flows, bad practices, tool detection |
| **travisbgreen/hunting-rules** | Travis Green | github.com/travisbgreen/hunting-rules | Free | Network anomaly hunting (non-signature approach) |
| **Abuse.ch Feodo** | Abuse.ch | feodotracker.abuse.ch/downloads | Free | Botnet/C2 IP blocklist in Suricata rule format |
| **SSL Blacklist (SSLBL)** | Abuse.ch | sslbl.abuse.ch | Free | Malicious TLS certificate blacklist |
| **URLhaus** | Abuse.ch | urlhaus.abuse.ch | Free | Malware distribution URL rules |

## Zeek Packages & Scripts

| Package | URL | Function |
|---------|-----|----------|
| **JA4+** | packages.zeek.org/packages/view/65d88958 | JA4/JA4S/JA4H/JA4SSH fingerprints |
| **JA3** | packages.zeek.org/packages/view/cebd1c8c | JA3/JA3S TLS client/server fingerprints |
| **zeek-EternalSafety** | github.com/lexibrent/zeek-EternalSafety | EternalBlue/SMB exploit detection |
| **Zeek-agent** | github.com/zeek/zeek-agent | Host activity monitoring |
| **Loginsoft-Research/zeek-scripts** | github.com/Loginsoft-Research/zeek-scripts | CVE detection and threat hunt scripts |
| **Canon88/zeek-threathunting** | github.com/Canon88/zeek-threathunting | Intel framework + Kafka integration |
| **community-id** | github.com/corelight/zeek-community-id | Community ID flow hash for cross-tool correlation |
| **zeek-quic** | github.com/mozilla/zeek-quic | QUIC protocol analysis |

## Detection Rule Repositories (Sigma / Generic)

| Repo | URL | Contents |
|------|-----|----------|
| **SigmaHQ/sigma** | github.com/SigmaHQ/sigma | 3000+ generic SIEM detection rules |
| **OTRF/ThreatHunter-Playbook** | github.com/OTRF/ThreatHunter-Playbook | Jupyter notebooks + Sigma + ATT&CK |
| **Elastic/detection-rules** | github.com/elastic/detection-rules | Elastic-native detection content |
| **Splunk/security-content** | github.com/splunk/security-content | Splunk detection rules + analytics stories |
| **MITRE/CAR** | car.mitre.org | ATT&CK Cyber Analytics Repository |
| **Chronicle YARA-L rules** | chronicle.security/detection-rules | Google Chronicle detection rules |

## YARA Rule Sources

| Repo | URL | Focus |
|------|-----|-------|
| **Neo23x0/signature-base** | github.com/Neo23x0/signature-base | Florian Roth's comprehensive malware rules |
| **Yara-Rules/rules** | github.com/Yara-Rules/rules | Community YARA rule collection |
| **reversinglabs/reversinglabs-yara-rules** | github.com/reversinglabs/reversinglabs-yara-rules | Commercial-grade YARA from ReversingLabs |
| **CAPE/CAPEv2** | github.com/kevoreilly/CAPEv2 | Sandbox-generated YARA rules |
| **Elastic/protections-artifacts** | github.com/elastic/protections-artifacts | Elastic YARA rules |

## Threat Intelligence Repositories

| Source | URL | IOC Type |
|--------|-----|----------|
| **Abuse.ch MalwareBazaar** | bazaar.abuse.ch | Malware file hashes |
| **Abuse.ch ThreatFox** | threatfox.abuse.ch | IOCs (IP, URL, domain, hash) |
| **AlienVault OTX** | otx.alienvault.com | Pulses with multiple IOC types |
| **MISP Project** | misp-project.org | Structured TI (STIX/TAXII) |
| **OpenCTI** | opencti.io | Graph-based CTI platform |
| **Feodo Tracker** | feodotracker.abuse.ch | Botnet C2 IP blocklists |
| **PhishTank** | phishtank.org | Phishing URLs |
| **URLhaus** | urlhaus.abuse.ch | Malware distribution URLs |
| **Ransomware Tracker** | abuse.ch (various) | Ransomware C2 and payment sites |

## Practice PCAP & Dataset Repositories

| Source | URL | Contents |
|--------|-----|----------|
| **Malware Traffic Analysis** | malware-traffic-analysis.net | Real malware PCAPs with analysis writeups |
| **PCAP-ATTACK** | github.com/sbousseaden/PCAP-ATTACK | Network captures mapped to ATT&CK techniques |
| **Mordor Project** | github.com/OTRF/mordor | Pre-recorded adversarial event datasets |
| **BOTS v1-v3** | github.com/splunk/botsv1, botsv2, botsv3 | Splunk Boss of the SOC CTF datasets |
| **CIC Datasets** | unb.ca/cic/datasets | Canadian Institute for Cybersecurity network datasets |
| **Stratosphere IPS** | stratosphereips.org/datasets | Labeled network traffic datasets |
| **CTF Network Challenges** | ctftime.org | Competition challenges often include PCAP |
| **PacketTotal** | packettotal.com | PCAP sharing and analysis platform |
| **Wireshark Sample Captures** | wiki.wireshark.org/SampleCaptures | Sample PCAPs for many protocols |

## C2 Framework Detection Resources

| Resource | URL | Contents |
|----------|-----|----------|
| **C2-Profiler** | github.com/mazen91111/C2-Profiler | C2 framework identification from PCAP |
| **Hive Security CS Blog** | hivesecurity.gitlab.io/blog/cobalt-strike-detection-hunting | CS detection playbook |
| **DFIR Report** | thedfirreport.com | Ransomware/APT case studies with network IOCs |
| **JARM** | github.com/salesforce/jarm | TLS server fingerprinting tool |
| **JA3** | github.com/salesforce/ja3 | TLS client fingerprinting |
| **JA4+** | github.com/FoxIO-LLC/ja4 | Improved fingerprinting family |
