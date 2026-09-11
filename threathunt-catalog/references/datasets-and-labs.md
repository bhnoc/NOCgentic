# Datasets & Lab Environments

## Practice Datasets (PCAP)

| Dataset | Source | Content | ATT&CK Mapped |
|---------|--------|---------|----------------|
| **Malware Traffic Analysis** | malware-traffic-analysis.net | Real malware infection chains, weekly updates | Partial |
| **PCAP-ATTACK** | github.com/sbousseaden/PCAP-ATTACK | Captures specifically tied to ATT&CK techniques | Yes |
| **Stratosphere IPS Datasets** | stratosphereips.org/datasets | Labeled malware C2 traffic captures | Yes |
| **Wireshark Sample Captures** | wiki.wireshark.org/SampleCaptures | Protocol examples for learning | No |
| **PacketLife** | packetlife.net/captures | Protocol analysis samples | No |
| **NETRESEC** | netresec.com/?page=PcapFiles | Curated list of PCAP repositories | Various |
| **CIC-IDS-2017** | unb.ca/cic/datasets/ids-2017.html | Full week of simulated attack traffic + benign | No |
| **UNSW-NB15** | research.unsw.edu.au/projects/unsw-nb15-dataset | Network traffic with labeled attack categories | No |

## Structured Event Datasets (Non-PCAP)

| Dataset | Source | Format | Content |
|---------|--------|--------|---------|
| **Mordor** | github.com/OTRF/mordor | JSON | Pre-recorded Windows + network adversarial events |
| **EVTX-ATTACK-SAMPLES** | github.com/sbousseaden/EVTX-ATTACK-SAMPLES | EVTX | Windows event logs for ATT&CK techniques |
| **BOTS v1** | github.com/splunk/botsv1 | Splunk index | APT campaign simulation |
| **BOTS v2** | github.com/splunk/botsv2 | Splunk index | Multiple threat scenarios |
| **BOTS v3** | github.com/splunk/botsv3 | Splunk index | Cloud + on-prem scenarios |
| **SecRepo.com** | secrepo.com | Various | Security-related sample data collection |
| **EMBER** | github.com/endgameinc/ember | JSON | PE file features for ML models |

## Lab Environments

### Self-Hosted

| Lab | URL | Stack | Best For |
|-----|-----|-------|----------|
| **Security Onion** | securityonion.net | Zeek + Suricata + Elastic + Kibana | Learning full NSM workflow |
| **DetectionLab** | github.com/celeryhappy/DetectionLab | Windows AD + Zeek + Suricata + Splunk | Windows lateral movement hunting |
| **HELK** | github.com/Cyb3rWard0g/HELK | ELK + Spark + Jupyter | ML-based threat hunting |
| **SELKS** | github.com/StamusNetworks/SELKS | Suricata + ELK + Arkime | Suricata + full packet |
| **Arkime** | arkime.com | Full PCAP store | Large-scale PCAP hunting |
| **BlueTeam Lab** | github.com/op7ic/BlueTeamLab | Azure | Cloud-based detection lab |
| **Attack Range** | github.com/splunk/attack-range | Splunk | Splunk-native detection testing |
| **Vulnerable VM** | vulnhub.com | Various | Practice environments |

### Cloud-Based / Managed

| Platform | URL | Cost | Notes |
|---------|-----|------|-------|
| **TryHackMe** | tryhackme.com | Freemium | Guided rooms: Zeek, Wireshark, NetworkMiner |
| **HackTheBox Academy** | academy.hackthebox.com | Freemium | SOC analyst path, RITA C2 module |
| **LetsDefend** | letsdefend.io | Freemium | SOC analyst simulation with real cases |
| **CyberDefenders** | cyberdefenders.org | Free/Paid | PCAP analysis challenges |
| **Blue Team Labs Online** | blueteamlabs.online | Freemium | Incident response challenges |
| **RangeForce** | rangeforce.com | Paid | Team-based security training |

## Specific Learning Paths

### Zeek
- TryHackMe: "Zeek" room (hands-on with zeek-cut and log analysis)
- HackTheBox Academy: Network Analysis module
- Applied Network Defense: zeek.org training resources
- SANS FOR572 with Zeek labs

### Suricata
- Stamus Networks: "The Security Analyst's Guide to Suricata" (free book)
- Kaspersky XTraining: Suricata for Incident Response and Threat Hunting course
- TryHackMe: "Snort" room (uses Suricata-compatible rule syntax)
- BsidesMunich 2019: Threat Hunting with Suricata workshop materials

### PCAP Analysis
- CyberDefenders: All PCAP-based challenges (filter by "network forensics")
- Malware Traffic Analysis: Read existing writeups, then try unguided
- SANS FOR572: Best structured curriculum
- Wireshark University: wireshark.org/docs/wsug_html_chunked

### Threat Hunting General
- SANS SEC555: SIEM with Tactical Analytics
- SANS FOR508: Advanced Incident Response (includes network)
- OTX/MISP practice: Set up free account, pull feeds, hunt on your own traffic
- MITRE ATT&CK training: attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/

## Threat Simulation Tools (Generate Your Own Hunt Data)

| Tool | URL | Function |
|------|-----|----------|
| **Atomic Red Team** | github.com/redcanaryco/atomic-red-team | Per-ATT&CK-technique tests |
| **MITRE CALDERA** | github.com/mitre/caldera | Automated adversary emulation |
| **Network Flight Simulator** | github.com/alphasoc/flightsim | Generates malicious network traffic patterns |
| **APTSimulator** | github.com/NextronSystems/APTSimulator | Windows compromise simulation |
| **PurpleSharp** | github.com/mvelazc0/PurpleSharp | AD attack simulation |
| **Invoke-AtomicRedTeam** | github.com/redcanaryco/invoke-atomicredteam | PowerShell wrapper for Atomic Red Team |
| **Infection Monkey** | github.com/guardicore/monkey | Breach and attack simulation |
