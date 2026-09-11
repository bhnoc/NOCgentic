# Threat Hunting Tools Ecosystem

## Network Capture & Analysis

| Tool | Role | Notes |
|------|------|-------|
| **Zeek** | Network Security Monitor | Event-driven; produces structured logs; behavior-based |
| **Suricata** | IDS/IPS/NSM | Signature + protocol logging; real-time alerting |
| **Snort 3** | IDS/IPS | Original NIDS; Suricata-compatible ruleset subset |
| **Arkime** (Moloch) | Full PCAP store + search | Indexed PCAP; search by IP/port/protocol; 10+ Gbps |
| **Stenographer** | Full PCAP capture | BPF-filtered retrieval by time/IP/port |
| **ntopng** | Flow monitoring | Real-time web dashboard for traffic |
| **VAST** | Network telemetry | High-performance analytics engine |
| **Corelight** | Commercial Zeek platform | Enterprise Zeek with enhanced packages + TI |
| **Stamus Networks SC5K** | Commercial Suricata platform | Enterprise SELKS with threat intel integration |

## Hunt Platforms & Stacks

| Stack | Components | Deployment |
|-------|-----------|-----------|
| **Security Onion 2** | Zeek + Suricata + Elastic + Kibana + Wazuh + Velociraptor | All-in-one Linux distro |
| **SELKS** | Suricata + Elastic + Logstash + Kibana + Scirius + Arkime | Debian-based; Docker or bare metal |
| **HELK** | Elastic + Logstash + Kibana + Spark + Jupyter | Analytics/ML-focused |
| **DetectionLab** | Full Windows AD lab with Zeek + Suricata + Elastic | Vagrant/Packer; local VM |
| **BlueTeam Lab** | Azure-based detection lab | Cloud; realistic environment |
| **Attack Range** | Splunk + vulnerable targets | Splunk-native |
| **Malware Traffic Analysis** | PCAP practice site | Real malware PCAPs for practice |

## C2 / Beaconing Detection Tools

| Tool | Function |
|------|----------|
| **RITA** | Statistical beaconing + DNS tunneling detection from Zeek logs |
| **AC-Hunter** | Commercial RITA with enterprise UI (Active Countermeasures) |
| **C2-Profiler** | Fingerprints Cobalt Strike/Sliver/Havoc/Brute Ratel from PCAP |
| **Brim** | ZQL-based PCAP + Zeek log analysis desktop app |
| **JA4+** | TLS/HTTP/SSH fingerprinting; available as Zeek package |
| **JARM** | Active TLS server fingerprinting |

## PCAP Analysis Tools

| Tool | Function |
|------|----------|
| **Wireshark** | GUI packet inspector |
| **tshark** | CLI packet inspector / field extractor |
| **tcpdump** | Capture + BPF filtering |
| **NetworkMiner** | Passive artifact extraction (files, creds, images) |
| **tcpflow** | TCP stream reassembly |
| **pcapfex** | File carving from PCAP |
| **Scapy** | Python packet crafting/parsing |
| **pyshark** | Python tshark wrapper |
| **Xplico** | Network forensics reconstruction tool |
| **YaraPCAP** | Apply YARA to HTTP content extracted from PCAP |
| **ngrep** | Content grep across PCAP |
| **chaosreader** | Session reconstruction to HTML/files |

## File Analysis & Malware Detection

| Tool | Function |
|------|----------|
| **YARA** | Pattern matching in files/memory/network extractions |
| **Capa** | Identifies capabilities in executable files |
| **ClamAV** | Open-source AV for scanning carved files |
| **Remnux** | Linux distro for malware analysis |
| **Any.run / Joe Sandbox / Cuckoo** | Dynamic sandbox analysis |
| **VirusTotal** | Multi-AV file/URL/IP/domain lookup |

## Threat Intelligence & Enrichment

| Tool | Function |
|------|----------|
| **MISP** | Threat intelligence sharing platform (STIX/TAXII) |
| **OpenCTI** | Structured CTI graph with ATT&CK integration |
| **Intel Owl** | OSINT aggregation — IP, domain, hash, all at once |
| **Shodan** | Internet-facing service fingerprinting + banner data |
| **Censys** | TLS certificate search + infrastructure mapping |
| **AlienVault OTX** | Community threat intelligence pulses and IOCs |
| **AbuseIPDB** | Crowdsourced IP abuse reporting |
| **GreyNoise** | Internet background noise vs targeted activity classification |
| **URLScan.io** | URL and domain behavioral scanning |
| **PassiveDNS (CIRCL)** | Historical DNS resolution database |
| **Threat Bus** | TI dissemination layer connecting tools |

## Endpoint Visibility (for correlation)

| Tool | Function |
|------|----------|
| **osquery** | SQL-based OS telemetry — cross-platform |
| **Velociraptor** | Endpoint collection, hunt orchestration, VQL queries |
| **Sysmon** | Windows detailed event logging (process, network, file, registry) |
| **OSSEC / Wazuh** | Host-based IDS with network correlation |
| **DeepBlueCLI** | PowerShell module for Windows event log hunting |
| **CimSweep** | CIM/WMI-based incident response |

## Detection Rule Management

| Tool | Function |
|------|----------|
| **sigmac / pySigma** | Convert Sigma rules to SIEM-specific query format |
| **suricata-update** | Rule management tool for Suricata |
| **Elastic Detection Rules** | Community detection library for Elastic |
| **Splunk Security Essentials** | Detection content for Splunk |
| **MITRE CAR** | Cyber Analytics Repository (framework-agnostic) |
| **MITRE ATT&CK Navigator** | Visual ATT&CK coverage mapping |

## Threat Simulation (Validate Detections)

| Tool | Function |
|------|----------|
| **MITRE CALDERA** | Automated adversary emulation (ATT&CK mapped) |
| **Atomic Red Team** | Per-technique portable test scripts |
| **APTSimulator** | Windows compromise simulation (batch) |
| **Network Flight Simulator** | Generate malicious network traffic patterns |
| **Infection Monkey** | Breach and attack simulation |
| **PurpleSharp** | Active Directory attack simulation |
| **Invoke-AtomicRedTeam** | PowerShell wrapper for Atomic Red Team |

## Log Management & SIEM

| Platform | Notes |
|---------|-------|
| **Elasticsearch + Kibana** | Open-source; core of Security Onion, SELKS, HELK |
| **Splunk** | Industry-leading SIEM with SPL |
| **Microsoft Sentinel** | Cloud-native SIEM with KQL |
| **Google Chronicle** | Cloud SIEM with YARA-L and UDM |
| **Graylog** | Open-source log management |
| **Elastic SIEM** | Built into Elasticsearch; detection rules library |

## Community Playbook Repositories

| Repo | Contents |
|------|----------|
| **OTRF/ThreatHunter-Playbook** | Jupyter notebooks + Sigma + ATT&CK mappings |
| **SigmaHQ/sigma** | Thousands of generic SIEM detection rules |
| **travisbgreen/hunting-rules** | Suricata network anomaly rules |
| **0x4D31/awesome-threat-detection** | Curated resource list (tools, datasets, frameworks) |
| **mitre/cti** | STIX bundles of all ATT&CK data |
| **ElasticSearch/detection-rules** | Elastic-native detection content |
| **Florianpiry/suricata-threat-hunting** | Suricata-specific hunting rules |
| **Loginsoft-Research/zeek-scripts** | Zeek CVE and threat hunting scripts |
