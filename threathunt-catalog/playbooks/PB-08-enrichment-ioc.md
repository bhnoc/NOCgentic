# PB-08: IOC Enrichment & Infrastructure Pivoting

**ATT&CK**: Supporting all tactics — enrichment converts raw IOCs to attribution/scope
**Data Sources**: Threat intelligence APIs, passive DNS, certificate transparency, OSINT
**Tools**: MISP, Intel Owl, VirusTotal, Shodan, Censys, PassiveDNS, jq, Python

## Overview

Raw IOCs (IP, domain, hash, URL) are low-signal until enriched. This playbook converts a single IOC into a complete adversary infrastructure picture.

---

## Enrichment Workflow

```
Single IOC
  ├── Reputation check → is this known-bad?
  ├── Historical context → what has this IOC been associated with?
  ├── Infrastructure mapping → what else is this IP/domain connected to?
  ├── Attribution pivot → what threat actor or malware family?
  ├── Timeline → when was this active? Still active?
  └── Confidence score → act on hunt/block decision
```

---

## IOC Type: IP Address

```bash
# 1. Basic reputation
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90&verbose" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | \
  jq '{score: .data.abuseConfidenceScore, isp: .data.isp, country: .data.countryCode, reports: .data.totalReports}'

# 2. VirusTotal
curl -s "https://www.virustotal.com/api/v3/ip_addresses/$IP" \
  -H "x-apikey: $VT_KEY" | \
  jq '{malicious: .data.attributes.last_analysis_stats.malicious,
       harmless: .data.attributes.last_analysis_stats.harmless,
       country: .data.attributes.country,
       asn: .data.attributes.asn,
       as_owner: .data.attributes.as_owner}'

# 3. Shodan
curl -s "https://api.shodan.io/shodan/host/$IP?key=$SHODAN_KEY" | \
  jq '{ports: .ports, org: .org, isp: .isp, hostnames: .hostnames, vulns: .vulns}'

# 4. GreyNoise (is it internet noise or targeted?)
curl -s "https://api.greynoise.io/v3/community/$IP" \
  -H "key: $GREYNOISE_KEY" | \
  jq '{classification: .classification, noise: .noise, riot: .riot, name: .name}'

# 5. Passive DNS — what domains has this IP hosted?
curl -s "https://api.circl.lu/pdns/query/$IP" | \
  jq '.[] | {rrname: .rrname, rrtype: .rrtype, time_first: .time_first, time_last: .time_last}'
```

---

## IOC Type: Domain

```bash
# 1. VirusTotal domain report
curl -s "https://www.virustotal.com/api/v3/domains/$DOMAIN" \
  -H "x-apikey: $VT_KEY" | \
  jq '{malicious: .data.attributes.last_analysis_stats.malicious,
       registrar: .data.attributes.registrar,
       creation_date: .data.attributes.creation_date,
       categories: .data.attributes.categories}'

# 2. WHOIS lookup
whois "$DOMAIN" | grep -E 'Registrar:|Created:|Updated:|Expiry:|Name Server:|Registrant'

# 3. DNS history (passive DNS)
curl -s "https://api.circl.lu/pdns/query/$DOMAIN" | \
  jq '.[] | {rdata: .rdata, rrtype: .rrtype, time_first: .time_first}' | head -20

# 4. Certificate transparency — find all certs for this domain
curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
  jq '.[].name_value' | sort -u | head -30

# 5. URLScan.io
curl -s "https://urlscan.io/api/v1/search/?q=domain:$DOMAIN" \
  -H "API-Key: $URLSCAN_KEY" | \
  jq '.results[0] | {url: .page.url, ip: .page.ip, country: .page.country, malicious: .verdicts.overall.malicious}'
```

---

## IOC Type: File Hash

```bash
# 1. VirusTotal
curl -s "https://www.virustotal.com/api/v3/files/$HASH" \
  -H "x-apikey: $VT_KEY" | \
  jq '{name: .data.attributes.meaningful_name,
       malicious: .data.attributes.last_analysis_stats.malicious,
       family: .data.attributes.popular_threat_classification.suggested_threat_label,
       type: .data.attributes.type_description,
       size: .data.attributes.size,
       first_seen: .data.attributes.first_submission_date}'

# 2. MalwareBazaar
curl -s -X POST "https://mb-api.abuse.ch/api/v1/" \
  -d "query=get_info&hash=$HASH" | \
  jq '{signature: .data[0].signature, tags: .data[0].tags, 
       file_type: .data[0].file_type, first_seen: .data[0].first_seen}'

# 3. Hybrid Analysis
curl -s "https://www.hybrid-analysis.com/api/v2/search/hash" \
  -H "api-key: $HA_KEY" \
  -d "hash=$HASH" | \
  jq '.[0] | {verdict: .verdict, threat_score: .threat_score, 
              threat_level: .threat_level, environment: .environment_id}'
```

---

## Infrastructure Pivoting Playbook

Given one IOC, expand to full adversary infrastructure:

```
Step 1: IP → Passive DNS → All domains that resolved to this IP
Step 2: Domain → TLS cert → Certificate fingerprint
Step 3: Cert fingerprint → Certificate search (Censys/Shodan) → All IPs hosting same cert
Step 4: Server → JARM hash → All servers with same TLS server fingerprint
Step 5: Domain registration → WHOIS email/org → All domains registered by same registrant
Step 6: ASN → IP range → Other IPs in same autonomous system
Step 7: Document all nodes → Map adversary infrastructure cluster
```

```python
import requests, json

VT_KEY = "your_vt_api_key"
SHODAN_KEY = "your_shodan_key"

def pivot_ip(ip):
    print(f"\n=== Pivoting on IP: {ip} ===")
    
    # Step 1: Get all domains that resolved to this IP (passive DNS)
    r = requests.get(f"https://api.circl.lu/pdns/query/{ip}")
    domains = list(set([entry['rrname'].rstrip('.') for entry in r.json()]))
    print(f"Domains resolved to {ip}: {domains[:10]}")
    
    # Step 2: Get Shodan info (ports, org, certs)
    r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}")
    if r.status_code == 200:
        data = r.json()
        print(f"Shodan: org={data.get('org')}, ports={data.get('ports')}")
        # Extract SSL cert subjects if available
        for item in data.get('data', []):
            if 'ssl' in item:
                print(f"  SSL Subject: {item['ssl'].get('cert', {}).get('subject', {})}")
    
    return domains

def pivot_domain(domain):
    print(f"\n=== Pivoting on domain: {domain} ===")
    
    # Get cert transparency records
    r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
    if r.status_code == 200:
        certs = r.json()
        related = list(set([c['name_value'] for c in certs]))
        print(f"Related domains from crt.sh: {related[:20]}")
    
    # Passive DNS for IPs
    r = requests.get(f"https://api.circl.lu/pdns/query/{domain}")
    ips = list(set([entry['rdata'] for entry in r.json() if entry['rrtype'] == 'A']))
    print(f"IPs for {domain}: {ips}")
    
    return ips
```

---

## Bulk IOC Sweep Against Network Logs

```bash
# Given a list of known-bad IPs/domains, sweep Zeek logs for hits

# Create IOC lists
cat > /tmp/bad_ips.txt << 'EOF'
1.2.3.4
5.6.7.8
10.20.30.40
EOF

cat > /tmp/bad_domains.txt << 'EOF'
evil.example.com
c2server.badguy.net
malware.download.io
EOF

# Sweep conn.log for bad IPs
echo "=== IP hits in conn.log ==="
zeek-cut id.orig_h id.resp_h < conn.log | \
  grep -Ff /tmp/bad_ips.txt | sort | uniq -c | sort -rn

# Sweep dns.log for bad domains
echo "=== Domain hits in dns.log ==="
zeek-cut id.orig_h query < dns.log | \
  grep -Ff /tmp/bad_domains.txt | sort | uniq -c | sort -rn

# Sweep http.log for bad domains
echo "=== Domain hits in http.log ==="
zeek-cut id.orig_h host < http.log | \
  grep -Ff /tmp/bad_domains.txt | sort | uniq -c | sort -rn

# Sweep files.log for bad hashes
echo "=== Hash hits in files.log ==="
cat /tmp/bad_hashes.txt | while read hash; do
  zeek-cut id.orig_h id.resp_h md5 sha256 < files.log | grep -i "$hash"
done
```

---

## MISP Integration

```python
from pymisp import PyMISP

misp = PyMISP("https://misp.your-org.com", "your_auth_key", False)

# Search for IOC
results = misp.search('attributes', value='1.2.3.4')
for attr in results:
    print(f"Event: {attr['Event']['info']}, Type: {attr['type']}, Comment: {attr['comment']}")

# Add new IOC to MISP event
event = misp.get_event(event_id)
attr = {'type': 'ip-dst', 'value': '1.2.3.4', 'comment': 'C2 from APE-743 hunt',
        'to_ids': True, 'distribution': 0}
misp.add_attribute(event, attr)
```

---

## Intel Owl (Self-Hosted OSINT Aggregator)

```bash
# Intel Owl analyzes IP, domain, URL, hash in parallel across 50+ services
# Deploy: docker-compose up

# Via API
curl -X POST "http://localhost:80/api/analyze_observable" \
  -H "Authorization: Token $INTEL_OWL_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "observable_name": "1.2.3.4",
    "observable_classification": "ip",
    "analyzers_requested": ["AbuseIPDB", "Shodan_Honeyscore", "VirusTotal_v3_Get_Observable",
                             "GreyNoiseCommunity", "MISP", "OTXQuery"]
  }'
```

---

## Enrichment Sources Quick Reference

| Source | Data Type | Free Tier | API |
|--------|-----------|-----------|-----|
| VirusTotal | Hash/IP/Domain/URL reputation | 4 req/min | Yes |
| AbuseIPDB | IP reputation + reports | 1000/day | Yes |
| Shodan | Internet-facing services + banners | Limited | Yes |
| Censys | TLS certs + infrastructure | Limited | Yes |
| AlienVault OTX | Community TI pulses | Unlimited | Yes |
| CIRCL Passive DNS | Historical DNS | Unlimited | Yes |
| crt.sh | Certificate transparency | Unlimited | Yes (JSON) |
| URLScan.io | URL/domain behavioral scan | 100/day | Yes |
| GreyNoise | Internet noise classification | 50/day | Yes |
| MalwareBazaar | Malware hash info | Unlimited | Yes |
| Hybrid Analysis | File sandbox results | 200/day | Yes |
| MISP | Community IOC sharing | Self-hosted | Yes |
| Intel Owl | Multi-source aggregation | Self-hosted | Yes |

## Sources

- [IOC Pivoting Playbook (cyberyatra, Medium)](https://cyberyatra.medium.com/the-threat-hunters-intel-iocs-pivoting-playbook-expanding-a-single-ioc-into-a-full-infrastructure-2aa74c0152e8)
- [My IOC Enrichment Workflow (Medium)](https://medium.com/@palupidyahr/my-ioc-enrichment-workflow-c3bad78298aa)
- [Intel Owl Project](https://github.com/intelowlproject/IntelOwl)
- [MISP Project](https://www.misp-project.org/)
