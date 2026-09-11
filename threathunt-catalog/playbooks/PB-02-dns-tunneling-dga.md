# PB-02: DNS Tunneling & DGA Detection

**ATT&CK**: T1071.004 (DNS), T1568.002 (Domain Generation Algorithms), T1048.003 (Exfiltration Over Alternative Protocol)
**Data Sources**: Zeek dns.log, Suricata dns events, network PCAP
**Tools**: Zeek, tshark, Python (dnspython, scipy), RITA

## Hypothesis A: DNS Tunneling

An attacker is encoding data in DNS query subdomains or TXT record responses to exfiltrate data or maintain C2 without triggering web proxy or HTTPS inspection.

### Detection: Long Subdomain Queries

```bash
# Zeek: find DNS queries with excessively long labels (>50 chars)
zeek-cut query < dns.log | awk '{
    n = split($1, parts, ".");
    for (i=1; i<=n; i++) {
        if (length(parts[i]) > 50) {
            print $1
        }
    }
}' | sort | uniq -c | sort -rn | head -20
```

```python
# Python: Calculate DNS query entropy and length
import math, re
from collections import Counter

def entropy(s):
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

with open('dns.log') as f:
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 10: continue
        query = fields[9]  # query field
        subdomain = query.split('.')[0]
        if len(subdomain) > 30 and entropy(subdomain) > 3.5:
            print(f"Suspicious: {query} (entropy={entropy(subdomain):.2f}, len={len(subdomain)})")
```

### Detection: High Volume of Unique Subdomains to Single Parent

```bash
# Find domains with >100 unique subdomains queried
zeek-cut query < dns.log | awk -F'.' '{
    # Extract parent domain (last 2 labels)
    n = NF; parent = $(n-1)"."$n
    subs[parent]++
} END {
    for (p in subs) if (subs[p] > 100) print subs[p], p
}' | sort -rn | head -20
```

### Detection: TXT/NULL Record Query Anomalies

```bash
# Flag TXT queries from workstations (unusual for normal traffic)
zeek-cut id.orig_h qtype_name query < dns.log | awk -F'\t' '$2=="TXT" || $2=="NULL" {print}' \
  | sort | uniq -c | sort -rn | head -20

# tshark equivalent
tshark -r cap.pcap -Y 'dns.qry.type == 16' -T fields -e ip.src -e dns.qry.name \
  | sort | uniq -c | sort -rn | head -20
```

### Detection: Unusually Large DNS Response Payloads

```bash
# Zeek: flag DNS responses with large answer fields
zeek-cut query answers < dns.log | awk '{
    if (length($2) > 200) print length($2), $1
}' | sort -rn | head -20
```

### Detection: jq (Suricata eve.json)

```bash
# Long subdomain queries
jq -r 'select(.event_type=="dns") | .dns.rrname' eve.json | \
  awk '{sub(/\..+/, "", $0); if(length($0) > 40) print}' | sort | uniq -c | sort -rn

# TXT queries
jq 'select(.event_type=="dns") | select(.dns.rrtype=="TXT")' eve.json | head -20

# High subdomain volume per parent domain
jq -r 'select(.event_type=="dns") | .dns.rrname' eve.json | \
  awk -F. '{parent=$(NF-1)"."$NF; print parent}' | sort | uniq -c | sort -rn | head -20
```

---

## Hypothesis B: Domain Generation Algorithm (DGA)

Malware is using a DGA to generate many random-looking domain names; it resolves them until it finds one registered by the attacker. This creates a burst of NXDomain responses and high-entropy domain queries.

### Detection: NXDomain Burst

```bash
# Zeek: count NXDomain responses per src per time bucket
zeek-cut ts id.orig_h rcode_name < dns.log | awk -F'\t' '
  $3=="NXDOMAIN" {
    bucket = int($1/300)*300  # 5-minute buckets
    key = bucket"\t"$2
    count[key]++
  }
  END {
    for (k in count) if (count[k] > 50) print count[k], k
  }
' | sort -rn | head -20
```

### Detection: Domain Entropy Analysis

```python
import math, csv
from collections import Counter, defaultdict

def entropy(s):
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

dga_candidates = defaultdict(int)

with open('dns.log') as f:
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 10: continue
        query = fields[9]
        rcode = fields[13] if len(fields) > 13 else ''
        
        labels = query.split('.')
        if len(labels) < 2: continue
        
        # Analyze the subdomain portion
        subdomain = labels[0]
        ent = entropy(subdomain)
        
        # Flag: high entropy + NXDOMAIN + no vowels OR all hex chars
        no_vowels = not any(c in 'aeiou' for c in subdomain.lower())
        if ent > 3.5 and (rcode == 'NXDOMAIN' or no_vowels):
            parent = '.'.join(labels[-2:])
            dga_candidates[parent] += 1

# Report candidates
for domain, count in sorted(dga_candidates.items(), key=lambda x: -x[1]):
    if count > 5:
        print(f"{count:4d}  {domain}")
```

### Detection: Consonant Ratio (DGA heuristic)

```python
def consonant_ratio(domain):
    label = domain.split('.')[0].lower()
    consonants = sum(1 for c in label if c.isalpha() and c not in 'aeiou')
    return consonants / len(label) if label else 0

# DGA domains tend to have consonant ratio > 0.6
```

### RITA for DGA/DNS Tunneling

```bash
rita show-dns-fqdns my-dataset | head -50
# Columns: Score, Unique Subdomains, Times Looked Up, Proxied, Queried, Blocker

# Focus on entries with:
# - Score close to 1.0
# - Many unique subdomains
# - Unusual parent domain
```

## Behavioral Indicators

| Indicator | DGA | DNS Tunnel |
|-----------|-----|-----------|
| High entropy subdomains (>3.5) | ✓ | ✓ |
| NXDomain burst (>50/5 min) | ✓ | Possible |
| Subdomain length > 50 chars | - | ✓ |
| >100 unique subdomains to one parent | ✓ | ✓ |
| TXT/NULL record queries | - | ✓ |
| Large DNS response payloads | - | ✓ |
| No vowels in subdomain | ✓ | Possible |
| Only queried once (no repeat) | ✓ | - |
| Very short DNS TTL | ✓ (fast flux) | - |

## Response

1. Block parent domain at DNS sinkhole or firewall
2. Review all hosts that queried the suspicious domain
3. For DNS tunnel: carve encoded payload from DNS TXT answers and decode
4. Identify malware family (domain seeds, DGA algorithm) for scope assessment
5. Check for other indicators of compromise on affected hosts

## Sources

- [SOC Investigation — Zeek Log Types](https://www.socinvestigation.com/threat-hunting-with-zeek-log-types-and-use-cases/)
- [RITA GitHub](https://github.com/activecm/rita)
- [DNS Tunneling Threat Landscape (arxiv)](https://arxiv.org/pdf/2507.10267)
- [Fine-tuning LLMs for DGA Detection (arxiv)](https://arxiv.org/pdf/2410.21723)
