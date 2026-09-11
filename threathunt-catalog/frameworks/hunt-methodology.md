# Hunt Methodology

## The Threat Hunt Cycle

```
                    ┌─────────────────────────────────────┐
                    ▼                                     │
1. TRIGGER → 2. HYPOTHESIS → 3. DATA MAP → 4. QUERY → 5. ANALYZE
                                                           │
              8. OPERATIONALIZE ← 7. DOCUMENT ← 6. VALIDATE
```

### Step 1: Trigger

Sources that initiate a hunt:

| Trigger Type | Example |
|-------------|---------|
| **Threat Intelligence** | New IOC from vendor advisory, ISAC, or MISP feed |
| **Incident Spillover** | Hunt for same adversary TTPs seen in peer incident |
| **Anomaly Alert** | SIEM/NDR flags unusual traffic pattern for investigation |
| **Analyst Intuition** | "I haven't checked for X in a while" |
| **Compliance/Audit** | Required periodic hunt for specific ATT&CK techniques |
| **Crown Jewel Review** | Quarterly hunt focused on highest-value assets |
| **Threat Intelligence Report** | New threat actor profile with described TTPs |

### Step 2: Hypothesis Formulation

A hypothesis is a testable statement about specific adversary behavior:

**Template**: "If [threat actor or malware type] has [achieved goal], they will [perform action] which will [produce observable evidence] in [data source]."

**Examples:**
- "If a host is compromised with a Cobalt Strike beacon (sleeping 60 seconds), there will be periodic connections with <1s standard deviation in interval appearing in conn.log for port 443 connections."
- "If an attacker is using Pass-the-Hash for lateral movement, NTLM authentication will appear on connections between workstations that normally use Kerberos."
- "If data is being exfiltrated via DNS, dns.log will show > 200 unique subdomains to a single parent domain with individual query label lengths > 40 characters."

**Hypothesis quality criteria:**
- Specific to a technique (maps to ATT&CK)
- Has a clear observable (specific log field, specific threshold)
- Is falsifiable (can be confirmed OR denied)
- Uses available data sources

### Step 3: Data Source Mapping

Before querying, identify: what log captures the expected evidence?

| Evidence Type | Primary Source | Backup Source |
|---------------|---------------|---------------|
| Network connection | Zeek conn.log | Suricata flow, NetFlow |
| DNS query/response | Zeek dns.log | Suricata dns events |
| HTTP request/response | Zeek http.log | Suricata http events |
| TLS handshake | Zeek ssl.log | Suricata tls events |
| File transfer | Zeek files.log | Suricata fileinfo events |
| SMB access | Zeek smb_mapping.log | Suricata smb events |
| Kerberos auth | Zeek kerberos.log | Suricata krb5 events |
| Protocol violation | Zeek weird.log | Suricata anomaly events |
| Full session content | PCAP (Arkime) | Reconstructed from Zeek logs |

### Step 4: Query Execution

Write targeted queries against the primary data source:

**Query principles:**
- Start broad, narrow down iteratively
- Apply time range constraints early (reduces noise)
- Use frequency analysis to spot anomalies in large datasets
- Exclude known-good baseline before flagging
- Use multiple complementary queries for the same hypothesis

### Step 5: Analysis

**Techniques:**
- **Stack counting**: Count occurrences of each unique value in a field
- **Rarity scoring**: Flag values that appear < N times (rare = suspicious)
- **Time series analysis**: Plot event counts over time; flag spikes
- **Correlation**: Join multiple log types by uid/flow_id/IP/timestamp
- **Clustering**: Group similar activity patterns to find outliers
- **Statistical baseline comparison**: Compare to known-good period

**Decision point:**
- Confirmed hit → proceed to validation and response
- Uncertain → pivot to corroborating evidence
- Clean → document negative result (also valuable)

### Step 6: Validate / Triage

- Does the evidence match the hypothesis?
- Is there alternative innocent explanation?
- Corroborate with endpoint evidence (EDR, SIEM)
- Map confirmed findings to ATT&CK technique(s)
- Assign severity and priority

### Step 7: Document

Record ALL hunt results, including negative outcomes:

```markdown
## Hunt Report Template

**Hunt ID**: H-2026-001
**Date**: 2026-09-10
**Analyst**: [name]
**Trigger**: New Cobalt Strike IOC from ISAC alert
**Hypothesis**: CS beacon present in conn.log as periodic 60s connections to port 443

**Data Sources Used**: Zeek conn.log (2026-09-01 to 2026-09-10)
**Query Used**: [paste query]

**Result**: [POSITIVE / NEGATIVE / INCONCLUSIVE]
**Findings**: [describe what was found or not found]
**Affected Hosts**: [list if positive]
**ATT&CK Technique**: T1071.001 (Web Protocols)
**Severity**: [CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL]

**Response Actions Taken**: [list]
**Detection Rule Created**: [yes/no, rule name/SID]
**Escalated To**: [team/ticket]
```

### Step 8: Operationalize

Convert successful hunts into automated detections:

| Hunt Method | Automated Detection |
|------------|-------------------|
| Zeek script | Create scheduled zeek script / notice.log rule |
| tshark filter | Suricata rule (content/pcre match) |
| Behavioral pattern | Elastic ML job or Splunk search alert |
| IOC match | Add to threat intelligence feed / blocklist |
| Statistical analysis | RITA scheduled scan |

---

## Hunt Approaches

### 1. Hypothesis-Driven
- Start with analyst-formed theory based on TI or ATT&CK
- Query to validate or refute
- Most focused and efficient

### 2. IOC-Based
- Start with known-bad indicators (IP, domain, hash)
- Search historical data for matches
- Good for retroactive sweeps; misses novel attacks

### 3. Analytics-Driven / Anomaly-Based
- Apply statistical methods without pre-formed hypothesis
- Find statistical outliers in network behavior
- Catches novel attacks; generates more false positives

### 4. TTP-Based (MITRE-Driven)
- Systematically hunt each ATT&CK technique relevant to your threat profile
- Map each technique to available data sources
- Build hunt library covering priority techniques

---

## Hunt Program Maturity (Hunting Maturity Model)

| Level | Label | Capability |
|-------|-------|-----------|
| HMM0 | Initial | Hunt relies on automated alerts; no proactive hunting |
| HMM1 | Minimal | Hunt procedures exist; mostly IOC-based; ad hoc |
| HMM2 | Procedural | Documented hypothesis-driven procedures; regular cadence |
| HMM3 | Innovative | Custom analytics; some automation; data science integration |
| HMM4 | Leading | Machine learning integration; automated hypothesis generation; continuous hunting |

---

## Scheduling

| Hunt Type | Recommended Cadence |
|-----------|-------------------|
| IOC Sweep (from new TI) | Within 24 hours of IOC publication |
| Beaconing / C2 Hunt | Weekly |
| Lateral Movement Hunt | Monthly |
| Kerberos Attack Hunt | Quarterly |
| Data Exfiltration Hunt | Monthly |
| Full ATT&CK Coverage Sweep | Quarterly |
| Crown Jewel-Focused Hunt | Quarterly |
| Threat Actor TTP Hunt | As-needed (after new threat report) |
