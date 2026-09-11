# PB-09: Anomaly Detection (Statistical & ML-Based)

**ATT&CK**: Supporting detection across all tactics — anomaly methods catch novel, uncatalogued techniques
**Data Sources**: Zeek conn.log, dns.log, http.log; NetFlow; Suricata flow events
**Tools**: Python (pandas, scikit-learn, scipy), RITA, Corelight, Elastic ML, Zeek

## Overview

Signature-based detection fails against novel, custom, or modified attacks. Anomaly detection establishes what "normal" looks like and flags statistical deviations — catching threats that have no known signatures.

81% of "hands-on-keyboard" intrusions in 2025 are malware-free (CrowdStrike), making behavioral/anomaly detection essential.

---

## Method 1: Stack Counting / Frequency Analysis

The most practical starting point — find rare values in a field where most values are common.

```python
import pandas as pd
from collections import Counter

# Load Zeek http.log
df = pd.read_csv('http.log', sep='\t', comment='#',
    names=['ts','uid','orig_h','orig_p','resp_h','resp_p','trans_depth',
           'method','host','uri','referrer','version','user_agent','origin',
           'request_body_len','response_body_len','status_code','status_msg',
           'info_code','info_msg','tags','username','password','proxied',
           'orig_fuids','orig_filenames','orig_mime_types',
           'resp_fuids','resp_filenames','resp_mime_types'])

# Stack count user agents — rare ones are suspicious
ua_counts = df['user_agent'].value_counts()
rare_uas = ua_counts[ua_counts < 3]  # Seen < 3 times total
print("Rare user agents:")
print(rare_uas.head(20))

# Stack count DNS queries — rare domains
import subprocess
dns_df = pd.read_csv('dns.log', sep='\t', comment='#',
    names=['ts','uid','orig_h','orig_p','resp_h','resp_p','proto','trans_id',
           'rtt','query','qclass','qclass_name','qtype','qtype_name',
           'rcode','rcode_name','AA','TC','RD','RA','Z','answers','TTLs','rejected'])

query_counts = dns_df['query'].value_counts()
rare_queries = query_counts[query_counts < 3]
print("Rare DNS queries (potential DGA):")
print(rare_queries.head(20))
```

---

## Method 2: Baseline Deviation (Z-Score)

```python
import pandas as pd
import numpy as np

# Load Zeek conn.log
df = pd.read_csv('conn.log', sep='\t', comment='#',
    names=['ts','uid','orig_h','orig_p','resp_h','resp_p','proto','service',
           'duration','orig_bytes','resp_bytes','conn_state','local_orig',
           'local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes',
           'resp_pkts','resp_ip_bytes','tunnel_parents'])

df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)

# Daily outbound bytes per host
df['date'] = pd.to_datetime(df['ts'], unit='s').dt.date
external = df[~df['resp_h'].str.match(r'^(10\.|172\.|192\.168\.)', na=False)]
daily_out = external.groupby(['orig_h', 'date'])['orig_bytes'].sum().reset_index()

# Z-score per host
def zscore_anomalies(group):
    mean = group['orig_bytes'].mean()
    std = group['orig_bytes'].std()
    if std == 0:
        return group.assign(zscore=0)
    group = group.copy()
    group['zscore'] = (group['orig_bytes'] - mean) / std
    return group

anomalies = daily_out.groupby('orig_h').apply(zscore_anomalies)
high_zscore = anomalies[anomalies['zscore'] > 3].sort_values('zscore', ascending=False)
print("Volume anomalies (Z > 3):")
print(high_zscore.head(20))
```

---

## Method 3: Unsupervised Clustering (K-Means)

```python
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np

# Feature engineering from conn.log
df = pd.read_csv('conn.log', sep='\t', comment='#', ...)
df['orig_bytes'] = pd.to_numeric(df['orig_bytes'], errors='coerce').fillna(0)
df['resp_bytes'] = pd.to_numeric(df['resp_bytes'], errors='coerce').fillna(0)
df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)

# Per-host features
host_features = df.groupby('orig_h').agg(
    conn_count=('uid', 'count'),
    unique_dsts=('resp_h', 'nunique'),
    unique_ports=('resp_p', 'nunique'),
    mean_bytes_out=('orig_bytes', 'mean'),
    total_bytes_out=('orig_bytes', 'sum'),
    mean_duration=('duration', 'mean'),
    ratio_out_in=('orig_bytes', lambda x: x.sum() / (df.loc[x.index, 'resp_bytes'].sum() + 1))
).fillna(0)

# Normalize features
scaler = StandardScaler()
X = scaler.fit_transform(host_features.values)

# DBSCAN finds outliers without predefined cluster count
db = DBSCAN(eps=0.5, min_samples=5)
host_features['cluster'] = db.fit_predict(X)

# Cluster -1 = outliers (anomalous hosts)
anomalous = host_features[host_features['cluster'] == -1]
print("Anomalous hosts (DBSCAN outliers):")
print(anomalous.sort_values('total_bytes_out', ascending=False).head(20))
```

---

## Method 4: Autoencoder for Traffic Anomaly Detection

```python
import numpy as np
from tensorflow import keras
from sklearn.preprocessing import MinMaxScaler

# Build autoencoder that learns to reconstruct "normal" traffic
# High reconstruction error = anomaly

# Features per connection: duration, orig_bytes, resp_bytes, orig_pkts, resp_pkts
feature_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']

X_train = normal_traffic[feature_cols].values  # Baseline "normal" traffic
scaler = MinMaxScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Simple autoencoder
model = keras.Sequential([
    keras.layers.Dense(32, activation='relu', input_shape=(5,)),
    keras.layers.Dense(16, activation='relu'),
    keras.layers.Dense(8, activation='relu'),
    keras.layers.Dense(16, activation='relu'),
    keras.layers.Dense(32, activation='relu'),
    keras.layers.Dense(5, activation='sigmoid')
])
model.compile(optimizer='adam', loss='mse')
model.fit(X_train_scaled, X_train_scaled, epochs=50, batch_size=256, validation_split=0.1, verbose=0)

# Score new traffic
X_new = new_traffic[feature_cols].values
X_new_scaled = scaler.transform(X_new)
reconstructions = model.predict(X_new_scaled)
mse = np.mean(np.power(X_new_scaled - reconstructions, 2), axis=1)

# High MSE = anomaly
threshold = np.percentile(mse, 99)  # Top 1% as anomalies
anomaly_mask = mse > threshold
anomalies = new_traffic[anomaly_mask]
print(f"Detected {anomaly_mask.sum()} anomalous connections")
```

---

## Method 5: Shannon Entropy Monitoring

```python
import math
from collections import Counter

def entropy(s):
    if not s: return 0
    freq = Counter(s.lower())
    total = len(s)
    return -sum((c/total) * math.log2(c/total) for c in freq.values())

# Apply to DNS queries
with open('dns.log') as f:
    results = []
    for line in f:
        if line.startswith('#'): continue
        fields = line.strip().split('\t')
        if len(fields) < 10: continue
        query = fields[9]
        if '.' in query:
            subdomain = query.split('.')[0]
            ent = entropy(subdomain)
            results.append((ent, query))

# Sort by entropy — high entropy = suspicious
results.sort(reverse=True)
print("High entropy DNS queries:")
for ent, query in results[:30]:
    print(f"{ent:.2f}  {query}")
```

---

## Method 6: Time Series Analysis (Hour-of-Day Profiling)

```python
import pandas as pd
import numpy as np

# Build hour-of-day profile for each host
df['hour'] = pd.to_datetime(df['ts'], unit='s').dt.hour
hourly_profile = df.groupby(['orig_h', 'hour'])['orig_bytes'].sum().unstack(fill_value=0)

# For each host, flag activity during off-hours if host normally goes quiet
for host in hourly_profile.index:
    row = hourly_profile.loc[host]
    normal_hours = row[row > row.mean()].index.tolist()
    off_hours = row[(row > 0) & ~row.index.isin(normal_hours)].index.tolist()
    if off_hours and row[off_hours].max() > 1e6:  # > 1MB in off-hours
        print(f"Host {host}: unusual activity at hours {off_hours}")
```

---

## Method 7: Peer Group Analysis

```python
# Compare each host's behavior against peer group (same subnet/role)
# Flag hosts that deviate significantly from their peers

peer_groups = df.groupby('subnet')  # You define subnets

for subnet, group in peer_groups:
    host_stats = group.groupby('orig_h').agg(
        conn_count=('uid', 'count'),
        unique_external_dsts=('resp_h', lambda x: (x.str.match(r'^(?!10\.|172\.|192\.168\.)') ).sum()),
        bytes_out=('orig_bytes', 'sum')
    )
    
    # Z-score within peer group
    z_bytes = (host_stats['bytes_out'] - host_stats['bytes_out'].mean()) / host_stats['bytes_out'].std()
    outliers = host_stats[z_bytes.abs() > 2.5]
    if len(outliers):
        print(f"Subnet {subnet} outliers:")
        print(outliers)
```

---

## Elastic ML (Production Anomaly Detection)

```json
// Create Elastic ML job for network traffic anomaly detection
PUT /_ml/anomaly_detectors/zeek-conn-anomaly
{
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "function": "high_sum",
        "field_name": "network.bytes",
        "over_field_name": "source.ip"
      },
      {
        "function": "rare",
        "by_field_name": "destination.port",
        "over_field_name": "source.ip"
      }
    ]
  },
  "data_description": {
    "time_field": "@timestamp"
  }
}
```

---

## RITA Anomaly Detection (Built-In)

```bash
# RITA uses statistical analysis for:
# 1. Beaconing (periodicity detection)
# 2. DNS tunneling (subdomain entropy and volume)
# 3. Long connections (unusual duration)
# 4. Threat scoring (combining multiple indicators)

rita show-beacons my-dataset         # Ranked by beacon score
rita show-long-connections my-dataset  # Unusually long connections
rita show-dns-fqdns my-dataset       # DNS anomalies
rita show-bl-hostnames my-dataset    # Blacklist matches
rita html-report my-dataset          # Full HTML report
```

---

## What Anomaly Detection Catches That Signatures Don't

| Threat | Why Signatures Fail | Anomaly Method |
|--------|--------------------|-----------------|
| Novel C2 framework | No known signature | Beaconing interval analysis |
| Custom malware | No hash match | Traffic volume outlier |
| Living-off-the-land | Legit tools, unusual context | Peer group deviation |
| Slow exfiltration | Under DLP thresholds | Time series baseline |
| Encrypted malware | Can't inspect payload | JA3/JA4 rarity scoring |
| DGA (new family) | No domain in blocklist | Entropy + NXDomain burst |
| Pass-the-Hash | Legit NTLM protocol | Behavioral baseline (NTLM where Kerberos expected) |

## Sources

- [Vectra AI — Network Anomaly Detection](https://www.vectra.ai/topics/network-anomaly-detection)
- [Corelight — Anomaly Detection](https://corelight.com/blog/anomaly-detection-network-security)
- [CrowdStrike 2025 Threat Hunting Report (via hunt.io)](https://hunt.io/glossary/threat-hunting-playbooks)
- [RITA GitHub](https://github.com/activecm/rita)
- [Autonomous Threat Hunting: AI-Driven Intelligence (arxiv)](https://arxiv.org/pdf/2401.00286)
