#!/usr/bin/env python3
"""
seed-s3.py — Generate and upload synthetic security event data to S3.

Usage:
    python scripts/seed-s3.py --bucket bhasia-noc-data --region us-east-1

Uploads NDJSON files to:
    s3://{bucket}/corelight/events-{timestamp}.ndjson
    s3://{bucket}/paloalto/events-{timestamp}.ndjson
    s3://{bucket}/partner/events-{timestamp}.ndjson
"""

import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone

import boto3

# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

SUSPICIOUS_IPS = [
    "185.220.101.47", "91.240.118.172", "45.155.205.233",
    "193.42.33.14", "23.129.64.210", "198.98.51.189",
    "104.244.72.115", "171.25.193.78", "209.141.33.42",
    "185.56.80.65", "37.120.198.219", "89.248.165.100",
    "62.102.148.68", "194.26.29.102", "5.2.69.50",
]

# Must stay inside the conference ranges in agents/shared/ipscope.py, or the
# scope allowlist redacts every seeded host to [OUT-OF-SCOPE-IP] and the demo
# looks broken. tests/python/test_ipscope.py asserts these are in scope.
INTERNAL_IPS = [
    "10.220.31.10", "10.220.31.25", "10.220.31.50",
    "10.220.40.10", "10.220.40.30", "10.220.40.100",
    "10.220.55.5", "10.220.55.20",
    "192.168.130.100",
]

C2_DOMAINS = [
    "evil-update.xyz", "c2-relay.top", "darkpayload.ru",
    "exfil-data.cc", "beacon-check.info", "malware-cdn.net",
]

BENIGN_DOMAINS = [
    "google.com", "github.com", "aws.amazon.com",
    "cloudflare.com", "microsoft.com", "ubuntu.com",
]

THREAT_CATEGORIES = [
    "malware-download", "spyware-callback", "command-and-control",
    "botnet-activity", "brute-force-attempt", "policy-violation",
    "data-exfiltration", "port-scan", "exploit-attempt",
]

SUSPICIOUS_PORTS = [4444, 6666, 8888, 31337, 1337, 9001, 5555, 7777, 12345]
NORMAL_PORTS = [80, 443, 53, 22, 25, 110, 143, 8080, 8443, 3389]

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
SEVERITY_WEIGHTS = [0.10, 0.25, 0.35, 0.20, 0.10]


def random_ts(hours_back: int = 24) -> str:
    """Random ISO timestamp within the last N hours."""
    now = datetime.now(timezone.utc)
    offset = timedelta(seconds=random.randint(0, hours_back * 3600))
    return (now - offset).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Event generators
# ---------------------------------------------------------------------------

def gen_corelight_flow() -> dict:
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(SUSPICIOUS_IPS + INTERNAL_IPS[:3])
    port = random.choice(SUSPICIOUS_PORTS + NORMAL_PORTS)
    return {
        "@timestamp": random_ts(),
        "uid": f"C{''.join(random.choices('abcdefghijklmnop0123456789', k=16))}",
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": dst,
        "id.resp_p": port,
        "proto": random.choice(["tcp", "udp"]),
        "service": random.choice(["ssl", "http", "dns", "ssh", "smtp", "-"]),
        "duration": round(random.uniform(0.01, 300.0), 3),
        "orig_bytes": random.randint(100, 500000),
        "resp_bytes": random.randint(100, 500000),
        "conn_state": random.choice(["S1", "SF", "S0", "REJ", "RSTO", "SH"]),
        "event_type": "conn",
        "source": "corelight",
    }


def gen_corelight_dns() -> dict:
    src = random.choice(INTERNAL_IPS)
    domain = random.choice(C2_DOMAINS + BENIGN_DOMAINS * 3)
    # DNS tunneling: long subdomain
    if random.random() < 0.15:
        sub = ''.join(random.choices('abcdefghijklmnop0123456789', k=random.randint(30, 60)))
        domain = f"{sub}.{random.choice(C2_DOMAINS)}"
    return {
        "@timestamp": random_ts(),
        "uid": f"D{''.join(random.choices('abcdefghijklmnop0123456789', k=16))}",
        "id.orig_h": src,
        "id.orig_p": random.randint(1024, 65535),
        "id.resp_h": "10.0.1.1",
        "id.resp_p": 53,
        "proto": "udp",
        "service": "dns",
        "query": domain,
        "qtype": random.choice(["A", "AAAA", "TXT", "MX"]),
        "rcode": random.choice(["NOERROR", "NOERROR", "NXDOMAIN"]),
        "event_type": "dns",
        "source": "corelight",
    }


def gen_corelight_notice() -> dict:
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(SUSPICIOUS_IPS)
    return {
        "@timestamp": random_ts(),
        "uid": f"N{''.join(random.choices('abcdefghijklmnop0123456789', k=16))}",
        "id.orig_h": src,
        "id.resp_h": dst,
        "note": random.choice([
            "Scan::Port_Scan",
            "Scan::Address_Scan",
            "SSL::Invalid_Server_Cert",
            "HTTP::Suspicious_User_Agent",
        ]),
        "msg": f"Suspicious activity from {src} to {dst}",
        "event_type": "notice",
        "source": "corelight",
    }


def gen_paloalto_alert() -> dict:
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(SUSPICIOUS_IPS)
    severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]
    return {
        "@timestamp": random_ts(),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(SUSPICIOUS_PORTS + NORMAL_PORTS),
        "proto": random.choice(["tcp", "udp"]),
        "action": random.choice(["allow", "deny", "drop", "alert"]),
        "severity": severity,
        "threat_category": random.choice(THREAT_CATEGORIES),
        "threat_name": f"ThreatID-{random.randint(10000, 99999)}",
        "rule": f"rule-{random.randint(1, 50)}",
        "event_type": "threat",
        "source": "paloalto",
    }


def gen_partner_event() -> dict:
    src = random.choice(INTERNAL_IPS + SUSPICIOUS_IPS)
    return {
        "@timestamp": random_ts(),
        "source_ip": src,
        "event_type": random.choice(["authentication", "access", "anomaly"]),
        "severity": random.choice(SEVERITIES),
        "description": random.choice([
            "Failed login attempt detected",
            "Unusual access pattern from source",
            "Multiple failed authentications",
            "Anomalous data transfer volume",
            "Policy violation detected",
        ]),
        "source": "partner-default",
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Seed S3 with synthetic NOC data")
    parser.add_argument("--bucket", required=True, help="S3 bucket name")
    parser.add_argument("--region", default="us-east-1", help="S3 region")
    parser.add_argument("--profile", default=None, help="AWS CLI profile")
    args = parser.parse_args()

    session_kwargs = {"region_name": args.region}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)
    s3 = session.client("s3")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    # Generate Corelight events
    corelight_events = []
    for _ in range(70):
        corelight_events.append(gen_corelight_flow())
    for _ in range(20):
        corelight_events.append(gen_corelight_dns())
    for _ in range(10):
        corelight_events.append(gen_corelight_notice())

    corelight_ndjson = "\n".join(json.dumps(e) for e in corelight_events)
    key = f"corelight/events-{ts}.ndjson"
    s3.put_object(Bucket=args.bucket, Key=key, Body=corelight_ndjson.encode())
    print(f"Uploaded {len(corelight_events)} corelight events → s3://{args.bucket}/{key}")

    # Generate Palo Alto alerts
    paloalto_events = [gen_paloalto_alert() for _ in range(50)]
    paloalto_ndjson = "\n".join(json.dumps(e) for e in paloalto_events)
    key = f"paloalto/events-{ts}.ndjson"
    s3.put_object(Bucket=args.bucket, Key=key, Body=paloalto_ndjson.encode())
    print(f"Uploaded {len(paloalto_events)} paloalto events → s3://{args.bucket}/{key}")

    # Generate Partner events
    partner_events = [gen_partner_event() for _ in range(20)]
    partner_ndjson = "\n".join(json.dumps(e) for e in partner_events)
    key = f"partner/events-{ts}.ndjson"
    s3.put_object(Bucket=args.bucket, Key=key, Body=partner_ndjson.encode())
    print(f"Uploaded {len(partner_events)} partner events → s3://{args.bucket}/{key}")

    print(f"\nTotal: {len(corelight_events) + len(paloalto_events) + len(partner_events)} events seeded to s3://{args.bucket}/")


if __name__ == "__main__":
    main()
