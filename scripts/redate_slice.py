#!/usr/bin/env python3
"""
Re-date a live traffic slice from dt=2026-04-24 -> dt=2026-07-23 (today), +90 days.

Takes a contiguous 3-hour window (00:00-03:00) of the genuinely-live 04-24 traffic
and INSERTs it back into the same tables under a new dt partition, with the two
time columns shifted so the app sees "today":
  - ts          (epoch double)  += 7_689_600   (89 days in seconds)
  - ts_datetime (string)        += interval '89' day

INSERT INTO writes parquet into s3://.../<table>/dt=2026-07-22/ and auto-registers
the partition. Views (alerts, uid_lookup, fuid_lookup) light up automatically.

Idempotent: drops any existing dt=2026-07-22 partition (Glue + S3) before inserting.
"""
import boto3, time, sys

REGION   = "us-west-2"
DB       = "blackhat_pope_logs"
WG       = "blackhat-pope-dev"
BUCKET   = "blackhat-pope-parquet"

SRC_DT   = "2026-04-24"
DST_DT   = "2026-07-23"
SHIFT_S  = 7_776_000          # 90 days in seconds
SHIFT_D  = "90"               # days, for interval literal
WIN_FROM = f"{SRC_DT} 00:00:00"
WIN_TO   = f"{SRC_DT} 03:00:00"

athena = boto3.client("athena", region_name=REGION)
glue   = boto3.client("glue",   region_name=REGION)
s3     = boto3.client("s3",     region_name=REGION)


def q(sql):
    """Run an Athena query, block until done, return state."""
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": DB},
        WorkGroup=WG,
    )["QueryExecutionId"]
    while True:
        ex = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        st = ex["Status"]["State"]
        if st in ("SUCCEEDED", "FAILED", "CANCELLED"):
            reason = ex["Status"].get("StateChangeReason", "")
            scanned = ex.get("Statistics", {}).get("DataScannedInBytes", 0)
            return st, reason, scanned, qid
        time.sleep(1.5)


def physical_tables():
    tabs, tok = [], None
    while True:
        kw = {"DatabaseName": DB, "MaxResults": 100}
        if tok:
            kw["NextToken"] = tok
        resp = glue.get_tables(**kw)
        for t in resp["TableList"]:
            if t.get("TableType") != "VIRTUAL_VIEW":
                tabs.append(t["Name"])
        tok = resp.get("NextToken")
        if not tok:
            break
    return tabs


def columns(table):
    """Ordered non-partition columns [(name,type), ...]."""
    t = glue.get_table(DatabaseName=DB, Name=table)["Table"]
    return [(c["Name"], c["Type"]) for c in t["StorageDescriptor"]["Columns"]]


def clear_dst_partition(table):
    """Drop dt=2026-07-22 partition (Glue) and delete its S3 objects, if present."""
    # Glue partition
    try:
        glue.delete_partition(DatabaseName=DB, TableName=table, PartitionValues=[DST_DT])
    except glue.exceptions.EntityNotFoundException:
        pass
    except Exception as e:
        print(f"    (glue partition drop: {e})")
    # S3 objects
    prefix = f"{table}/dt={DST_DT}/"
    paginator = s3.get_paginator("list_objects_v2")
    to_del = []
    for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            to_del.append({"Key": obj["Key"]})
            if len(to_del) == 1000:
                s3.delete_objects(Bucket=BUCKET, Delete={"Objects": to_del})
                to_del = []
    if to_del:
        s3.delete_objects(Bucket=BUCKET, Delete={"Objects": to_del})


def build_insert(table, cols):
    names = {c for c, _ in cols}
    has_win = "ts_datetime" in names
    select_exprs = []
    for name, _typ in cols:
        if name == "ts":
            select_exprs.append(f"ts + {SHIFT_S}")
        elif name == "ts_datetime":
            select_exprs.append(
                "date_format(date_parse(ts_datetime,'%Y-%m-%d %H:%i:%s') "
                f"+ interval '{SHIFT_D}' day, '%Y-%m-%d %H:%i:%s')"
            )
        else:
            select_exprs.append(f'"{name}"')
    where = f"dt = '{SRC_DT}'"
    if has_win:
        where += f" AND ts_datetime >= '{WIN_FROM}' AND ts_datetime < '{WIN_TO}'"
    sql = (
        f'INSERT INTO "{table}"\n'
        f'SELECT {", ".join(select_exprs)}, \'{DST_DT}\' AS dt\n'
        f'FROM "{table}"\n'
        f'WHERE {where}'
    )
    return sql, has_win


def main():
    only = set(sys.argv[1:])  # optional: restrict to given tables
    tables = physical_tables()
    if only:
        tables = [t for t in tables if t in only]
    print(f"Re-dating {SRC_DT} [{WIN_FROM}..{WIN_TO}) -> {DST_DT} across {len(tables)} tables\n")
    total_scanned = 0
    ok = skipped = failed = 0
    for i, t in enumerate(sorted(tables), 1):
        cols = columns(t)
        sql, has_win = build_insert(t, cols)
        print(f"[{i}/{len(tables)}] {t} (win={'y' if has_win else 'n'}) ... ", end="", flush=True)
        clear_dst_partition(t)
        st, reason, scanned, qid = q(sql)
        total_scanned += scanned
        if st == "SUCCEEDED":
            ok += 1
            print(f"OK  ({scanned/1e6:.0f} MB scanned)")
        else:
            failed += 1
            print(f"{st}: {reason[:160]}")
    print(f"\nDone. ok={ok} failed={failed}  total scanned={total_scanned/1e9:.2f} GB "
          f"(~${total_scanned/1e12*5:.2f})")


if __name__ == "__main__":
    main()
