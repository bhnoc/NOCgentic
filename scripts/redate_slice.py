#!/usr/bin/env python3
"""
Re-date a live traffic slice from dt=2026-04-24 -> dt=2026-07-24 (today), +91 days.

Takes a contiguous 3-hour window (00:00-03:00) of the genuinely-live 04-24 traffic
and INSERTs it back into the same tables under a new dt partition, with the two
time columns shifted so the app sees "today":
  - ts          (epoch double)  += SHIFT_S seconds
  - ts_datetime (string)        += interval 'SHIFT_D' day

INSERT INTO writes parquet into s3://.../<table>/dt=<DST_DT>/ and auto-registers
the partition. Views (alerts, uid_lookup, fuid_lookup) light up automatically.

Idempotent: drops any existing dt=<DST_DT> partition (Glue + S3) before inserting.
"""
import boto3, time, sys

REGION   = "us-west-2"
DB       = "blackhat_pope_logs"
WG       = "blackhat-pope-dev"
BUCKET   = "blackhat-pope-parquet"

SRC_DT   = "2026-04-24"
DST_DT   = "2026-07-24"
SHIFT_S  = 7_862_400          # 91 days in seconds
SHIFT_D  = "91"               # days, for interval literal
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
    """Drop the destination dt=<DST_DT> partition (Glue) and delete its S3 objects, if present."""
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
    # Args are optional table names to restrict to (ignore any leading-dash tokens).
    only = {a for a in sys.argv[1:] if not a.startswith("-")}

    # Guard the destructive path. clear_dst_partition() deletes the dt=<DST_DT>
    # partition (Glue + S3) before each insert, so a mis-set DST_DT could wipe real
    # data. Two hard stops that no flag can override:
    if DST_DT == SRC_DT:
        sys.exit(f"REFUSING: DST_DT == SRC_DT ({SRC_DT}). This would delete the SOURCE "
                 f"partition before reading it. Set DST_DT to the target (today).")
    if BUCKET != "blackhat-pope-parquet":
        sys.exit(f"REFUSING: BUCKET is '{BUCKET}', not the expected demo parquet bucket. "
                 f"This script only re-dates the demo slice; aborting to avoid touching other data.")

    tables = physical_tables()
    if only:
        tables = [t for t in tables if t in only]
    print(f"Re-dating {SRC_DT} [{WIN_FROM}..{WIN_TO}) -> {DST_DT} across {len(tables)} tables")
    print(f"This DELETES and rewrites the dt={DST_DT} partition of each table in {BUCKET}.\n")
    total_scanned = 0
    ok = skipped = failed = 0
    for i, t in enumerate(sorted(tables), 1):
        cols = columns(t)
        sql, has_win = build_insert(t, cols)
        print(f"[{i}/{len(tables)}] {t} (win={'y' if has_win else 'n'}) ... ", end="", flush=True)
        # Destructive: this deletes the existing dt=<DST_DT> partition. If the
        # INSERT below fails the partition is left EMPTY, so shout about it.
        clear_dst_partition(t)
        st, reason, scanned, qid = q(sql)
        total_scanned += scanned
        if st == "SUCCEEDED":
            ok += 1
            print(f"OK  ({scanned/1e6:.0f} MB scanned)")
        else:
            failed += 1
            print(f"{st}: {reason[:160]}")
            print(f"    !! DATA LOSS: dt={DST_DT} for '{t}' was cleared but the INSERT "
                  f"failed, so the partition is now EMPTY. Re-run for this table "
                  f"(python {sys.argv[0]} {t}) before relying on the demo data.",
                  file=sys.stderr)
    print(f"\nDone. ok={ok} failed={failed}  total scanned={total_scanned/1e9:.2f} GB "
          f"(~${total_scanned/1e12*5:.2f})")
    if failed:
        print(f"WARNING: {failed} table(s) failed to insert after their partition was "
              f"cleared. Those partitions are empty until you re-run them.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
