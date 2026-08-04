#!/usr/bin/env python3
"""
Re-date a live traffic slice from dt=2026-04-24 into today + tomorrow (dev demo refresh).

Takes a contiguous 3-hour window (00:00-03:00) of the genuinely-live 04-24 traffic
and INSERTs it into the same tables under one partition PER target day, with the two
time columns shifted so each target day carries its own 00:00-03:00 block:
  - ts          (epoch double)  += (target_day - SRC_DT) seconds
  - ts_datetime (string)        += (target_day - SRC_DT) days

Why TWO days (today + tomorrow): the app answers "last 24h" with a 2-day partition
prune (today, yesterday) AND a `ts >= now-24h` bound. A single midnight-anchored block
ages out of that window a few hours into the NEXT day. Seeding today AND tomorrow means
a rolling 24h window always overlaps a seeded block, so the demo stays non-empty all day
today and all day tomorrow from one run. No double-count: the ts bound only ever counts
the one in-window day's copy (that is what the ts-bound fix in athena_client is for).

INSERT INTO writes parquet into s3://.../<table>/dt=<DST_DT>/ and auto-registers each
partition. Views (alerts, uid_lookup, fuid_lookup) light up automatically.

Idempotent: drops any existing dt=<target> partition (Glue + S3) before inserting.

Dates derive from "today" (UTC) at runtime, so there is no manual day-offset to keep in
sync. Override with DAYS_AHEAD env or positional table args as before.

RETIRED, AND DELIBERATELY LEFT POINTING AT A DEAD TARGET
-------------------------------------------------------
The dev slice this script re-dated lived in the blackhat_pope_logs catalog and the
blackhat-pope-parquet bucket. Both are gone; prod is blackhatnoc_glue over
s3://blackhatnoc/corelight/usa2026/parquet. So this script no longer runs.

It has NOT been retargeted at prod, and it should not be. clear_dst_partition()
DELETES the dt=<target> partition from Glue and S3 before each insert, and the only
thing standing between that and real data is the BUCKET guard in main(). Pointing
that at the bucket holding live conference traffic would convert the guard into a
loaded gun for the sake of a demo-seeding tool nobody needs during the show.

If a dev slice is ever wanted again, stand up a SEPARATE bucket for it and set
BUCKET to that. Do not set BUCKET to a bucket that holds data you want to keep.
"""
import boto3, time, sys, os
from datetime import datetime, timezone, timedelta

REGION   = "us-west-2"
# Retired dev-slice coordinates. See the note above before changing any of these:
# the BUCKET value is a safety interlock, not just configuration.
DB       = "blackhat-pope-retired-dev"
WG       = "blackhat-pope-retired-dev"
BUCKET   = "blackhat-pope-parquet"

SRC_DT   = "2026-04-24"
# Target days: today + the next N (default 1 => today + tomorrow). All UTC to match
# how the app computes its date window.
_TODAY   = datetime.now(timezone.utc).date()
_SRC     = datetime.strptime(SRC_DT, "%Y-%m-%d").date()
DAYS_AHEAD = int(os.environ.get("DAYS_AHEAD", "1"))
DST_DTS  = [(_TODAY + timedelta(days=d)).strftime("%Y-%m-%d") for d in range(DAYS_AHEAD + 1)]

WIN_FROM = f"{SRC_DT} 00:00:00"
WIN_TO   = f"{SRC_DT} 03:00:00"

def _shift_for(dst_dt):
    """(seconds, days-as-str) to shift SRC_DT timestamps onto dst_dt."""
    days = (datetime.strptime(dst_dt, "%Y-%m-%d").date() - _SRC).days
    return days * 86_400, str(days)

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


class ClearFailed(Exception):
    """The destination partition could NOT be cleared (e.g. no permission).

    Raised so the caller skips the INSERT entirely. Nothing was deleted, so this is
    NOT data loss; it is a no-op that must be reported as such, not as a wiped table.
    """


def clear_dst_partition(table, dst_dt):
    """Drop the destination dt=<dst_dt> partition (Glue) and delete its S3 objects.

    Returns silently only if the partition is genuinely clear afterward. Raises
    ClearFailed if a delete was denied/errored, so the caller does NOT then run an
    INSERT it cannot commit and does NOT print a false DATA LOSS warning.
    """
    # Glue partition
    try:
        glue.delete_partition(DatabaseName=DB, TableName=table, PartitionValues=[dst_dt])
    except glue.exceptions.EntityNotFoundException:
        pass
    except Exception as e:
        raise ClearFailed(f"glue delete_partition: {e}") from e
    # S3 objects
    prefix = f"{table}/dt={dst_dt}/"
    paginator = s3.get_paginator("list_objects_v2")
    to_del = []
    try:
        for page in paginator.paginate(Bucket=BUCKET, Prefix=prefix):
            for obj in page.get("Contents", []):
                to_del.append({"Key": obj["Key"]})
                if len(to_del) == 1000:
                    s3.delete_objects(Bucket=BUCKET, Delete={"Objects": to_del})
                    to_del = []
        if to_del:
            s3.delete_objects(Bucket=BUCKET, Delete={"Objects": to_del})
    except Exception as e:
        raise ClearFailed(f"s3 delete_objects: {e}") from e


def build_insert(table, cols, dst_dt):
    shift_s, shift_d = _shift_for(dst_dt)
    names = {c for c, _ in cols}
    has_win = "ts_datetime" in names
    select_exprs = []
    for name, _typ in cols:
        if name == "ts":
            select_exprs.append(f"ts + {shift_s}")
        elif name == "ts_datetime":
            select_exprs.append(
                "date_format(date_parse(ts_datetime,'%Y-%m-%d %H:%i:%s') "
                f"+ interval '{shift_d}' day, '%Y-%m-%d %H:%i:%s')"
            )
        else:
            select_exprs.append(f'"{name}"')
    where = f"dt = '{SRC_DT}'"
    if has_win:
        where += f" AND ts_datetime >= '{WIN_FROM}' AND ts_datetime < '{WIN_TO}'"
    sql = (
        f'INSERT INTO "{table}"\n'
        f'SELECT {", ".join(select_exprs)}, \'{dst_dt}\' AS dt\n'
        f'FROM "{table}"\n'
        f'WHERE {where}'
    )
    return sql, has_win


def main():
    # Args are optional table names to restrict to (ignore any leading-dash tokens).
    only = {a for a in sys.argv[1:] if not a.startswith("-")}

    # Guard the destructive path. clear_dst_partition() deletes the dt=<target>
    # partition (Glue + S3) before each insert, so a mis-set target could wipe real
    # data. Two hard stops that no flag can override:
    if SRC_DT in DST_DTS:
        sys.exit(f"REFUSING: a target day equals SRC_DT ({SRC_DT}). That would delete the "
                 f"SOURCE partition before reading it. Targets: {DST_DTS}")
    if BUCKET != "blackhat-pope-parquet":
        sys.exit(f"REFUSING: BUCKET is '{BUCKET}', not the expected demo parquet bucket. "
                 f"This script only re-dates the demo slice; aborting to avoid touching other data.")

    tables = physical_tables()
    if only:
        tables = [t for t in tables if t in only]
    print(f"Re-dating {SRC_DT} [{WIN_FROM}..{WIN_TO}) -> {DST_DTS} across {len(tables)} tables")
    print(f"This DELETES and rewrites the dt=<target> partition of each table in {BUCKET}.\n")
    total_scanned = 0
    ok = failed = wiped = 0
    # Outer loop over target days so one run seeds today AND tomorrow (a rolling 24h
    # window always overlaps a seeded 00:00-03:00 block on either day).
    for dst_dt in DST_DTS:
        print(f"=== target dt={dst_dt} ===")
        for i, t in enumerate(sorted(tables), 1):
            cols = columns(t)
            sql, has_win = build_insert(t, cols, dst_dt)
            print(f"[{dst_dt}][{i}/{len(tables)}] {t} (win={'y' if has_win else 'n'}) ... ",
                  end="", flush=True)
            # Clear FIRST. If the clear is denied/errors, nothing was deleted, so skip the
            # INSERT and report a clean no-op (not data loss). This also fails fast on a
            # credentials problem: if the very FIRST clear of the run is denied, the role is
            # read-only (run locally with the write-capable profile), so stop immediately.
            try:
                clear_dst_partition(t, dst_dt)
            except ClearFailed as e:
                print(f"SKIP (clear failed, nothing deleted): {e}")
                if dst_dt == DST_DTS[0] and i == 1:
                    sys.exit("\nABORT: cannot clear the destination partition. The current "
                             "credentials are read-only. Run this locally with the "
                             "write-capable profile (AWS_PROFILE=VirtualPOC-users), NOT on "
                             "the box's instance role.")
                failed += 1
                continue
            # Partition is now clear. If the INSERT fails, the partition IS left empty.
            st, reason, scanned, qid = q(sql)
            total_scanned += scanned
            if st == "SUCCEEDED":
                ok += 1
                print(f"OK  ({scanned/1e6:.0f} MB scanned)")
            else:
                failed += 1
                wiped += 1
                print(f"{st}: {reason[:160]}")
                print(f"    !! DATA LOSS: dt={dst_dt} for '{t}' was cleared but the INSERT "
                      f"failed, so the partition is now EMPTY. Re-run for this table "
                      f"(python {sys.argv[0]} {t}) before relying on the demo data.",
                      file=sys.stderr)
    print(f"\nDone. ok={ok} failed={failed}  total scanned={total_scanned/1e9:.2f} GB "
          f"(~${total_scanned/1e12*5:.2f})")
    if wiped:
        print(f"WARNING: {wiped} table(s) were cleared but their INSERT failed, so those "
              f"partitions are EMPTY until you re-run them.", file=sys.stderr)


if __name__ == "__main__":
    main()
