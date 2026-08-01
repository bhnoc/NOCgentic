"""
Athena Log Refresh Lambda v6
- Dispatcher/worker fan-out: one log_type per invocation, never times out
- Per-log-type watermark files, safe to run in parallel
- Retry INTERNAL_ERROR_QUERY_ENGINE with exponential backoff
- Backfill mode via start_date/end_date

Event shapes
  {}                                           -> dispatcher for today
  {"date": "2026-04-23"}                       -> dispatcher for one day
  {"start_date": "2026-04-22",
   "end_date":   "2026-04-24"}                 -> dispatcher for a range (inclusive)
  {"log_type": "conn", "date": "2026-04-23"}   -> worker for one table/day
"""
import boto3

import asset_classification
import entity_context
import derived_views
import json
import os
import time
import re
from datetime import datetime, timezone, timedelta

# All config is env-driven so one code artifact serves any tenant/dataset without
# hardcoded account or show names.
#
# These are REQUIRED, not defaulted. The previous version fell back to the retired
# account's bucket/database/workgroup, which meant a Lambda deployed with a missing
# env var would quietly point at infrastructure that no longer exists, create
# nothing, and report success. Failing at import is louder and cheaper to diagnose.
def _required(name: str) -> str:
    val = os.environ.get(name, '').strip()
    if not val:
        raise RuntimeError(
            f"{name} is not set. This Lambda has no safe default: guessing a bucket "
            f"or database silently targets the wrong dataset."
        )
    return val


REGION = _required('REGION')
S3_LOG_BUCKET = _required('S3_LOG_BUCKET')
S3_LOG_PREFIX = _required('S3_LOG_PREFIX').strip('/')
S3_PARQUET_BUCKET = _required('S3_PARQUET_BUCKET')
GLUE_DATABASE = _required('GLUE_DATABASE')
ATHENA_WORKGROUP = _required('ATHENA_WORKGROUP')
# Optional: empty means the parquet tables sit at the bucket root.
S3_PARQUET_PREFIX = os.environ.get('S3_PARQUET_PREFIX', '').strip('/')
WATERMARK_PREFIX = os.environ.get('WATERMARK_PREFIX', '_watermarks/v6')
SELF_FUNCTION_NAME = os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'blackhatnoc-athena-refresh')

_PARQUET_BASE = (f"s3://{S3_PARQUET_BUCKET}/{S3_PARQUET_PREFIX}/"
                 if S3_PARQUET_PREFIX else f"s3://{S3_PARQUET_BUCKET}/")
TIME_SAFETY_BUFFER_MS = 60_000

s3 = boto3.client('s3', region_name=REGION)
athena = boto3.client('athena', region_name=REGION)
glue = boto3.client('glue', region_name=REGION)
lambda_client = boto3.client('lambda', region_name=REGION)


def watermark_key(log_type, date_str):
    return f"{WATERMARK_PREFIX}/{log_type}/{date_str}.json"


def get_watermark(log_type, date_str):
    try:
        resp = s3.get_object(Bucket=S3_PARQUET_BUCKET, Key=watermark_key(log_type, date_str))
        return float(json.loads(resp['Body'].read())['ts'])
    except Exception:
        return 0.0


def save_watermark(log_type, date_str, ts):
    s3.put_object(
        Bucket=S3_PARQUET_BUCKET,
        Key=watermark_key(log_type, date_str),
        Body=json.dumps({
            'log_type': log_type,
            'date': date_str,
            'ts': ts,
            'updated_at': datetime.now(timezone.utc).isoformat(),
        }),
        ContentType='application/json',
    )


def sanitize_column_name(field_name):
    """Map a raw Zeek field name to a safe Athena column name.

    Only structural fixes: dots and dashes to underscores, drop anything else,
    prefix a leading digit. Reserved words are deliberately NOT renamed here, see
    quote_column below.
    """
    name = re.sub(r'[.\-]', '_', field_name)
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    if name and name[0].isdigit():
        name = 'f_' + name
    return name.lower()


def quote_column(name):
    """Backtick every column in generated DDL.

    This replaced a hand-maintained 19-word reserved list that renamed collisions
    to `name_`. Two problems with that approach, both of which bit us:

      * The list always lags the parser. Corelight started emitting a `net_perf`
        log whose schema has a column literally called `window`, which was not in
        the list, so CREATE TABLE died with a ParseException and that whole log
        type stayed invisible. Any future log type with a reserved column would
        fail the same way, silently, until someone noticed a missing table.
      * Renaming means the column no longer matches the field name in the Parquet
        file, so the schema and the data drift apart and every consumer has to
        know about the rewrite. Seven columns in this catalog carry a trailing
        underscore for exactly this reason (date_, from_, index_, to_, user_,
        ja3_string_, ja3s_string_), and each one is a papercut the agents' prompt
        has to document.

    Quoting is unconditional on purpose: no list to maintain, nothing to keep in
    sync with the parser, and a name that survives verbatim from the raw log to
    the query. Verified against Athena that backticked reserved words work in both
    CREATE EXTERNAL TABLE and SELECT.

    Existing tables keep their renamed columns: they were created with the old
    scheme and CREATE TABLE IF NOT EXISTS will not rewrite them. Only new log
    types get the verbatim name, which is why the trailing-underscore columns
    above are still documented as-is.
    """
    return f"`{name}`"


def get_log_types_in_s3(date_str):
    prefix = f"{S3_LOG_PREFIX}/{date_str}/"
    log_types = set()
    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=S3_LOG_BUCKET, Prefix=prefix, Delimiter='/'):
        for obj in page.get('Contents', []):
            key = obj['Key']
            filename = key.split('/')[-1]
            if '_2026' in filename:
                log_type = filename.split('_2026')[0]
                log_types.add(log_type)
    return log_types


def get_existing_tables():
    tables = {}
    paginator = glue.get_paginator('get_tables')
    for page in paginator.paginate(DatabaseName=GLUE_DATABASE):
        for t in page['TableList']:
            loc = t.get('StorageDescriptor', {}).get('Location', '')
            if loc.startswith(_PARQUET_BASE):
                cols = [(c['Name'], c['Type']) for c in t.get('StorageDescriptor', {}).get('Columns', [])]
                tables[t['Name']] = cols
    return tables


def run_athena_query(query, timeout=900, retries=3):
    """Run Athena query with retries on transient INTERNAL_ERROR_QUERY_ENGINE."""
    attempt = 0
    while True:
        attempt += 1
        response = athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': GLUE_DATABASE},
            WorkGroup=ATHENA_WORKGROUP,
        )
        query_id = response['QueryExecutionId']
        start = time.time()
        state = 'RUNNING'
        reason = None
        while time.time() - start < timeout:
            result = athena.get_query_execution(QueryExecutionId=query_id)
            state = result['QueryExecution']['Status']['State']
            if state == 'SUCCEEDED':
                return query_id, state, None
            if state in ('FAILED', 'CANCELLED'):
                reason = result['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                break
            time.sleep(3)
        else:
            reason = 'Query timed out'
            state = 'TIMEOUT'
        transient = reason and ('INTERNAL_ERROR_QUERY_ENGINE' in reason
                                 or 'SLOW_DOWN' in reason
                                 or 'throttl' in reason.lower())
        if transient and attempt < retries:
            backoff = min(60, 5 * 2 ** (attempt - 1))
            print(f"  transient error, retry {attempt}/{retries} after {backoff}s: {reason[:120]}")
            time.sleep(backoff)
            continue
        return query_id, state, reason


def get_schema_from_raw(log_type, date_str):
    query = f"""
    SELECT DISTINCT line FROM corelight_raw
    WHERE dt = '{date_str}' AND line LIKE '#fields%' AND "$path" LIKE '%/{log_type}_%'
    LIMIT 1
    """
    query_id, state, _ = run_athena_query(query, timeout=120, retries=2)
    if state != 'SUCCEEDED':
        return None
    results = athena.get_query_results(QueryExecutionId=query_id)
    rows = results.get('ResultSet', {}).get('Rows', [])
    if len(rows) > 1:
        line = rows[1]['Data'][0].get('VarCharValue', '')
        fields = line.replace('#fields\t', '').split('\t')
        return fields
    return None


def create_new_table(log_type, date_str):
    fields = get_schema_from_raw(log_type, date_str)
    if not fields:
        print(f"  Could not get schema for {log_type}")
        return False

    columns = [f"{quote_column('ts_datetime')} string"]
    seen = {'ts_datetime'}
    for field in fields:
        col_name = sanitize_column_name(field)
        # Two raw fields can sanitize to the same name (e.g. `id.orig_h` and
        # `id-orig_h`). A duplicate column makes CREATE TABLE fail, so keep the
        # first and skip the rest rather than losing the whole table.
        if not col_name or col_name in seen:
            continue
        seen.add(col_name)
        col_type = 'DOUBLE' if field.lower() == 'ts' else 'string'
        columns.append(f"{quote_column(col_name)} {col_type}")

    columns_str = ',\n  '.join(columns)
    table_name = log_type.replace('-', '_')
    s3_location = f"{_PARQUET_BASE}{log_type}/"

    create_query = f"""
CREATE EXTERNAL TABLE IF NOT EXISTS {GLUE_DATABASE}.{table_name} (
  {columns_str}
)
PARTITIONED BY (dt string)
STORED AS PARQUET
LOCATION '{s3_location}'
TBLPROPERTIES (
  'parquet.compression'='SNAPPY',
  'projection.enabled'='true',
  'projection.dt.type'='date',
  'projection.dt.range'='2026-04-01,2026-12-31',
  'projection.dt.format'='yyyy-MM-dd',
  'storage.location.template'='{s3_location}dt=${{dt}}'
)
"""
    _, state, reason = run_athena_query(create_query, timeout=180, retries=2)
    if state != 'SUCCEEDED':
        print(f"  CREATE TABLE failed: {(reason or '')[:160]}")
        return False
    return True


def incremental_load(log_type, table_cols, date_str, last_ts):
    fields = get_schema_from_raw(log_type, date_str)
    if not fields:
        return False, None

    field_map = {sanitize_column_name(f): i + 1 for i, f in enumerate(fields)}

    select_cols = [
        "CASE WHEN cardinality(split(line, chr(9))) >= 1 "
        "THEN TRY(date_format(from_unixtime(CAST(NULLIF(element_at(split(line, chr(9)), 1), '-') AS double)), '%Y-%m-%d %H:%i:%s')) "
        "ELSE NULL END"
    ]
    for col_name, col_type in table_cols:
        if col_name in ('ts_datetime', 'dt'):
            continue
        idx = field_map.get(col_name)
        if idx is None:
            cast_type = 'varchar' if col_type == 'string' else col_type
            select_cols.append(f"CAST(NULL AS {cast_type})")
            continue
        base_expr = f"NULLIF(element_at(split(line, chr(9)), {idx}), '-')"
        check = f"cardinality(split(line, chr(9))) >= {idx}"
        if col_type == 'double':
            expr = f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS double) ELSE NULL END"
        elif col_type == 'int':
            expr = f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS int) ELSE NULL END"
        elif col_type == 'bigint':
            expr = f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS bigint) ELSE NULL END"
        elif col_type == 'boolean':
            expr = (f"CASE WHEN {check} THEN CASE WHEN {base_expr} = 'T' THEN true "
                    f"WHEN {base_expr} = 'F' THEN false ELSE NULL END ELSE NULL END")
        else:
            expr = f"CASE WHEN {check} THEN {base_expr} ELSE NULL END"
        select_cols.append(expr)

    select_cols.append(f"'{date_str}'")
    select_str = ',\n    '.join(select_cols)

    ts_filter = (f"TRY_CAST(NULLIF(element_at(split(line, chr(9)), 1), '-') AS double) > {last_ts}"
                 if last_ts else "1=1")

    table_name = log_type.replace('-', '_')
    query = f"""
INSERT INTO {GLUE_DATABASE}.{table_name}
SELECT
    {select_str}
FROM {GLUE_DATABASE}.corelight_raw
WHERE dt = '{date_str}'
  AND "$path" LIKE '%/{log_type}_%'
  AND NOT line LIKE '#%'
  AND {ts_filter}
"""
    print(f"  Loading {log_type}/dt={date_str} (ts > {last_ts or 0})")
    _, state, reason = run_athena_query(query, timeout=840, retries=3)
    if state != 'SUCCEEDED':
        print(f"  INSERT FAILED: {(reason or '')[:160]}")
        return False, None

    max_query = f"SELECT MAX(ts) FROM {GLUE_DATABASE}.{table_name} WHERE dt = '{date_str}'"
    max_id, max_state, _ = run_athena_query(max_query, timeout=120, retries=2)
    new_max_ts = last_ts
    if max_state == 'SUCCEEDED':
        res = athena.get_query_results(QueryExecutionId=max_id)
        rows = res.get('ResultSet', {}).get('Rows', [])
        if len(rows) > 1:
            val = rows[1]['Data'][0].get('VarCharValue')
            if val:
                try:
                    new_max_ts = float(val)
                except ValueError:
                    pass
    print(f"  SUCCESS (new max ts: {new_max_ts})")
    return True, new_max_ts


def invoke_worker(log_type, date_str):
    lambda_client.invoke(
        FunctionName=SELF_FUNCTION_NAME,
        InvocationType='Event',
        Payload=json.dumps({'log_type': log_type, 'date': date_str}).encode('utf-8'),
    )


def invoke_dispatcher(date_str):
    lambda_client.invoke(
        FunctionName=SELF_FUNCTION_NAME,
        InvocationType='Event',
        Payload=json.dumps({'date': date_str}).encode('utf-8'),
    )


def _catalog_columns():
    """{table_name: {column names}} for every real table, partitions included.

    get_existing_tables() only returns tables under the parquet prefix and drops
    partition keys; the views need dt, so read the catalog directly.
    """
    catalog = {}
    paginator = glue.get_paginator('get_tables')
    for page in paginator.paginate(DatabaseName=GLUE_DATABASE):
        for t in page['TableList']:
            if t.get('TableType') == 'VIRTUAL_VIEW':
                continue
            cols = {c['Name'] for c in t.get('StorageDescriptor', {}).get('Columns', [])}
            cols |= {p['Name'] for p in t.get('PartitionKeys', [])}
            catalog[t['Name']] = cols
    return catalog


def rebuild_derived_views():
    """Regenerate alerts / uid_lookup / fuid_lookup from the live catalog.

    Runs every invocation, not just when a table was created: a log type can gain
    columns, and CREATE OR REPLACE VIEW is cheap (metadata only, no data scanned).

    This is what makes a net-new log type self-integrating. When the sensor first
    emits `rdp`, or the anomaly detector finishes baselining and starts writing,
    the table gets created above and the next line folds it into the views with no
    code change. The previous hand-maintained views drifted for exactly this
    reason: uid_lookup covered 9 tables while 37 carried a uid.
    """
    catalog = _catalog_columns()
    ddl = derived_views.build_view_ddl(GLUE_DATABASE, catalog)
    rebuilt, failed = [], []
    for view, sql in ddl.items():
        _, state, reason = run_athena_query(sql, timeout=120, retries=2)
        if state == 'SUCCEEDED':
            rebuilt.append(view)
        else:
            # A broken view is worse than a stale one: the previous definition
            # stays in place, so log loudly and keep going.
            failed.append({'view': view, 'reason': (reason or '')[:200]})
            print(f"  VIEW REBUILD FAILED {view}: {(reason or '')[:200]}")
    print(f"derived views rebuilt={rebuilt} failed={[f['view'] for f in failed]}")
    return {'rebuilt': rebuilt, 'failed': failed}


def rebuild_asset_classification(date_str):
    """Materialize asset_classification for one partition.

    A CTAS rather than a view: the inference is several joins plus window functions
    over conn/http/ssl, so evaluating it per query would be slow and expensive.
    Dropping and recreating is idempotent, which matters because this runs hourly
    and the day's data keeps growing.
    """
    catalog = _catalog_columns()
    table = asset_classification.table_name(date_str)
    # No external_location: this workgroup sets EnforceWorkGroupConfiguration, so
    # Athena rejects a CTAS that names its own output path. It therefore picks a
    # random UUID prefix under the workgroup's location, and DROP TABLE removes only
    # the catalog entry, leaving the data behind. So read the location OFF the
    # existing table first and delete that, rather than guessing where it lives.
    ddl = asset_classification.build_ctas(GLUE_DATABASE, date_str, catalog)
    if not ddl:
        print("asset_classification: source tables absent, skipped")
        return {'built': False, 'reason': 'sources_absent'}

    stale_location = None
    try:
        existing = glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)['Table']
        stale_location = existing.get('StorageDescriptor', {}).get('Location')
    except glue.exceptions.EntityNotFoundException:
        pass

    _, drop_state, drop_reason = run_athena_query(
        f"DROP TABLE IF EXISTS {GLUE_DATABASE}.{table}", timeout=120, retries=1)
    if drop_state != 'SUCCEEDED':
        # Do NOT proceed to the CTAS: it would fail TABLE_ALREADY_EXISTS with a
        # message pointing at the table rather than the real cause. This exact
        # ignored return value hid a missing glue:DeleteTable grant for hours: the
        # first run worked (nothing to drop) and every run after failed with a
        # misleading error. Surface the DROP's own reason instead.
        print(f"  DROP {table} FAILED: {(drop_reason or '')[:300]}")
        return {'built': False, 'reason': f"drop_failed: {(drop_reason or '')[:200]}"}
    print(f"  DROP {table}: SUCCEEDED")

    # Belt and braces after a SUCCEEDED drop: Glue is eventually consistent, so poll
    # until the table is actually gone rather than sleeping a guessed interval. The
    # real cause of the original "not visible" was a failed DROP, now caught above.
    for attempt in range(20):
        try:
            glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)
        except glue.exceptions.EntityNotFoundException:
            break
        time.sleep(1.5)
    else:
        try:
            surviving = glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)['Table']
            print(f"  {table} STILL PRESENT after DROP: type={surviving.get('TableType')} "
                  f"loc={surviving.get('StorageDescriptor',{}).get('Location')} "
                  f"created={surviving.get('CreateTime')}")
        except Exception as exc:
            print(f"  paradox: poll said present but get_table now says {type(exc).__name__}")
        return {'built': False, 'reason': 'drop_not_visible'}

    if stale_location and stale_location.startswith('s3://'):
        bucket, _, prefix = stale_location[5:].partition('/')
        deleted = 0
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
            keys = [{'Key': o['Key']} for o in page.get('Contents', [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={'Objects': keys})
                deleted += len(keys)
        print(f"  cleared {deleted} objects from the previous build at {prefix}")

    _, state, reason = run_athena_query(ddl, timeout=600, retries=1)
    if state != 'SUCCEEDED':
        print(f"  asset_classification FAILED: {(reason or '')[:200]}")
        return {'built': False, 'reason': (reason or '')[:200]}

    # Point the stable `asset_classification` name at the newest partition so the
    # agents query one name instead of guessing the date suffix.
    view = (f"CREATE OR REPLACE VIEW {GLUE_DATABASE}.asset_classification AS "
            f"SELECT * FROM {GLUE_DATABASE}.{table}")
    _, v_state, v_reason = run_athena_query(view, timeout=120, retries=1)
    if v_state != 'SUCCEEDED':
        print(f"  asset_classification view FAILED: {(v_reason or '')[:200]}")
        return {'built': True, 'view': False, 'reason': (v_reason or '')[:200]}
    print(f"asset_classification rebuilt -> {table}")
    return {'built': True, 'view': True, 'table': table}


def _rebuild_materialized(module, label, date_str, timeout=900):
    """DROP + CTAS + re-point the stable view, for a per-day materialized table.

    Shared by asset_classification and entity_context because they need the exact
    same dance, including the two traps it exists to avoid:

      * the workgroup sets EnforceWorkGroupConfiguration, so a CTAS may NOT name
        its own external_location. Athena picks a random UUID prefix, and DROP
        TABLE removes only the catalog entry, so the data survives and the next
        CTAS fails TABLE_ALREADY_EXISTS against an orphan. Read the location off
        the existing table and delete it.
      * a failed DROP must be fatal. Ignoring its return state hid a missing
        glue:DeleteTable grant: the first run worked and every run after failed
        with a misleading downstream error.
    """
    catalog = _catalog_columns()
    table = module.table_name(date_str)
    ddl = module.build_ctas(GLUE_DATABASE, date_str, catalog)
    if not ddl:
        print(f"{label}: source tables absent, skipped")
        return {'built': False, 'reason': 'sources_absent'}

    stale_location = None
    try:
        existing = glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)['Table']
        stale_location = existing.get('StorageDescriptor', {}).get('Location')
    except glue.exceptions.EntityNotFoundException:
        pass

    _, drop_state, drop_reason = run_athena_query(
        f"DROP TABLE IF EXISTS {GLUE_DATABASE}.{table}", timeout=120, retries=1)
    if drop_state != 'SUCCEEDED':
        print(f"  DROP {table} FAILED: {(drop_reason or '')[:300]}")
        return {'built': False, 'reason': f"drop_failed: {(drop_reason or '')[:200]}"}

    for _ in range(20):
        try:
            glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)
        except glue.exceptions.EntityNotFoundException:
            break
        time.sleep(1.5)
    else:
        return {'built': False, 'reason': 'drop_not_visible'}

    if stale_location and stale_location.startswith('s3://'):
        bucket, _, prefix = stale_location[5:].partition('/')
        deleted = 0
        for page in s3.get_paginator('list_objects_v2').paginate(Bucket=bucket, Prefix=prefix):
            keys = [{'Key': o['Key']} for o in page.get('Contents', [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={'Objects': keys})
                deleted += len(keys)
        if deleted:
            print(f"  cleared {deleted} objects from the previous {label} build")

    _, state, reason = run_athena_query(ddl, timeout=timeout, retries=1)
    if state != 'SUCCEEDED':
        print(f"  {label} FAILED: {(reason or '')[:250]}")
        return {'built': False, 'reason': (reason or '')[:200]}

    stable = label
    view = (f"CREATE OR REPLACE VIEW {GLUE_DATABASE}.{stable} AS "
            f"SELECT * FROM {GLUE_DATABASE}.{table}")
    _, v_state, v_reason = run_athena_query(view, timeout=120, retries=1)
    if v_state != 'SUCCEEDED':
        print(f"  {label} view FAILED: {(v_reason or '')[:200]}")
        return {'built': True, 'view': False, 'reason': (v_reason or '')[:200]}
    print(f"{label} rebuilt -> {table}")
    return {'built': True, 'view': True, 'table': table}


def dispatch_for_date(date_str):
    log_types = get_log_types_in_s3(date_str)
    if not log_types:
        print(f"No log types found under s3://{S3_LOG_BUCKET}/{S3_LOG_PREFIX}/{date_str}/")
        return {'date': date_str, 'fanned_out': 0}

    existing_tables = get_existing_tables()
    created, failed_create = [], []
    for log_type in sorted(log_types):
        table_name = log_type.replace('-', '_')
        if table_name in existing_tables:
            continue
        print(f"Creating table for {log_type}...")
        if create_new_table(log_type, date_str):
            created.append(log_type)
        else:
            failed_create.append(log_type)
    if created:
        existing_tables = get_existing_tables()

    fanned = 0
    for log_type in sorted(log_types):
        table_name = log_type.replace('-', '_')
        if table_name not in existing_tables:
            continue
        invoke_worker(log_type, date_str)
        fanned += 1

    # Rebuild AFTER table creation so a brand-new log type is already in the
    # catalog and gets picked up on the same run that created it.
    views = rebuild_derived_views()
    assets = rebuild_asset_classification(date_str)
    # LAST: entity_context aggregates over alerts, uid_lookup and
    # asset_classification, so all of those must already be current.
    entities = _rebuild_materialized(entity_context, 'entity_context', date_str)

    result = {
        'date': date_str,
        'log_types_found': len(log_types),
        'tables_created': created,
        'table_create_failures': failed_create,
        'workers_dispatched': fanned,
        'derived_views': views,
        'asset_classification': assets,
        'entity_context': entities,
    }
    print(json.dumps(result))
    return result


def process_single(log_type, date_str, context):
    existing_tables = get_existing_tables()
    table_name = log_type.replace('-', '_')
    if table_name not in existing_tables:
        print(f"Creating table for {log_type}...")
        if not create_new_table(log_type, date_str):
            return {'status': 'table_create_failed', 'log_type': log_type, 'date': date_str}
        existing_tables = get_existing_tables()

    last_ts = get_watermark(log_type, date_str)
    success, new_ts = incremental_load(log_type, existing_tables[table_name], date_str, last_ts)
    if success and new_ts and new_ts > last_ts:
        save_watermark(log_type, date_str, new_ts)
        return {'status': 'loaded', 'log_type': log_type, 'date': date_str,
                'last_ts': last_ts, 'new_ts': new_ts}
    if success:
        return {'status': 'no_new_data', 'log_type': log_type, 'date': date_str, 'last_ts': last_ts}
    return {'status': 'insert_failed', 'log_type': log_type, 'date': date_str, 'last_ts': last_ts}


def daterange(start_date, end_date):
    start = datetime.strptime(start_date, '%Y-%m-%d').date()
    end = datetime.strptime(end_date, '%Y-%m-%d').date()
    cur = start
    while cur <= end:
        yield cur.strftime('%Y-%m-%d')
        cur += timedelta(days=1)


def handler(event, context):
    print(f"Event: {json.dumps(event)}")

    if 'log_type' in event and 'date' in event:
        return process_single(event['log_type'], event['date'], context)

    if 'start_date' in event and 'end_date' in event:
        dispatched = []
        for d in daterange(event['start_date'], event['end_date']):
            invoke_dispatcher(d)
            dispatched.append(d)
        return {'status': 'backfill_dispatched', 'dates': dispatched}

    date_str = event.get('date') or datetime.now(timezone.utc).strftime('%Y-%m-%d')
    return dispatch_for_date(date_str)
