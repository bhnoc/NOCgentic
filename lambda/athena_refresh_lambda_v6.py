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

import derived_views
import json
import os
import time
import re
from datetime import datetime, timezone, timedelta

# All config is env-driven so one code artifact serves any tenant/dataset
# (dev vs show) without hardcoded account/project names.
REGION = os.environ.get('REGION', 'us-west-2')
S3_LOG_BUCKET = os.environ.get('S3_LOG_BUCKET', 'blackhat-pope-dev-logs')
S3_LOG_PREFIX = os.environ.get('S3_LOG_PREFIX', 'bh-asia-26/corelight')
S3_PARQUET_BUCKET = os.environ.get('S3_PARQUET_BUCKET', 'blackhat-pope-parquet')
S3_PARQUET_PREFIX = os.environ.get('S3_PARQUET_PREFIX', '').strip('/')
WATERMARK_PREFIX = os.environ.get('WATERMARK_PREFIX', '_watermarks/v6')
GLUE_DATABASE = os.environ.get('GLUE_DATABASE', 'blackhat_pope_logs')
ATHENA_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', 'blackhat-pope-dev')
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
    name = re.sub(r'[.\-]', '_', field_name)
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)
    if name and name[0].isdigit():
        name = 'f_' + name
    reserved = {'from', 'to', 'date', 'time', 'user', 'group', 'order',
                'table', 'index', 'database', 'schema', 'column', 'row',
                'select', 'insert', 'update', 'delete', 'create', 'drop'}
    if name.lower() in reserved:
        name = name + '_'
    return name.lower()


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

    columns = ["ts_datetime string"]
    for field in fields:
        col_name = sanitize_column_name(field)
        col_type = 'DOUBLE' if field.lower() == 'ts' else 'string'
        columns.append(f"{col_name} {col_type}")

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

    result = {
        'date': date_str,
        'log_types_found': len(log_types),
        'tables_created': created,
        'table_create_failures': failed_create,
        'workers_dispatched': fanned,
        'derived_views': views,
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
