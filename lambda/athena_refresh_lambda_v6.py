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
import device_links
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


def path_predicate(log_type):
    """A `$path` filter that matches THIS log type and no other.

    Filenames are `<log_type>_<YYYYMMDD>_<HH:MM:SS>-...log.gz`, so the obvious
    `LIKE '%/conn_%'` also matches `conn_long_20260801_...`. SIX tables were loading a
    foreign log type's rows on top of their own, with a different field order:
    conn<-conn_long, dce_rpc<-dce_rpc_activity, dhcp<-dhcp_fp_lite,
    files<-files_metadata, ldap<-ldap_search, profinet<-profinet_dce_rpc.

    Anchoring on the 8-digit date that always follows the name is what makes the
    boundary explicit -- the same class of bug as an unanchored SNI substring, and the
    same fix. `_` is a single-character wildcard in SQL LIKE, so REGEXP_LIKE is used
    rather than a LIKE pattern that would silently match `connXlong`.
    """
    return f"""REGEXP_LIKE("$path", '/{re.escape(log_type)}_[0-9]{{8}}_')"""


def get_schemas_from_raw(log_type, date_str):
    """Every DISTINCT `#fields` header for this log type, keyed by field count.

    ONE header is not enough. Measured on dt=2026-08-01: `conn` ships two headers,
    68 fields and 70, because `cli_rtt`/`svr_rtt` are optional and appear MID-SCHEMA --
    everything after them shifts by two. `conn_long` likewise (72/74), and http, quic
    and ssl each have two.

    The old code read one header via LIMIT 1 and applied its positional offsets to
    every row of every shape. That silently misaligned the tail of the wider variant:
    `remote_country` sits at 1-based 62 in one conn header and 64 in the other, so the
    column labelled 'country' was actually holding `remote_city`'s hash. The comment in
    entity_context blamed "40-char hex hashes" in the data; the data was fine and the
    read was shifted.

    Field COUNT is the discriminator, verified sufficient: every variant of every log
    type has a distinct count, so `cardinality(split(line, chr(9)))` picks the right
    map per row without needing to inspect the header inline.
    """
    query = f"""
    SELECT DISTINCT line FROM corelight_raw
    WHERE dt = '{date_str}' AND line LIKE '#fields%' AND {path_predicate(log_type)}
    """
    query_id, state, _ = run_athena_query(query, timeout=120, retries=2)
    if state != 'SUCCEEDED':
        return None
    results = athena.get_query_results(QueryExecutionId=query_id)
    rows = results.get('ResultSet', {}).get('Rows', [])
    schemas = {}
    for row in rows[1:]:
        line = (row['Data'][0].get('VarCharValue') or '')
        if not line.startswith('#fields'):
            continue
        fields = line.replace('#fields\t', '', 1).split('\t')
        fields = [f for f in fields if f != '']
        if fields:
            # Keyed by the DATA row's field count, which is what the loader can test
            # per row. A '#fields' line carries one extra leading token.
            schemas[len(fields)] = fields
    return schemas or None


def get_schema_from_raw(log_type, date_str):
    """The WIDEST header, for DDL only.

    The table needs a column for every field any variant emits, so the widest header
    is the right one to build columns from -- a narrower variant simply leaves the
    extra columns NULL for its rows. Reading a narrow header here would permanently
    lose the optional fields for every row.
    """
    schemas = get_schemas_from_raw(log_type, date_str)
    if not schemas:
        return None
    return schemas[max(schemas)]


def columns_for_fields(fields):
    """(column name, DDL type) per raw field, deduped, in header order.

    Shared by CREATE and the ALTER reconciliation so the two can never disagree about
    what a field is called -- a mismatch there is exactly how `user_` came to exist in
    a table whose loader was looking for `user`.
    """
    columns = [('ts_datetime', 'string')]
    seen = {'ts_datetime'}
    for field in fields:
        col_name = sanitize_column_name(field)
        # Two raw fields can sanitize to the same name (e.g. `id.orig_h` and
        # `id-orig_h`). A duplicate column makes CREATE TABLE fail, so keep the
        # first and skip the rest rather than losing the whole table.
        if not col_name or col_name in seen:
            continue
        seen.add(col_name)
        columns.append((col_name, 'DOUBLE' if field.lower() == 'ts' else 'string'))
    return columns


def reconcile_table_columns(log_type, date_str, existing_cols):
    """ADD COLUMNS for header fields the live table has no column for.

    WHY THIS EXISTS. `CREATE TABLE IF NOT EXISTS` runs once and never again, so a table
    is frozen at the schema of the day it was created -- but Corelight keeps ADDING
    fields. Measured on dt=2026-08-01, every multi-variant table was missing the newer
    field outright: cli_rtt/svr_rtt (conn, conn_long), hs_delay (ssl, quic),
    tx_delay/trans_time (http). The loader read them correctly and then had nowhere to
    put them, so they were dropped on every run with no error.

    Purely ADDITIVE. Columns are never dropped, renamed or retyped: an unexpected column
    is harmless, whereas dropping one that a view or an agent's SQL still references
    breaks reads. That also makes this safe to run on every pass -- it is a no-op once
    the table is current.

    Returns the list of added column names (empty if already current).
    """
    fields = get_schema_from_raw(log_type, date_str)
    if not fields:
        return []
    have = {c for c, _ in existing_cols}
    # A column the loader would bind via the trailing-underscore fallback already has a
    # home, so it is NOT missing. Without this, a table carrying the old `user_` would
    # get a SECOND column named `user` and the two would split the data between them.
    missing = [(c, t) for c, t in columns_for_fields(fields)
               if c not in have and f"{c}_" not in have]
    if not missing:
        return []
    table_name = log_type.replace('-', '_')
    added = ', '.join(f"{quote_column(c)} {t.lower()}" for c, t in missing)
    query = f"ALTER TABLE {GLUE_DATABASE}.{table_name} ADD COLUMNS ({added})"
    _, state, reason = run_athena_query(query, timeout=120, retries=2)
    if state != 'SUCCEEDED':
        # Not fatal: the load still works for every column that does exist, and failing
        # the whole refresh over an additive DDL would trade a missing field for a
        # missing hour of data.
        print(f"  ALTER TABLE {table_name} failed: {(reason or '')[:160]}")
        return []
    names = [c for c, _ in missing]
    print(f"  {table_name}: added {len(names)} column(s): {', '.join(names)}")
    return names


def create_new_table(log_type, date_str):
    fields = get_schema_from_raw(log_type, date_str)
    if not fields:
        print(f"  Could not get schema for {log_type}")
        return False

    columns_str = ',\n  '.join(
        f"{quote_column(c)} {t}" for c, t in columns_for_fields(fields))
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


def resolve_field_index(field_map, col_name):
    """The raw-field position for an existing table column, tolerating the old rename.

    THE SCAR THIS EXISTS FOR. The loader used to rename reserved words by appending an
    underscore (`user` -> `user_`), then commit 9b2549a switched to backtick-quoting
    and dropped the rename. But `CREATE TABLE IF NOT EXISTS` never rewrites a table
    that already exists, so tables created under the old scheme still have `user_`
    while the raw header says `user` -- the lookup missed and `incremental_load`
    emitted `CAST(NULL AS varchar)` for every row. known_users.user_ went from
    populated to exactly zero the hour that commit shipped, and smtp's date_/from_/to_
    with it.

    Trailing underscores are stripped ONLY as a fallback, so a log type that genuinely
    has a `foo_` field still binds to `foo_` first and is never silently redirected.
    """
    idx = field_map.get(col_name)
    if idx is not None:
        return idx
    if col_name.endswith('_'):
        return field_map.get(col_name.rstrip('_'))
    return None


def incremental_load(log_type, table_cols, date_str, last_ts):
    schemas = get_schemas_from_raw(log_type, date_str)
    if not schemas:
        return False, None

    # One field map PER HEADER SHAPE, keyed by the row's field count. A log type with
    # optional mid-schema fields (conn's cli_rtt/svr_rtt) shifts every position after
    # them, so a single map read off one header misaligns the whole tail of the other
    # variant. See get_schemas_from_raw.
    field_maps = {
        nf: {sanitize_column_name(f): i + 1 for i, f in enumerate(fields)}
        for nf, fields in schemas.items()
    }
    nfields = "cardinality(split(line, chr(9)))"

    select_cols = [
        "CASE WHEN cardinality(split(line, chr(9))) >= 1 "
        "THEN TRY(date_format(from_unixtime(CAST(NULLIF(element_at(split(line, chr(9)), 1), '-') AS double)), '%Y-%m-%d %H:%i:%s')) "
        "ELSE NULL END"
    ]
    for col_name, col_type in table_cols:
        if col_name in ('ts_datetime', 'dt'):
            continue
        # Position per variant. Identical across variants for every field ahead of the
        # optional block, which is the common case and collapses back to one arm.
        by_idx = {}
        for nf, fmap in field_maps.items():
            idx = resolve_field_index(fmap, col_name)
            if idx is not None:
                by_idx.setdefault(idx, []).append(nf)

        cast_type = 'varchar' if col_type == 'string' else col_type
        if not by_idx:
            select_cols.append(f"CAST(NULL AS {cast_type})")
            continue

        def _typed(idx):
            base_expr = f"NULLIF(element_at(split(line, chr(9)), {idx}), '-')"
            check = f"{nfields} >= {idx}"
            if col_type == 'double':
                return f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS double) ELSE NULL END"
            if col_type == 'int':
                return f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS int) ELSE NULL END"
            if col_type == 'bigint':
                return f"CASE WHEN {check} THEN TRY_CAST({base_expr} AS bigint) ELSE NULL END"
            if col_type == 'boolean':
                return (f"CASE WHEN {check} THEN CASE WHEN {base_expr} = 'T' THEN true "
                        f"WHEN {base_expr} = 'F' THEN false ELSE NULL END ELSE NULL END")
            return f"CASE WHEN {check} THEN {base_expr} ELSE NULL END"

        # The shortcut is ONLY safe when the field sits at the same position in EVERY
        # variant. A field present in just one of them must stay guarded: cli_rtt is at
        # position 49 in conn's 70-field header and ABSENT from the 68-field one, so an
        # unguarded read would pull position 49 of a narrow row -- 'inner_vlan' -- and
        # file it under cli_rtt. That is the same misalignment this function exists to
        # fix, so collapsing on `len(by_idx) == 1` alone would have reintroduced it.
        covered = sum(len(nfs) for nfs in by_idx.values())
        if len(by_idx) == 1 and covered == len(field_maps):
            select_cols.append(_typed(next(iter(by_idx))))
            continue
        # The position differs by variant, or the field is missing from some variant.
        # Either way, dispatch on the row's own field count. A count matching no known
        # header falls to NULL rather than guessing a position: a wrong offset ships a
        # real value under the wrong column name, which is worse than an absent one.
        arms = "".join(
            f" WHEN {nfields} IN ({', '.join(str(n) for n in sorted(nfs))}) "
            f"THEN {_typed(idx)}"
            for idx, nfs in sorted(by_idx.items())
        )
        select_cols.append(f"CASE{arms} ELSE CAST(NULL AS {cast_type}) END")

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
  AND {path_predicate(log_type)}
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


def _table_column_order(table):
    """Column names for one table in CATALOG ORDER.

    _catalog_columns returns sets, which is fine for presence tests but useless for
    building a positional UNION — the arms have to agree on order, and a set does
    not have one.
    """
    try:
        t = glue.get_table(DatabaseName=GLUE_DATABASE, Name=table)['Table']
    except Exception as exc:  # table may not exist yet on a first run
        print(f"  column order unavailable for {table}: {exc}")
        return []
    cols = [c['Name'] for c in t.get('StorageDescriptor', {}).get('Columns', [])]
    cols += [p['Name'] for p in t.get('PartitionKeys', [])]
    return cols


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


def _stable_view_ddl(stable, newest_table):
    """CREATE OR REPLACE VIEW over EVERY daily partition table, newest included.

    Pinning the view at a single day is a silent-wrong-answer bug, not a staleness
    bug. `asset_classification` pointed only at 2026_08_02, so a perfectly
    reasonable `WHERE dt = '2026-08-01'` returned ZERO rows while 108,686 sat in
    asset_classification_2026_08_01 — no error, just an empty result an agent
    reports as "no data". Three QA validators lost queries to it.

    Each arm names its columns EXPLICITLY, in the newest partition's order, with
    CAST(NULL AS VARCHAR) for any column that partition lacks. `UNION ALL BY NAME`
    would express this directly but Athena rejects it ("mismatched input 'BY'"), and
    a bare `SELECT *` union is positional: the per-day tables are built from a
    discovered catalog, so an older partition can have fewer columns than today's
    and positional matching would silently transpose values between columns. A
    wrong value under a right column name is the worst outcome available here.
    """
    catalog = _catalog_columns()
    tables = sorted(t for t in catalog if t.startswith(f"{stable}_"))
    if newest_table not in tables:
        tables.append(newest_table)
        tables.sort()
    if not tables:
        return None

    # The newest partition defines the column set and its order.
    order = _table_column_order(newest_table) or sorted(catalog.get(newest_table, ()))
    if not order:
        return None

    arms = []
    for t in tables:
        have = catalog.get(t, set())
        cols = ", ".join(
            (f'"{c}"' if c in have else f'CAST(NULL AS VARCHAR) AS "{c}"')
            for c in order
        )
        arms.append(f"SELECT {cols} FROM {GLUE_DATABASE}.{t}")
    return (f"CREATE OR REPLACE VIEW {GLUE_DATABASE}.{stable} AS "
            + " UNION ALL ".join(arms))


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

    # Point the stable `asset_classification` name at EVERY partition so the agents
    # query one name instead of guessing the date suffix, and so a dt filter for any
    # retained day still finds rows.
    view = _stable_view_ddl('asset_classification', table)
    if not view:
        print("  asset_classification view skipped: no partition tables")
        return {'built': True, 'view': False, 'reason': 'no partition tables'}
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

    view = _stable_view_ddl(label, table)
    if not view:
        print(f"  {label} view skipped: no partition tables")
        return {'built': True, 'view': False, 'reason': 'no partition tables'}
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
    # device_links reads only raw logs (ssl/ssh/dns/dhcp/known_*), so it does not
    # depend on the two above and its position here is not load-bearing.
    links = _rebuild_materialized(device_links, 'device_links', date_str)

    result = {
        'date': date_str,
        'log_types_found': len(log_types),
        'tables_created': created,
        'table_create_failures': failed_create,
        'workers_dispatched': fanned,
        'derived_views': views,
        'asset_classification': assets,
        'entity_context': entities,
        'device_links': links,
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
    elif reconcile_table_columns(log_type, date_str, existing_tables[table_name]):
        # Re-read: incremental_load builds its SELECT from the table's column list, so
        # a column added a moment ago is only populated if we see it now.
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
