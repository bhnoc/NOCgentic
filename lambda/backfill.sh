#!/usr/bin/env bash
# Reload one or more (log_type, date) partitions from the raw logs.
#
# WHY THIS IS NEEDED. The loader reads raw TSV by FIELD POSITION and appends with
# INSERT INTO under a watermark, so a partition keeps whatever offsets were in force
# the hour it was written. Fixing the reader does nothing for data already loaded:
# the geo columns, ssl.user_agent, known_users.user_ and the smtp columns stay wrong
# until their partition is re-read, and conn keeps the conn_long rows it ingested
# through the old unanchored $path filter.
#
# WHAT IT DOES, per (log_type, date):
#   1. delete the Parquet objects under parquet/<log_type>/dt=<date>/
#   2. delete the watermark at _watermarks/v6/<log_type>/<date>.json
#   3. invoke the Lambda for that log type and date, which reloads from ts=0
#
# DESTRUCTIVE. Step 1 deletes derived Parquet, not source logs -- the raw .log.gz
# files in S3 are untouched and are the actual system of record, which is what makes
# this recoverable. Still, it drops a partition's rows for as long as the reload takes.
#
#   ./lambda/backfill.sh --list                       # what would run, no changes
#   ./lambda/backfill.sh --dry-run conn 2026-08-01
#   ./lambda/backfill.sh conn 2026-08-01              # one partition
#   ./lambda/backfill.sh --all-affected               # every known-bad partition
set -euo pipefail

PROFILE="${AWS_PROFILE_OVERRIDE:-ProductResearch-admins}"
REGION="us-east-2"
FUNCTION="blackhatnoc-athena-refresh"
BUCKET="blackhatnoc"
PARQUET_PREFIX="corelight/usa2026/parquet"
WATERMARK_PREFIX="corelight/usa2026/_watermarks/v6"

# Black Hat USA 2026 only. Deliberately not parameterised: an accidental wider range
# would rewrite partitions nobody asked about.
DATES=(2026-07-31 2026-08-01 2026-08-02)

# Every log type whose loaded data is provably wrong, and why:
#   mid-schema header variants shifting positions -> conn conn_long ssl http
#     (quic also has two headers but APPENDS, so its offsets never moved)
#   foreign rows via the unanchored $path filter  -> conn dce_rpc dhcp files ldap profinet
#   reserved-word rename the loader stopped binding -> known_users smtp
AFFECTED=(conn conn_long ssl http dce_rpc dhcp files ldap profinet known_users smtp)

DRY_RUN=false
LIST=false
ALL=false
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --dry-run)      DRY_RUN=true ;;
        --list)         LIST=true ;;
        --all-affected) ALL=true ;;
        -*) echo "unknown flag: $arg" >&2; exit 2 ;;
        *)  ARGS+=("$arg") ;;
    esac
done

if [[ "$LIST" == true ]]; then
    echo "log types (${#AFFECTED[@]}):"
    printf '  %s\n' "${AFFECTED[@]}"
    echo "dates (${#DATES[@]}): ${DATES[*]}"
    echo "total partitions: $(( ${#AFFECTED[@]} * ${#DATES[@]} ))"
    exit 0
fi

reload_one() {
    local log_type="$1" date_str="$2"
    # Validate rather than trusting the caller: these values are interpolated into an
    # S3 prefix, and a stray '../' or an empty string would target the wrong data.
    if [[ ! "$log_type" =~ ^[a-z0-9_-]+$ ]]; then
        echo "ERROR: bad log type '${log_type}'" >&2; return 1
    fi
    if [[ ! "$date_str" =~ ^2026-[0-9]{2}-[0-9]{2}$ ]]; then
        echo "ERROR: bad date '${date_str}'" >&2; return 1
    fi

    local pq="s3://${BUCKET}/${PARQUET_PREFIX}/${log_type}/dt=${date_str}/"
    local wm="s3://${BUCKET}/${WATERMARK_PREFIX}/${log_type}/${date_str}.json"

    if [[ "$DRY_RUN" == true ]]; then
        local n
        n=$(aws s3 ls "$pq" --recursive --profile "$PROFILE" --region "$REGION" 2>/dev/null | wc -l | tr -d ' ')
        echo "  [dry-run] ${log_type}/${date_str}: would delete ${n} parquet object(s) + watermark, then reload"
        return 0
    fi

    echo "==> ${log_type}/dt=${date_str}"
    aws s3 rm "$pq" --recursive --quiet --profile "$PROFILE" --region "$REGION" 2>/dev/null || true
    aws s3 rm "$wm" --quiet --profile "$PROFILE" --region "$REGION" 2>/dev/null || true

    # The Lambda reloads from ts=0 now that the watermark is gone. Its own reply carries
    # the outcome; a non-zero exit here means the invoke itself failed.
    local out
    out=$(aws lambda invoke --function-name "$FUNCTION" \
            --payload "$(printf '{"log_type":"%s","date":"%s"}' "$log_type" "$date_str" | base64)" \
            --profile "$PROFILE" --region "$REGION" \
            --cli-read-timeout 900 /dev/stdout 2>/dev/null | head -1)
    echo "    ${out}"
    case "$out" in
        *'"status": "loaded"'*|*'"status": "no_new_data"'*) return 0 ;;
        # A log type that emitted no files at all that day has no #fields header to
        # read, so the load reports insert_failed. Not every log type runs every day
        # (known_users has zero raw files on 2026-07-31), and treating that as an error
        # would make a clean backfill look broken. Confirm the source really is empty
        # rather than assuming it.
        *'"status": "insert_failed"'*|*'"status": "table_create_failed"'*)
            local raw
            raw=$(aws s3 ls "s3://${BUCKET}/corelight/usa2026/${date_str}/" \
                    --profile "$PROFILE" --region "$REGION" 2>/dev/null \
                  | grep -cE "[[:space:]]${log_type}_[0-9]{8}_" || true)
            if [[ "$raw" == "0" ]]; then
                echo "    (no raw ${log_type} files on ${date_str}; nothing to load)"
                return 0
            fi
            echo "    ERROR: ${raw} raw file(s) exist but the load failed" >&2
            return 1 ;;
        *) echo "    WARNING: unexpected status, inspect before continuing" >&2; return 1 ;;
    esac
}

if [[ "$ALL" == true ]]; then
    total=$(( ${#AFFECTED[@]} * ${#DATES[@]} ))
    if [[ "$DRY_RUN" != true ]]; then
        echo "About to reload ${total} partitions on the LIVE Black Hat NOC."
        echo "Parquet for each is deleted and rebuilt from the raw logs."
        read -r -p "Type 'reload' to continue: " ok
        [[ "$ok" == "reload" ]] || { echo "aborted"; exit 1; }
    fi
    failed=()
    # Smallest log types first: if the mechanism is broken, it should be proven wrong on
    # 70 rows of smtp rather than 122M rows of conn.
    for log_type in smtp dce_rpc known_users ldap profinet conn_long dhcp files http ssl conn; do
        for date_str in "${DATES[@]}"; do
            reload_one "$log_type" "$date_str" || failed+=("${log_type}/${date_str}")
        done
    done
    if (( ${#failed[@]} )); then
        echo; echo "FAILED (${#failed[@]}): ${failed[*]}" >&2; exit 1
    fi
    echo; echo "all ${total} partitions reloaded"
    exit 0
fi

if (( ${#ARGS[@]} != 2 )); then
    echo "usage: $0 [--dry-run] <log_type> <date>   |   $0 --all-affected   |   $0 --list" >&2
    exit 2
fi
reload_one "${ARGS[0]}" "${ARGS[1]}"
