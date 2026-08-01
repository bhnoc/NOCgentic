#!/usr/bin/env bash
# Package and deploy the Athena refresh Lambda.
#
# The Lambda was previously only editable through the AWS console, so its source
# lived nowhere in git. That is how the derived views (alerts, uid_lookup,
# fuid_lookup) came to be hand-made in one account and silently absent in the
# next: nothing tracked them. Everything it needs is now in this directory.
#
#   ./lambda/deploy.sh                 # deploy to the show function
#   ./lambda/deploy.sh --dev           # deploy to the dev twin
#   ./lambda/deploy.sh --dry-run       # build the zip, change nothing
#
# The two functions share ONE code artifact and differ only by env vars (see
# infra/*.json), so a fix lands in both without divergence.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${AWS_PROFILE_OVERRIDE:-ProductResearch-admins}"
REGION="us-east-2"
FUNCTION="blackhatnoc-athena-refresh"
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --dev)     FUNCTION="blackhatnoc-athena-refresh-dev" ;;
        --dry-run) DRY_RUN=true ;;
        *) echo "unknown flag: $arg" >&2; exit 2 ;;
    esac
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Every .py in this directory. Globbing rather than naming files: the first version
# listed two modules explicitly, then asset_classification.py was added and the
# deploy silently shipped without it, so the Lambda died on import. No dependencies
# vendored: boto3 is in the runtime, and bundling it pins a version the runtime
# overrides anyway.
cp "$HERE"/*.py "$WORK/"

# Fail before upload rather than after: a syntax error here means the hourly
# refresh dies and the alert feed silently goes stale.
for f in "$WORK"/*.py; do
    python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f"
done

ZIP="$WORK/function.zip"
(cd "$WORK" && zip -q -r "$ZIP" ./*.py)
echo "==> packaged $(unzip -l "$ZIP" | tail -1 | awk '{print $2}') files, $(wc -c < "$ZIP") bytes"

if [[ "$DRY_RUN" == true ]]; then
    echo "==> dry run, not deploying"
    unzip -l "$ZIP"
    exit 0
fi

echo "==> deploying to $FUNCTION ($REGION)"
aws lambda update-function-code \
    --function-name "$FUNCTION" \
    --zip-file "fileb://$ZIP" \
    --profile "$PROFILE" --region "$REGION" \
    --query 'LastUpdateStatus' --output text

aws lambda wait function-updated \
    --function-name "$FUNCTION" --profile "$PROFILE" --region "$REGION"

echo "==> deployed. verify with a real invocation:"
echo "    aws lambda invoke --function-name $FUNCTION \\"
echo "      --payload \"\$(printf '{\"date\":\"%s\"}' \"\$(date -u +%F)\" | base64)\" \\"
echo "      --profile $PROFILE --region $REGION /dev/stdout"
echo
echo "    Check the response's derived_views.rebuilt lists all three views and"
echo "    derived_views.failed is empty. A failed view keeps its OLD definition,"
echo "    so the feed looks fine while going stale."
