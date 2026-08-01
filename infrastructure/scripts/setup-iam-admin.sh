#!/usr/bin/env bash
#
# IAM Admin User Setup Script for BH Asia 2026 NOC
#
# This script creates an IAM admin user in the MANAGEMENT account that can:
# 1. Assume roles into member accounts for deployment
# 2. Manage organization resources
# 3. NOT have root-level access (principle of least privilege)
#
# After running this script, STOP using root credentials.
#
# Usage: ./setup-iam-admin.sh [--dry-run]
#

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# Configuration
# ============================================================================

readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/setup-iam-admin-$(date +%Y%m%d-%H%M%S).log"

# IAM Configuration
readonly ADMIN_USER_NAME="nocgentic-deploy"
readonly ADMIN_GROUP_NAME="NOCgenticAdmins"
readonly PROJECT_TAG="NOCgenticNOC"

# Member account IDs (from organization setup)
readonly SECURITY_ACCOUNT_ID="${SECURITY_ACCOUNT_ID:?Set SECURITY_ACCOUNT_ID env var}"
readonly PRODUCTION_ACCOUNT_ID="${PRODUCTION_ACCOUNT_ID:?Set PRODUCTION_ACCOUNT_ID env var}"
readonly DEVELOPMENT_ACCOUNT_ID="${DEVELOPMENT_ACCOUNT_ID:?Set DEVELOPMENT_ACCOUNT_ID env var}"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# ============================================================================
# Utility Functions
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info() { log "INFO" "$@"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${LOG_FILE}"; }
error() { echo -e "${RED}[ERROR]${NC} $*" | tee -a "${LOG_FILE}" >&2; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "${LOG_FILE}"; }

die() {
    error "$@"
    exit 1
}

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    warn "Running in DRY-RUN mode - no changes will be made"
fi

# ============================================================================
# Pre-flight Checks
# ============================================================================

preflight_checks() {
    info "Running pre-flight checks..."

    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        die "AWS CLI is not installed"
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        die "jq is not installed"
    fi

    # Verify credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        die "AWS credentials not configured"
    fi

    local caller_identity
    caller_identity="$(aws sts get-caller-identity)"
    local account_id arn
    account_id="$(echo "${caller_identity}" | jq -r '.Account')"
    arn="$(echo "${caller_identity}" | jq -r '.Arn')"

    info "Current AWS Account: ${account_id}"
    info "Current ARN: ${arn}"

    # Verify this is the management account
    local mgmt_account
    mgmt_account="$(aws organizations describe-organization --query 'Organization.MasterAccountId' --output text 2>/dev/null || echo "")"

    if [[ "${account_id}" != "${mgmt_account}" ]]; then
        die "This script must be run from the management account (${mgmt_account})"
    fi

    # Verify running as root (required for initial IAM setup)
    if [[ "${arn}" != *":root" ]]; then
        warn "Not running as root. Some operations may fail."
        warn "For initial setup, root credentials are recommended."
    fi

    success "Pre-flight checks passed"
}

# ============================================================================
# IAM Policy Documents
# ============================================================================

# Policy: Allow assuming OrganizationAccountAccessRole in member accounts
get_assume_role_policy() {
    cat << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AssumeRoleInMemberAccounts",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": [
                "arn:aws:iam::${SECURITY_ACCOUNT_ID}:role/OrganizationAccountAccessRole",
                "arn:aws:iam::${PRODUCTION_ACCOUNT_ID}:role/OrganizationAccountAccessRole",
                "arn:aws:iam::${DEVELOPMENT_ACCOUNT_ID}:role/OrganizationAccountAccessRole"
            ]
        }
    ]
}
EOF
}

# Policy: Organization management (read-heavy, limited write)
get_org_management_policy() {
    cat << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "OrganizationReadAccess",
            "Effect": "Allow",
            "Action": [
                "organizations:Describe*",
                "organizations:List*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "CloudTrailReadAccess",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:Describe*",
                "cloudtrail:Get*",
                "cloudtrail:List*",
                "cloudtrail:LookupEvents"
            ],
            "Resource": "*"
        },
        {
            "Sid": "BillingReadAccess",
            "Effect": "Allow",
            "Action": [
                "ce:Get*",
                "ce:Describe*",
                "ce:List*",
                "budgets:View*",
                "budgets:Describe*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMReadAccess",
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*"
            ],
            "Resource": "*"
        },
        {
            "Sid": "IAMSelfManage",
            "Effect": "Allow",
            "Action": [
                "iam:ChangePassword",
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:GetAccessKeyLastUsed",
                "iam:GetUser",
                "iam:ListAccessKeys",
                "iam:UpdateAccessKey",
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:ListMFADevices",
                "iam:ResyncMFADevice"
            ],
            "Resource": "arn:aws:iam::*:user/\${aws:username}"
        }
    ]
}
EOF
}

# Policy: S3 access for CloudTrail bucket (read-only)
get_cloudtrail_s3_policy() {
    local mgmt_account_id
    mgmt_account_id="$(aws sts get-caller-identity --query 'Account' --output text)"

    cat << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "CloudTrailBucketReadAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::nocgentic-cloudtrail-${mgmt_account_id}",
                "arn:aws:s3:::nocgentic-cloudtrail-${mgmt_account_id}/*"
            ]
        }
    ]
}
EOF
}

# ============================================================================
# IAM Setup Functions
# ============================================================================

create_iam_group() {
    info "Creating IAM group: ${ADMIN_GROUP_NAME}..."

    # Check if group exists
    if aws iam get-group --group-name "${ADMIN_GROUP_NAME}" &> /dev/null; then
        info "Group '${ADMIN_GROUP_NAME}' already exists"
        return 0
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create group: ${ADMIN_GROUP_NAME}"
        return 0
    fi

    aws iam create-group --group-name "${ADMIN_GROUP_NAME}"
    success "Created IAM group: ${ADMIN_GROUP_NAME}"
}

create_and_attach_policies() {
    info "Creating and attaching IAM policies..."

    local mgmt_account_id
    mgmt_account_id="$(aws sts get-caller-identity --query 'Account' --output text)"

    # Policy 1: Assume Role in Member Accounts
    local assume_role_policy_name="NOCgentic-AssumeRoleInMemberAccounts"
    create_policy_if_not_exists "${assume_role_policy_name}" "$(get_assume_role_policy)"
    attach_policy_to_group "${assume_role_policy_name}" "${mgmt_account_id}"

    # Policy 2: Organization Management
    local org_mgmt_policy_name="NOCgentic-OrganizationManagement"
    create_policy_if_not_exists "${org_mgmt_policy_name}" "$(get_org_management_policy)"
    attach_policy_to_group "${org_mgmt_policy_name}" "${mgmt_account_id}"

    # Policy 3: CloudTrail S3 Access
    local cloudtrail_policy_name="NOCgentic-CloudTrailS3Access"
    create_policy_if_not_exists "${cloudtrail_policy_name}" "$(get_cloudtrail_s3_policy)"
    attach_policy_to_group "${cloudtrail_policy_name}" "${mgmt_account_id}"

    success "All policies created and attached"
}

create_policy_if_not_exists() {
    local policy_name="$1"
    local policy_document="$2"

    local mgmt_account_id
    mgmt_account_id="$(aws sts get-caller-identity --query 'Account' --output text)"
    local policy_arn="arn:aws:iam::${mgmt_account_id}:policy/${policy_name}"

    # Check if policy exists
    if aws iam get-policy --policy-arn "${policy_arn}" &> /dev/null; then
        info "Policy '${policy_name}' already exists"
        return 0
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create policy: ${policy_name}"
        return 0
    fi

    aws iam create-policy \
        --policy-name "${policy_name}" \
        --policy-document "${policy_document}" \
        --description "BH Asia 2026 NOC - ${policy_name}" \
        --tags "Key=Project,Value=${PROJECT_TAG}"

    success "Created policy: ${policy_name}"
}

attach_policy_to_group() {
    local policy_name="$1"
    local account_id="$2"
    local policy_arn="arn:aws:iam::${account_id}:policy/${policy_name}"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would attach policy ${policy_name} to group ${ADMIN_GROUP_NAME}"
        return 0
    fi

    # Check if already attached
    local attached
    attached="$(aws iam list-attached-group-policies \
        --group-name "${ADMIN_GROUP_NAME}" \
        --query "AttachedPolicies[?PolicyName=='${policy_name}'].PolicyName" \
        --output text 2>/dev/null || echo "")"

    if [[ -n "${attached}" ]]; then
        info "Policy '${policy_name}' already attached to group"
        return 0
    fi

    aws iam attach-group-policy \
        --group-name "${ADMIN_GROUP_NAME}" \
        --policy-arn "${policy_arn}"

    info "Attached policy '${policy_name}' to group"
}

create_iam_user() {
    info "Creating IAM user: ${ADMIN_USER_NAME}..."

    # Check if user exists
    if aws iam get-user --user-name "${ADMIN_USER_NAME}" &> /dev/null; then
        info "User '${ADMIN_USER_NAME}' already exists"
        return 0
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create user: ${ADMIN_USER_NAME}"
        return 0
    fi

    aws iam create-user \
        --user-name "${ADMIN_USER_NAME}" \
        --tags "Key=Project,Value=${PROJECT_TAG}" "Key=Purpose,Value=Deployment"

    success "Created IAM user: ${ADMIN_USER_NAME}"
}

add_user_to_group() {
    info "Adding user to group..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would add ${ADMIN_USER_NAME} to ${ADMIN_GROUP_NAME}"
        return 0
    fi

    # Check if already in group
    local in_group
    in_group="$(aws iam list-groups-for-user \
        --user-name "${ADMIN_USER_NAME}" \
        --query "Groups[?GroupName=='${ADMIN_GROUP_NAME}'].GroupName" \
        --output text 2>/dev/null || echo "")"

    if [[ -n "${in_group}" ]]; then
        info "User already in group"
        return 0
    fi

    aws iam add-user-to-group \
        --user-name "${ADMIN_USER_NAME}" \
        --group-name "${ADMIN_GROUP_NAME}"

    success "Added ${ADMIN_USER_NAME} to ${ADMIN_GROUP_NAME}"
}

create_access_keys() {
    info "Creating access keys for ${ADMIN_USER_NAME}..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create access keys for ${ADMIN_USER_NAME}"
        return 0
    fi

    # Check existing keys
    local existing_keys
    existing_keys="$(aws iam list-access-keys \
        --user-name "${ADMIN_USER_NAME}" \
        --query 'AccessKeyMetadata | length(@)' \
        --output text)"

    if [[ "${existing_keys}" -ge 2 ]]; then
        warn "User already has 2 access keys (maximum). Delete one first if you need new keys."
        return 0
    fi

    # Create new access key
    local key_output
    key_output="$(aws iam create-access-key --user-name "${ADMIN_USER_NAME}")"

    local access_key_id secret_access_key
    access_key_id="$(echo "${key_output}" | jq -r '.AccessKey.AccessKeyId')"
    secret_access_key="$(echo "${key_output}" | jq -r '.AccessKey.SecretAccessKey')"

    # Save to secure file
    local creds_file="${SCRIPT_DIR}/../.credentials-${ADMIN_USER_NAME}.json"

    cat > "${creds_file}" << EOF
{
    "user": "${ADMIN_USER_NAME}",
    "access_key_id": "${access_key_id}",
    "secret_access_key": "${secret_access_key}",
    "created_at": "$(date -Iseconds)",
    "note": "KEEP THIS FILE SECURE. Delete after configuring AWS CLI."
}
EOF

    chmod 600 "${creds_file}"

    success "Access keys created and saved to: ${creds_file}"

    echo ""
    echo "=============================================="
    echo "  ACCESS KEY CREATED - SAVE THESE SECURELY"
    echo "=============================================="
    echo ""
    echo "  Access Key ID:     ${access_key_id}"
    echo "  Secret Access Key: ${secret_access_key}"
    echo ""
    echo "  Credentials saved to: ${creds_file}"
    echo ""
    echo "  IMPORTANT: This is the ONLY time the secret"
    echo "  key will be displayed. Save it securely!"
    echo ""
    echo "=============================================="
    echo ""
}

# ============================================================================
# Summary
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "  IAM Admin User Setup Summary"
    echo "=============================================="
    echo ""

    if [[ "${DRY_RUN}" == true ]]; then
        warn "This was a DRY RUN - no changes were made"
        echo ""
    fi

    echo "User:  ${ADMIN_USER_NAME}"
    echo "Group: ${ADMIN_GROUP_NAME}"
    echo ""

    echo "Permissions:"
    echo "  - Assume role into member accounts (Security, Production, Development)"
    echo "  - Read organization structure"
    echo "  - Read CloudTrail logs"
    echo "  - Read billing/budgets"
    echo "  - Manage own credentials (password, MFA, access keys)"
    echo ""

    echo "Member Account Access:"
    echo "  - nocgentic-security    (${SECURITY_ACCOUNT_ID})"
    echo "  - nocgentic-production  (${PRODUCTION_ACCOUNT_ID})"
    echo "  - nocgentic-development (${DEVELOPMENT_ACCOUNT_ID})"
    echo ""

    echo "=============================================="
    echo "  NEXT STEPS"
    echo "=============================================="
    echo ""
    echo "1. Configure AWS CLI with the new credentials:"
    echo ""
    echo "   aws configure --profile nocgentic-deploy"
    echo "   # Enter the Access Key ID and Secret Access Key"
    echo ""
    echo "2. Test the new credentials:"
    echo ""
    echo "   aws sts get-caller-identity --profile nocgentic-deploy"
    echo ""
    echo "3. To deploy to production account, assume the role:"
    echo ""
    echo "   aws sts assume-role \\"
    echo "       --role-arn arn:aws:iam::${PRODUCTION_ACCOUNT_ID}:role/OrganizationAccountAccessRole \\"
    echo "       --role-session-name DeploySession \\"
    echo "       --profile nocgentic-deploy"
    echo ""
    echo "4. (Optional) Set up MFA for the user in AWS Console"
    echo ""
    echo "5. DELETE the credentials file after configuring CLI:"
    echo "   rm ${SCRIPT_DIR}/../.credentials-${ADMIN_USER_NAME}.json"
    echo ""
    echo "6. STOP using root credentials!"
    echo ""
    echo "Log file: ${LOG_FILE}"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    echo "=============================================="
    echo "  BH Asia 2026 - IAM Admin User Setup"
    echo "=============================================="
    echo ""

    preflight_checks

    create_iam_group
    create_and_attach_policies
    create_iam_user
    add_user_to_group
    create_access_keys

    print_summary

    success "IAM admin user setup complete!"
}

main "$@"
