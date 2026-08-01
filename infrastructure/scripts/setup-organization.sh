#!/usr/bin/env bash
#
# AWS Organization Setup Script for BH Asia 2026 NOC
#
# SECURITY WARNING: This script is designed to be run with root account credentials.
# It implements strict security controls and creates an isolated organizational structure.
#
# This script will:
# 1. Create an AWS Organization (if not exists)
# 2. Enable Service Control Policies (SCPs)
# 3. Create Organizational Units (OUs) for environment isolation
# 4. Configure alternate contacts for billing, security, and operations
# 5. Set up basic SCPs to restrict dangerous operations
# 6. Set up organization-wide CloudTrail
#
# Usage: ./setup-organization.sh [--dry-run]
#

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# Configuration
# ============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/setup-organization-$(date +%Y%m%d-%H%M%S).log"

# AWS Region - Singapore
readonly AWS_REGION="ap-southeast-1"

# Organization configuration
readonly ORG_NAME="NOCgenticSOC"
readonly PROJECT_TAG="NOCgentic2026NOC"
readonly RESOURCE_PREFIX="nocgentic"

# Alternate Contacts
readonly BILLING_EMAIL="${BILLING_EMAIL:?Set BILLING_EMAIL env var}"
readonly BILLING_NAME="Billing Contact"
readonly BILLING_PHONE="${BILLING_PHONE:?Set BILLING_PHONE env var}"
readonly BILLING_TITLE="Billing Manager"

readonly SECURITY_EMAIL="${SECURITY_EMAIL:?Set SECURITY_EMAIL env var}"
readonly SECURITY_NAME="Security Contact"
readonly SECURITY_PHONE="${SECURITY_PHONE:?Set SECURITY_PHONE env var}"
readonly SECURITY_TITLE="Security Officer"

readonly OPERATIONS_EMAIL="${OPERATIONS_EMAIL:?Set OPERATIONS_EMAIL env var}"
readonly OPERATIONS_NAME="Operations Contact"
readonly OPERATIONS_PHONE="${OPERATIONS_PHONE:?Set OPERATIONS_PHONE env var}"
readonly OPERATIONS_TITLE="Operations Manager"

# Organizational Units to create
declare -A OU_STRUCTURE=(
    ["Security"]="Security and audit accounts"
    ["Production"]="Production workloads"
    ["Development"]="Development and testing"
    ["Sandbox"]="Experimentation and learning"
)

# Accounts to create (name:email:ou)
# Format: name:email:ou
declare -a ACCOUNTS_TO_CREATE=(
    "nocgentic-security:${SECURITY_ACCOUNT_EMAIL:?Set SECURITY_ACCOUNT_EMAIL}:Security"
    "nocgentic-production:${PRODUCTION_ACCOUNT_EMAIL:?Set PRODUCTION_ACCOUNT_EMAIL}:Production"
    "nocgentic-development:${DEVELOPMENT_ACCOUNT_EMAIL:?Set DEVELOPMENT_ACCOUNT_EMAIL}:Development"
)

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

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

# Check if running in dry-run mode
DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN=true
    warn "Running in DRY-RUN mode - no changes will be made"
fi

# Execute AWS command (respects dry-run)
aws_exec() {
    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would execute: aws $*"
        return 0
    fi
    aws --region "${AWS_REGION}" "$@"
}

# Execute AWS command that must run in us-east-1 (Organizations, IAM)
aws_global() {
    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would execute: aws $*"
        return 0
    fi
    aws --region us-east-1 "$@"
}

# ============================================================================
# Pre-flight Checks
# ============================================================================

preflight_checks() {
    info "Running pre-flight checks..."
    info "Target region: ${AWS_REGION} (Singapore)"

    # Check AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        die "AWS CLI is not installed. Please install it first."
    fi

    # Check jq is installed
    if ! command -v jq &> /dev/null; then
        die "jq is not installed. Please install it first."
    fi

    # Check AWS CLI version
    local aws_version
    aws_version="$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)"
    info "AWS CLI version: ${aws_version}"

    # Verify AWS credentials are configured
    if ! aws sts get-caller-identity &> /dev/null; then
        die "AWS credentials are not configured or invalid."
    fi

    # Get current identity info
    local caller_identity
    caller_identity="$(aws sts get-caller-identity)"
    local account_id
    account_id="$(echo "${caller_identity}" | jq -r '.Account')"
    local arn
    arn="$(echo "${caller_identity}" | jq -r '.Arn')"

    info "Current AWS Account: ${account_id}"
    info "Current ARN: ${arn}"

    # CRITICAL: Check if this is the root account
    if [[ "${arn}" == *":root" ]]; then
        warn "=========================================="
        warn "  RUNNING WITH ROOT ACCOUNT CREDENTIALS  "
        warn "=========================================="
        warn "This is acceptable for initial org setup only."
        warn "After setup, switch to IAM user/role immediately."
        echo ""

        if [[ "${DRY_RUN}" != true ]]; then
            read -r -p "Type 'I UNDERSTAND THE RISKS' to continue: " confirmation
            if [[ "${confirmation}" != "I UNDERSTAND THE RISKS" ]]; then
                die "Aborting due to user confirmation failure."
            fi
        fi
    fi

    success "Pre-flight checks passed"
}

# ============================================================================
# Organization Management
# ============================================================================

check_organization_exists() {
    if aws organizations describe-organization &> /dev/null; then
        return 0
    fi
    return 1
}

create_organization() {
    info "Checking for existing AWS Organization..."

    if check_organization_exists; then
        local org_id
        org_id="$(aws organizations describe-organization --query 'Organization.Id' --output text)"
        info "Organization already exists: ${org_id}"
        return 0
    fi

    info "Creating new AWS Organization..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create organization with all features enabled"
        return 0
    fi

    aws organizations create-organization --feature-set ALL

    # Wait for organization to be ready
    sleep 5

    local org_id
    org_id="$(aws organizations describe-organization --query 'Organization.Id' --output text)"
    success "Created organization: ${org_id}"
}

enable_organization_policies() {
    info "Enabling Service Control Policies (SCPs)..."

    # Check if SCPs are already enabled
    local scp_enabled
    scp_enabled="$(aws organizations describe-organization \
        --query 'Organization.AvailablePolicyTypes[?Type==`SERVICE_CONTROL_POLICY`].Status' \
        --output text 2>/dev/null || echo "DISABLED")"

    if [[ "${scp_enabled}" == "ENABLED" ]]; then
        info "SCPs already enabled"
        return 0
    fi

    aws_global organizations enable-policy-type \
        --root-id "$(get_root_id)" \
        --policy-type SERVICE_CONTROL_POLICY

    success "SCPs enabled"
}

get_root_id() {
    aws organizations list-roots --query 'Roots[0].Id' --output text
}

# ============================================================================
# Alternate Contacts Setup
# ============================================================================

setup_alternate_contacts() {
    info "Setting up alternate contacts..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would set billing contact: ${BILLING_EMAIL}"
        info "[DRY-RUN] Would set security contact: ${SECURITY_EMAIL}"
        info "[DRY-RUN] Would set operations contact: ${OPERATIONS_EMAIL}"
        return 0
    fi

    # Billing contact
    info "Setting billing contact: ${BILLING_EMAIL}"
    aws account put-alternate-contact \
        --alternate-contact-type BILLING \
        --email-address "${BILLING_EMAIL}" \
        --name "${BILLING_NAME}" \
        --phone-number "${BILLING_PHONE}" \
        --title "${BILLING_TITLE}" || warn "Failed to set billing contact (may already exist)"

    # Security contact
    info "Setting security contact: ${SECURITY_EMAIL}"
    aws account put-alternate-contact \
        --alternate-contact-type SECURITY \
        --email-address "${SECURITY_EMAIL}" \
        --name "${SECURITY_NAME}" \
        --phone-number "${SECURITY_PHONE}" \
        --title "${SECURITY_TITLE}" || warn "Failed to set security contact (may already exist)"

    # Operations contact
    info "Setting operations contact: ${OPERATIONS_EMAIL}"
    aws account put-alternate-contact \
        --alternate-contact-type OPERATIONS \
        --email-address "${OPERATIONS_EMAIL}" \
        --name "${OPERATIONS_NAME}" \
        --phone-number "${OPERATIONS_PHONE}" \
        --title "${OPERATIONS_TITLE}" || warn "Failed to set operations contact (may already exist)"

    success "Alternate contacts configured"
}

# ============================================================================
# Organizational Unit Management
# ============================================================================

create_organizational_units() {
    local root_id
    root_id="$(get_root_id)"

    info "Creating Organizational Units under root: ${root_id}"

    for ou_name in "${!OU_STRUCTURE[@]}"; do
        local description="${OU_STRUCTURE[${ou_name}]}"

        # Check if OU already exists
        local existing_ou
        existing_ou="$(aws organizations list-organizational-units-for-parent \
            --parent-id "${root_id}" \
            --query "OrganizationalUnits[?Name=='${ou_name}'].Id" \
            --output text 2>/dev/null || echo "")"

        if [[ -n "${existing_ou}" && "${existing_ou}" != "None" ]]; then
            info "OU '${ou_name}' already exists: ${existing_ou}"
            continue
        fi

        info "Creating OU: ${ou_name} - ${description}"

        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Would create OU: ${ou_name}"
            continue
        fi

        local ou_id
        ou_id="$(aws organizations create-organizational-unit \
            --parent-id "${root_id}" \
            --name "${ou_name}" \
            --query 'OrganizationalUnit.Id' \
            --output text)"

        success "Created OU '${ou_name}': ${ou_id}"
    done
}

get_ou_id_by_name() {
    local ou_name="$1"
    local root_id
    root_id="$(get_root_id)"

    aws organizations list-organizational-units-for-parent \
        --parent-id "${root_id}" \
        --query "OrganizationalUnits[?Name=='${ou_name}'].Id" \
        --output text
}

# ============================================================================
# Create Member Accounts
# ============================================================================

create_member_accounts() {
    info "Creating member accounts..."

    local root_id
    root_id="$(get_root_id)"

    for account_spec in "${ACCOUNTS_TO_CREATE[@]}"; do
        local name email ou_name
        name="$(echo "${account_spec}" | cut -d: -f1)"
        email="$(echo "${account_spec}" | cut -d: -f2)"
        ou_name="$(echo "${account_spec}" | cut -d: -f3)"

        # Check if account already exists (by name)
        local existing_account
        existing_account="$(aws organizations list-accounts \
            --query "Accounts[?Name=='${name}'].Id" \
            --output text 2>/dev/null || echo "")"

        if [[ -n "${existing_account}" && "${existing_account}" != "None" ]]; then
            info "Account '${name}' already exists: ${existing_account}"
            # Still try to move it to the correct OU
            move_account_to_ou "${existing_account}" "${name}" "${ou_name}"
            continue
        fi

        info "Creating account: ${name} (${email})"

        if [[ "${DRY_RUN}" == true ]]; then
            info "[DRY-RUN] Would create account: ${name} with email ${email}"
            info "[DRY-RUN] Would move account to OU: ${ou_name}"
            continue
        fi

        # Create the account
        # - iam-user-access-to-billing DENY = security best practice
        # - Creates OrganizationAccountAccessRole automatically for cross-account access
        local create_status_id
        create_status_id="$(aws organizations create-account \
            --account-name "${name}" \
            --email "${email}" \
            --iam-user-access-to-billing DENY \
            --query 'CreateAccountStatus.Id' \
            --output text)"

        info "Account creation initiated: ${create_status_id}"
        info "Waiting for account creation (this may take a few minutes)..."

        # Wait for account creation (can take 1-5 minutes)
        local status="IN_PROGRESS"
        local max_attempts=60
        local attempt=0

        while [[ "${status}" == "IN_PROGRESS" && ${attempt} -lt ${max_attempts} ]]; do
            sleep 5
            status="$(aws organizations describe-create-account-status \
                --create-account-request-id "${create_status_id}" \
                --query 'CreateAccountStatus.State' \
                --output text)"
            ((attempt++))

            # Show progress every 30 seconds
            if (( attempt % 6 == 0 )); then
                info "Still waiting... status: ${status} (${attempt}/${max_attempts})"
            fi
        done

        if [[ "${status}" != "SUCCEEDED" ]]; then
            local failure_reason
            failure_reason="$(aws organizations describe-create-account-status \
                --create-account-request-id "${create_status_id}" \
                --query 'CreateAccountStatus.FailureReason' \
                --output text)"
            error "Failed to create account '${name}': ${failure_reason}"
            continue
        fi

        # Get the new account ID
        local new_account_id
        new_account_id="$(aws organizations describe-create-account-status \
            --create-account-request-id "${create_status_id}" \
            --query 'CreateAccountStatus.AccountId' \
            --output text)"

        success "Created account '${name}': ${new_account_id}"

        # Move to appropriate OU
        move_account_to_ou "${new_account_id}" "${name}" "${ou_name}"
    done
}

move_account_to_ou() {
    local account_id="$1"
    local account_name="$2"
    local ou_name="$3"

    # Get target OU ID
    local ou_id
    ou_id="$(get_ou_id_by_name "${ou_name}")"

    if [[ -z "${ou_id}" || "${ou_id}" == "None" ]]; then
        warn "OU '${ou_name}' not found, cannot move account '${account_name}'"
        return 1
    fi

    # Check current parent
    local current_parent
    current_parent="$(aws organizations list-parents \
        --child-id "${account_id}" \
        --query 'Parents[0].Id' \
        --output text 2>/dev/null || echo "")"

    if [[ "${current_parent}" == "${ou_id}" ]]; then
        info "Account '${account_name}' already in OU '${ou_name}'"
        return 0
    fi

    info "Moving account '${account_name}' to OU '${ou_name}'..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would move account ${account_id} to OU ${ou_id}"
        return 0
    fi

    aws organizations move-account \
        --account-id "${account_id}" \
        --source-parent-id "${current_parent}" \
        --destination-parent-id "${ou_id}"

    success "Moved account '${account_name}' to OU '${ou_name}'"
}

# ============================================================================
# Service Control Policies
# ============================================================================

create_security_scps() {
    info "Creating security Service Control Policies..."

    # SCP: Deny root account usage in member accounts
    local deny_root_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyRootAccountUsage",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalArn": "arn:aws:iam::*:root"
                    }
                }
            }
        ]
    }'

    # SCP: Require MFA for sensitive operations
    local require_mfa_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyStopCloudTrailWithoutMFA",
                "Effect": "Deny",
                "Action": [
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail"
                ],
                "Resource": "*",
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }
        ]
    }'

    # SCP: Deny leaving organization
    local deny_leave_org_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyLeaveOrganization",
                "Effect": "Deny",
                "Action": "organizations:LeaveOrganization",
                "Resource": "*"
            }
        ]
    }'

    # SCP: Restrict to allowed regions (Singapore + Global services)
    local region_restriction_policy='{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyNonApprovedRegions",
                "Effect": "Deny",
                "NotAction": [
                    "iam:*",
                    "organizations:*",
                    "support:*",
                    "sts:*",
                    "cloudfront:*",
                    "route53:*",
                    "route53domains:*",
                    "waf:*",
                    "wafv2:*",
                    "waf-regional:*",
                    "globalaccelerator:*",
                    "budgets:*",
                    "ce:*",
                    "account:*",
                    "billing:*"
                ],
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": [
                            "ap-southeast-1",
                            "us-east-1"
                        ]
                    }
                }
            }
        ]
    }'

    # Create policies
    create_scp_if_not_exists "NOCgentic-DenyRootUsage" "Deny root account usage in member accounts" "${deny_root_policy}"
    create_scp_if_not_exists "NOCgentic-RequireMFAForSensitive" "Require MFA for sensitive operations" "${require_mfa_policy}"
    create_scp_if_not_exists "NOCgentic-DenyLeaveOrg" "Prevent accounts from leaving organization" "${deny_leave_org_policy}"
    create_scp_if_not_exists "NOCgentic-RegionRestriction" "Restrict to Singapore and global services" "${region_restriction_policy}"
}

create_scp_if_not_exists() {
    local policy_name="$1"
    local description="$2"
    local content="$3"

    # Check if policy exists
    local existing_policy
    existing_policy="$(aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query "Policies[?Name=='${policy_name}'].Id" \
        --output text 2>/dev/null || echo "")"

    if [[ -n "${existing_policy}" && "${existing_policy}" != "None" ]]; then
        info "SCP '${policy_name}' already exists: ${existing_policy}"
        return 0
    fi

    info "Creating SCP: ${policy_name}"

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would create SCP: ${policy_name}"
        return 0
    fi

    local policy_id
    policy_id="$(aws organizations create-policy \
        --name "${policy_name}" \
        --description "${description}" \
        --type SERVICE_CONTROL_POLICY \
        --content "${content}" \
        --query 'Policy.PolicySummary.Id' \
        --output text)"

    success "Created SCP '${policy_name}': ${policy_id}"

    # Attach to root (applies to all accounts)
    local root_id
    root_id="$(get_root_id)"

    aws organizations attach-policy \
        --policy-id "${policy_id}" \
        --target-id "${root_id}"

    success "Attached SCP '${policy_name}' to organization root"
}

# ============================================================================
# CloudTrail Setup (Organization-wide)
# ============================================================================

setup_org_cloudtrail() {
    info "Setting up organization-wide CloudTrail in ${AWS_REGION}..."

    if [[ "${DRY_RUN}" == true ]]; then
        info "[DRY-RUN] Would set up organization CloudTrail"
        return 0
    fi

    local trail_name="${RESOURCE_PREFIX}-org-trail"

    # Get management account ID
    local mgmt_account_id
    mgmt_account_id="$(aws sts get-caller-identity --query 'Account' --output text)"

    # Check if trail already exists
    local existing_trail
    existing_trail="$(aws cloudtrail describe-trails \
        --region "${AWS_REGION}" \
        --trail-name-list "${trail_name}" \
        --query 'trailList[0].Name' \
        --output text 2>/dev/null || echo "")"

    if [[ -n "${existing_trail}" && "${existing_trail}" != "None" ]]; then
        info "Organization CloudTrail '${trail_name}' already exists"
        return 0
    fi

    # Create S3 bucket for CloudTrail logs
    local bucket_name="${RESOURCE_PREFIX}-cloudtrail-${mgmt_account_id}"

    # Check if bucket exists
    if ! aws s3api head-bucket --bucket "${bucket_name}" 2>/dev/null; then
        info "Creating S3 bucket for CloudTrail: ${bucket_name}"

        aws s3api create-bucket \
            --bucket "${bucket_name}" \
            --region "${AWS_REGION}" \
            --create-bucket-configuration LocationConstraint="${AWS_REGION}"

        # Enable versioning
        aws s3api put-bucket-versioning \
            --bucket "${bucket_name}" \
            --versioning-configuration Status=Enabled

        # Block public access
        aws s3api put-public-access-block \
            --bucket "${bucket_name}" \
            --public-access-block-configuration \
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

        # Set bucket policy for CloudTrail
        local bucket_policy
        bucket_policy=$(cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${bucket_name}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${bucket_name}/*",
            "Condition": {
                "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
            }
        }
    ]
}
EOF
)
        aws s3api put-bucket-policy --bucket "${bucket_name}" --policy "${bucket_policy}"

        # Add tags
        aws s3api put-bucket-tagging \
            --bucket "${bucket_name}" \
            --tagging "TagSet=[{Key=Project,Value=${PROJECT_TAG}},{Key=ManagedBy,Value=setup-organization-script}]"

        success "Created and configured S3 bucket: ${bucket_name}"
    fi

    # Create organization trail
    aws cloudtrail create-trail \
        --name "${trail_name}" \
        --s3-bucket-name "${bucket_name}" \
        --is-organization-trail \
        --is-multi-region-trail \
        --enable-log-file-validation \
        --include-global-service-events \
        --region "${AWS_REGION}"

    # Add tags to trail
    local trail_arn
    trail_arn="$(aws cloudtrail describe-trails \
        --region "${AWS_REGION}" \
        --trail-name-list "${trail_name}" \
        --query 'trailList[0].TrailARN' \
        --output text)"

    aws cloudtrail add-tags \
        --resource-id "${trail_arn}" \
        --tags-list "Key=Project,Value=${PROJECT_TAG}" "Key=ManagedBy,Value=setup-organization-script" \
        --region "${AWS_REGION}"

    # Start logging
    aws cloudtrail start-logging --name "${trail_name}" --region "${AWS_REGION}"

    success "Created and started organization CloudTrail: ${trail_name}"
}

# ============================================================================
# Summary Report
# ============================================================================

print_summary() {
    echo ""
    echo "=============================================="
    echo "  BH Asia 2026 - AWS Organization Summary"
    echo "=============================================="
    echo ""
    echo "Region: ${AWS_REGION} (Singapore)"
    echo ""

    if [[ "${DRY_RUN}" == true ]]; then
        warn "This was a DRY RUN - no changes were made"
        echo ""
    fi

    # List organization info
    if check_organization_exists; then
        local org_info
        org_info="$(aws organizations describe-organization --query 'Organization' 2>/dev/null || echo "{}")"
        echo "Organization ID: $(echo "${org_info}" | jq -r '.Id // "N/A"')"
        echo "Master Account: $(echo "${org_info}" | jq -r '.MasterAccountId // "N/A"')"
        echo ""
    fi

    # List OUs
    echo "Organizational Units:"
    local root_id
    root_id="$(get_root_id 2>/dev/null || echo "")"
    if [[ -n "${root_id}" ]]; then
        aws organizations list-organizational-units-for-parent \
            --parent-id "${root_id}" \
            --query 'OrganizationalUnits[].{Name:Name,Id:Id}' \
            --output table 2>/dev/null || echo "  (none)"
    fi
    echo ""

    # List accounts
    echo "Member Accounts:"
    aws organizations list-accounts \
        --query 'Accounts[].{Name:Name,Id:Id,Email:Email,Status:Status}' \
        --output table 2>/dev/null || echo "  (none)"
    echo ""

    # List SCPs
    echo "Service Control Policies:"
    aws organizations list-policies \
        --filter SERVICE_CONTROL_POLICY \
        --query 'Policies[].{Name:Name,Id:Id}' \
        --output table 2>/dev/null || echo "  (none)"
    echo ""

    # Show alternate contacts
    echo "Alternate Contacts:"
    echo "  Billing:    ${BILLING_EMAIL}"
    echo "  Security:   ${SECURITY_EMAIL}"
    echo "  Operations: ${OPERATIONS_EMAIL}"
    echo ""

    echo "=============================================="
    echo "  NEXT STEPS"
    echo "=============================================="
    echo ""
    echo "1. Create IAM admin user in management account"
    echo "2. Configure MFA for all users"
    echo "3. Stop using root account credentials"
    echo "4. Review and customize SCPs for your needs"
    echo "5. Set up AWS Config for compliance monitoring"
    echo "6. Configure budget alerts"
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
    echo "  BH Asia 2026 - AWS Organization Setup"
    echo "  Region: ${AWS_REGION} (Singapore)"
    echo "=============================================="
    echo ""

    preflight_checks

    create_organization
    enable_organization_policies
    setup_alternate_contacts
    create_organizational_units
    create_member_accounts
    create_security_scps
    setup_org_cloudtrail

    print_summary

    success "Organization setup complete!"
}

main "$@"
