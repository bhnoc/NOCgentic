#!/usr/bin/env bash
# refresh-env-creds.sh — Extract temporary AWS credentials from EC2 instance role
# and write them into the .env file so Docker containers can access S3.
#
# Usage (on EC2):
#   ./scripts/refresh-env-creds.sh          # updates .env in place
#   ./scripts/refresh-env-creds.sh .env.s3  # updates a specific file
#
# This is needed because Docker containers cannot reach the EC2 instance
# metadata service (169.254.169.254) to get IAM role credentials.

set -euo pipefail

ENV_FILE="${1:-.env}"

echo "Fetching instance role credentials from IMDS..."

# Get the role name from instance metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || true)

if [ -n "$TOKEN" ]; then
  # IMDSv2
  ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  CREDS=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
else
  # IMDSv1 fallback
  ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
  CREDS=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE")
fi

ACCESS_KEY=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
SECRET_KEY=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")
SESSION_TOKEN=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Token'])")
EXPIRATION=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Expiration'])")

echo "Role: $ROLE"
echo "Credentials expire: $EXPIRATION"

# Update .env file
if [ -f "$ENV_FILE" ]; then
  # Replace existing keys or append
  if grep -q "^AWS_ACCESS_KEY_ID=" "$ENV_FILE"; then
    sed -i "s|^AWS_ACCESS_KEY_ID=.*|AWS_ACCESS_KEY_ID=$ACCESS_KEY|" "$ENV_FILE"
  else
    echo "AWS_ACCESS_KEY_ID=$ACCESS_KEY" >> "$ENV_FILE"
  fi

  if grep -q "^AWS_SECRET_ACCESS_KEY=" "$ENV_FILE"; then
    sed -i "s|^AWS_SECRET_ACCESS_KEY=.*|AWS_SECRET_ACCESS_KEY=$SECRET_KEY|" "$ENV_FILE"
  else
    echo "AWS_SECRET_ACCESS_KEY=$SECRET_KEY" >> "$ENV_FILE"
  fi

  if grep -q "^AWS_SESSION_TOKEN=" "$ENV_FILE"; then
    sed -i "s|^AWS_SESSION_TOKEN=.*|AWS_SESSION_TOKEN=$SESSION_TOKEN|" "$ENV_FILE"
  else
    echo "AWS_SESSION_TOKEN=$SESSION_TOKEN" >> "$ENV_FILE"
  fi
else
  echo "AWS_ACCESS_KEY_ID=$ACCESS_KEY" > "$ENV_FILE"
  echo "AWS_SECRET_ACCESS_KEY=$SECRET_KEY" >> "$ENV_FILE"
  echo "AWS_SESSION_TOKEN=$SESSION_TOKEN" >> "$ENV_FILE"
fi

echo "Updated $ENV_FILE with temporary credentials (valid until $EXPIRATION)"
echo ""
echo "Now run: docker compose -f docker-compose.agents.yml --env-file $ENV_FILE up -d --build"
