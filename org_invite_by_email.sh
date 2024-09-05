. ./get_token.sh
org_id="${1}"
email1="${2}"
email2="${3}"
set -x
curl -X POST http://localhost:5000/organization/invite_by_emails \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
  \"org_id\": \"${org_id}\",
  \"emails\": [\"$email1\", \"$email2\"]
}"
