. ./get_token.sh
org_id=$1
set -x
curl -X POST http://localhost:5000/update_organization \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
  \"org_id\": \"$org_id\",
  \"plan_type\": \"paid\",
  \"description\": \"Updated description for the organization.\"
}"
