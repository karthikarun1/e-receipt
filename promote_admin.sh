. get_token.sh
set -x
org_id=$1
user_id=$2
curl -X POST "http://localhost:5000/organization/$org_id/promote_admin" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d "{\"user_id\": \"$user_id\"}"
