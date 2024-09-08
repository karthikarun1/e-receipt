. get_token.sh
org_id=$1
user_id=$2
curl -X POST http://localhost:5000/organization/$org_id/demote_admin \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d "{\"user_id\": \"$user_id\"}"
