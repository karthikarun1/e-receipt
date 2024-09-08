. get_token.sh
set -x
org_id=$1
curl -X GET http://localhost:5000/organization/$org_id/users \
-H "Authorization: Bearer $token" \
-H 'Content-Type: application/json'
