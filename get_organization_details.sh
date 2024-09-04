. get_token.sh
org_id=$1
curl -X GET "http://localhost:5000/organization/details" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d "{\"org_id\": \"${org_id}\"}"
