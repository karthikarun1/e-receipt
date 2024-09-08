. get_token.sh
org_id=$1
user_id=$2
new_role=$3
curl -X POST http://localhost:5000/change_role \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
  \"org_id\": \"$org_id\",
  \"user_id\": \"$user_id\",
  \"new_role\": \"$new_role\"
}"
