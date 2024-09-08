source ./get_token.sh
org_id=$1
curl -X POST http://localhost:5000/update_organization \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
    \"org_id\": \"$org_id\",
    \"org_name\": \"KarSoft Inc.\",
    \"description\": \"KarSoft Inc takes over GOAT!!!.\"
}"
