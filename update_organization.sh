source ./get_token.sh
curl -X POST http://localhost:5000/update_organization \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d '{
    "org_id": "dc7500b0-5025-4b1f-b809-0abce482e018",
    "some_key": "some value"
}'
