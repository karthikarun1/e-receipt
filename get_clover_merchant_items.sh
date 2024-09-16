token=$1
curl -X GET "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/items" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json"

