token=$1
curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/orders" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d '{
  "state": "open"
}'
