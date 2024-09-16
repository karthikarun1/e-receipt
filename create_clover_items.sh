set -x
token=$1
curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/items" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d '{
  "name": "Latte",
  "price": 400,
  "sku": "sku_001",
  "hidden": false
}'
