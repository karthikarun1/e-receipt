curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/orders" \
-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
-H "Content-Type: application/json" \
-d '{
  "state": "open",
  "customer": {
    "id": "VXRVA0ANGNPQG"
  }
}'
