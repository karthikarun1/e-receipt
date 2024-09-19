curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/orders/W94SD2QJ19RJJ/payments" \
-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
-H "Content-Type: application/json" \
-d '{
  "orderId": "W94SD2QJ19RJJ", 
  "amount": 3650, 
  "currency": "USD", 
  "cardTransaction": {
    "number": "6011000990139424", 
    "expMonth": 12,
    "expYear": 2025,
    "cvv": "123",
    "last4": "9424"
  },
  "tender": {
    "id": "MSW81T3A09NGG"
  }
}'
