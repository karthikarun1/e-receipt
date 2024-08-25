token=$1
curl -X POST http://localhost:5000/change_password \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d '{
  "current_password": "Testing321",
  "new_password": "Testing123",
  "confirm_new_password": "Testing123"
}'
