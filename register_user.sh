set -x
curl -X POST http://localhost:5000/register \
-H "Content-Type: application/json" \
-d '{
  "username": "rajkarthikarun",
  "email": "rajkarthikarun@gmail.com",
  "password": "Testing123",
  "confirm_password": "Testing123"
}'
