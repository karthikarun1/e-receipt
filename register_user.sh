set -x
curl -X POST http://localhost:5000/register \
-H "Content-Type: application/json" \
-d '{
  "username": "user_2",
  "email": "karthikarun@gmail.com",
  "password": "secure_password",
  "confirm_password": "secure_password"
}'
