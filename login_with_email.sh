username_or_email=$1
password=$2
curl -X POST http://localhost:5000/login \
-H "Content-Type: application/json" \
-d '{
  "identifier": "${username_or_email}",
  "password": "${password}"
}'
