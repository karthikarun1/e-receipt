source ./get_token.sh
curl -X GET http://localhost:5000/whoami \
-H "Authorization: Bearer ${token}"
