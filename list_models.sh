source ./get_token.sh
curl -X GET http://localhost:5000/list_models \
-H "Authorization: Bearer ${token}"

