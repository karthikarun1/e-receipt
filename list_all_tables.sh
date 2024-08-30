source ./get_token.sh
curl -X GET http://localhost:5000/list_all_tables \
-H "Authorization: Bearer ${token}"
