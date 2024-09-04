source ./get_token.sh
curl -X GET http://localhost:5000/list_all_organizations \
-H "Authorization: Bearer ${token}"

