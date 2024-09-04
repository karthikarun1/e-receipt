source ./get_token.sh
curl -X GET http://localhost:5000/user/organizations \
-H "Authorization: Bearer ${token}"

