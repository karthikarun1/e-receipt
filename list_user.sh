source ./get_token.sh
username=$1
curl -X GET http://localhost:5000/list_user/$username \
-H "Authorization: Bearer ${token}"
