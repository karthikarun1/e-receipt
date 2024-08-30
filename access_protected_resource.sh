source ./get_token.sh
token="${1}"
curl -X GET http://localhost:5000/protected_resource -H "Authorization: Bearer ${token}"
