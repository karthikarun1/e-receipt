. get_token.sh
org_id=$1
set -x
curl -X GET "http://localhost:5000/organization/${org_id}/users" \
-H "Authorization: Bearer $token" \
