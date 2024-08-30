set -x
source ./get_token.sh
table="${1}"
curl -X GET http://localhost:5000/list_table/$table \
-H "Authorization: Bearer ${token}"
