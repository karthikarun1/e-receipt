source ./get_token.sh
table_name="${1}"
curl http://127.0.0.1:5000/describe_table/$table_name \
-H "Authorization: Bearer ${token}"
