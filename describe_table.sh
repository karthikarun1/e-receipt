table_name="${1}"
echo curl http://127.0.0.1:5000/describe_table/$table_name
curl http://127.0.0.1:5000/describe_table/$table_name
