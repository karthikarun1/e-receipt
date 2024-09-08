source ./get_token.sh
name=$1
name=$2
set -x
curl -X POST http://127.0.0.1:5000/create_organization \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
  \"org_name\": \"$name\",
  \"description\": \"$description\"
}"
