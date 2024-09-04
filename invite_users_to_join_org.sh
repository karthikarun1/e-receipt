. ./get_token.sh
org_id=$1
user1=$2
user2=$3
set -x
curl -X POST http://localhost:5000/organization/invite \
-H "Authorization: Bearer ${token}" \
-H 'Content-Type: application/json' \
-d "{
  \"org_id\": \"${org_id}\",
  \"user_ids\": [\"${user1}\", \"${user2}\"]
}"

