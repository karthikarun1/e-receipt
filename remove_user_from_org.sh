. get_token.sh
set -x
org_id=$1
identifier=$2
curl -X POST http://localhost:5000/organization/remove_user \
-H "Content-Type: application/json" \
-H "Authorization: Bearer $token" \
-d "{
    \"org_id\": \"$org_id\",
    \"username_or_email\": \"$identifier\"
}"
