username_or_email=$1
password=$2
#set -x
curl -X POST $URL/login \
-H "Content-Type: application/json" \
-d "{
  \"identifier\": \"${username_or_email}\",
  \"password\": \"${password}\"
}"
