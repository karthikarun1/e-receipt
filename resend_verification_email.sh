val=$1
set -x
curl -X POST http://localhost:5000/resend_verification_email \
-H "Content-Type: application/json" \
-d "{
  \"identifier\": \"${val}\"
}"

