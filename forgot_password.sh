identifier="${1}"
curl -X POST http://localhost:5000/forgot_password \
-H "Content-Type: application/json" \
-d "{
  \"identifier\": \"${identifier}\"
}"
