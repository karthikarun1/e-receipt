set -x
curl -X POST http://localhost:5000/register \
-H "Content-Type: application/json" \
-d "{
  \"username\": \"$1\",
  \"email\": \"$2\",
  \"password\": \"$3\",
  \"confirm_password\": \"$4\"
}"
