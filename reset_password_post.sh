token=$1
new_password=$2

curl -X POST http://localhost:5000/reset_password \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "token=$token" \
-d "new_password=$new_password"
