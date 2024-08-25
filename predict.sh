token=$1
name=$2
version=$3
features="[1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8, 9.9, 10.0]"
#features="[1.2, 3.4, 5.6, 4.4]"

curl -X POST "http://localhost:5000/predict/$name/$version" \
-H "Authorization: Bearer $token" \
-H "Content-Type: application/json" \
-d "{
  \"features\": $features,
  \"expected_output\": 2
}"
