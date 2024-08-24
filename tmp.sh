TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

model_name=$1
model_file=$2
version=$3

curl -X POST http://localhost:5000/upload_model \
  -H "Content-Type: multipart/form-data" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "version=$version" \
  -F "accuracy=0.5" \
  -F "description=Sample model copy for testing" \
  -F "model_name=$model_name" \
  -F "model_file=@$model_file"

#curl -X DELETE http://localhost:5000/remove_model/$model_name/$version \
#  -H "Authorization: Bearer ${TOKEN}" \
