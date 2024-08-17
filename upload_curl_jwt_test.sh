# Create access token

# Sample call
# ./upload_curl_jwt_test.sh sample_model.pkl v5 "This model will predict the future. This is just the initialc!" 75

set -x
set -e

# Check if both model_filename and version are provided
model_filename=${1:-"sample_model.pkl"}
version=${2:-"v0"}

if [[ -z "$model_filename" || -z "$version" ]]; then
  echo "Error: Both model_filename and version are required for the 'upload' endpoint."
  exit 1
fi

description="${3:-"Description for model $model_filename and version ${version}"}"
accuracy=${4:-0.5}

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

# Test /upload_model endpoint using the generated token
curl -X POST http://localhost:5000/upload_model \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: multipart/form-data" \
    -F "version=$version" \
    -F "description=$description" \
    -F "accuracy=$accuracy" \
    -F "model_file=@$model_filename"
