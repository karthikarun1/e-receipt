# Create access token

# Sample call
# ./upload_curl_jwt_test.sh sample_model.pkl v5 "This model will predict the future. This is just the initialc!" 75
#
#args: model_filename=${1:-"sample_model.pkl"}
#args: version=${2:-"v0"}
#args: description="${3:-"Description for model $model_filename and version ${version}"}"
#args: accuracy=${4:-0.5}
#args: model_name=${5:-"sample_model"}

set -x
set -e

# Check if both model_filename and version are provided
model_name=${1:-"sample_model"}
model_file=${2:-"sample_model"}
version=${3:-"v0"}

if [[ -z "$model_name" || -z "$version" ]]; then
  echo "Error: Both model_name and version are required for the 'upload' endpoint."
  exit 1
fi

description="${4:-"Description for model $model_filename and version ${version}"}"
accuracy=${5:-0.5}

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

# Test /upload_model endpoint using the generated token
curl -X POST http://localhost:5000/upload_model \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: multipart/form-data" \
  -F "model_name=${model_name}" \
  -F "version=${version}" \
  -F "accuracy=${accuracy}" \
  -F "description=${description}" \
  -F "model_file=@${model_name}.pkl"
