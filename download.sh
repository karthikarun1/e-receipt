#!/bin/bash

# Initialize variables
model_name=""
version=""

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --model_name) model_name="$2"; shift ;; # Set model_name
        --version) version="$2"; shift ;;       # Set version
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

# Check if version and model_name are empty
if [[ -z "$version" || -z "$model_name" ]]; then
  echo "Error: Both 'version' and 'model_name' must be provided."
  exit 1
fi

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

# Start building the curl command
rm -f /tmp/tmp.pkl
curl_cmd="curl -sS -X GET http://localhost:5000/download_model/$model_name/$version \
  -H \"Content-Type: multipart/form-data\" \
  -H \"Authorization: Bearer ${TOKEN}\" \
  -o /tmp/tmp.pkl"

# Execute the constructed curl command
eval $curl_cmd
