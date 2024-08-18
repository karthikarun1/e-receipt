#!/bin/bash

# Initialize variables
model_name=""
version=""
expected_output=""

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --model_name) model_name="$2"; shift ;; # Set model_name
        --version) version="$2"; shift ;;       # Set version
        --expected_output) expected_output="$2"; shift ;;       # Set version
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
if [[ -n "$expected_output" ]]; then
curl_cmd="curl -sS -X POST http://localhost:5000/predict/$model_name/$version \
  -H \"Content-Type: application/json\" \
  -H \"Authorization: Bearer ${TOKEN}\"
  -d '{\"data\": [5.9, 3.0, 4.2, 1.5], \"expected_output\": $expected_output}'"
else
curl_cmd="curl -sS -X POST http://localhost:5000/predict/$model_name/$version \
  -H \"Content-Type: application/json\" \
  -H \"Authorization: Bearer ${TOKEN}\"
  -d '{\"data\": [5.9, 3.0, 4.2, 1.5]}'"
fi


## Execute the constructed curl command
eval $curl_cmd
