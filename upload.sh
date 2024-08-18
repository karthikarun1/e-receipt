#!/bin/bash

# Initialize variables
model_name=""
model_file=""
version=""
accuracy=""
description=""

# Parse named arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --model_name) model_name="$2"; shift ;; # Set model_name
        --model_file) model_file="$2"; shift ;; # Set model_file
        --version) version="$2"; shift ;;       # Set version
        --accuracy) accuracy="$2"; shift ;;       # Set accuracy
        --description) description="$2"; shift ;;       # Set description
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

# Start building the curl command
curl_cmd="curl -sS -X POST http://localhost:5000/upload_model \
  -H \"Content-Type: multipart/form-data\" \
  -H \"Authorization: Bearer ${TOKEN}\""

# Conditionally add fields if they are non-empty
if [[ -n "$model_name" ]]; then
  curl_cmd+=" -F \"model_name=$model_name\""
fi

if [[ -n "$model_file" ]]; then
  curl_cmd+=" -F \"model_file=@$model_file\""
fi

if [[ -n "$accuracy" ]]; then
  curl_cmd+=" -F \"accuracy=$accuracy\""
fi

if [[ -n "$description" ]]; then
  curl_cmd+=" -F \"description=$description\""
fi

if [[ -n "$version" ]]; then
  curl_cmd+=" -F \"version=$version\""
fi

# Execute the constructed curl command
eval $curl_cmd
