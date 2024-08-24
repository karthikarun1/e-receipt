#!/bin/bash

# Assuming the token is passed as the first argument to the script
token="$1"

# Use the correct syntax for passing the token in the curl command
curl -X POST -H "Content-Type: application/json" -d "{\"token\":\"$token\"}" http://localhost:5000/token_remaining_time
