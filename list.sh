#!/bin/bash

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

curl -sS -X GET http://localhost:5000/list_models \
  -H "Authorization: Bearer ${TOKEN}" \
