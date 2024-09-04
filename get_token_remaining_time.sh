#!/bin/bash

set -x
source ./get_token.sh
token_to_check="${1}"
curl -X POST http://localhost:5000/token_remaining_time \
-H "Authorization: Bearer ${token}" \
-H 'Content-Type: application/json' \
-d "{\"token_to_check\": \"${token_to_check}\"}"
