#!/bin/bash

source ./get_token.sh
curl -sS -X GET http://localhost:5000/list_models \
  -H "Authorization: Bearer ${TOKEN}" \
