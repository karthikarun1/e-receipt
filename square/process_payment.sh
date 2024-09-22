#!/bin/bash

# Done at square POS terminal

curl https://connect.squareupsandbox.com/v2/payments \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{
    "source_id": "cnon:card-nonce-ok", 
    "amount_money": {
      "amount": 2000,
      "currency": "USD"
    },
    "idempotency_key": "cjlsj092ujlfs-28f1-098l0wjfw-b140db2dafbc", 
    "order_id": "wM0siRUFbjXKa6vUiTSemGSQsiHZY",
    "location_id": "LYZE6ENMVZXZW"
  }'

