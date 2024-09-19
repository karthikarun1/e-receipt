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
    "idempotency_key": "cjlsj092ujlfs-28f1-098lwflw-b140db2dafbc", 
    "order_id": "wcSn0cjfMiaZxTgXHIoNCQ4FTrZZY",
    "location_id": "LYZE6ENMVZXZW"
  }'

