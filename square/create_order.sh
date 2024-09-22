#!/bin/bash

# Done at square POS terminal

curl https://connect.squareupsandbox.com/v2/orders \
  -X POST \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{
    "order": {
      "location_id": "LYZE6ENMVZXZW",
      "line_items": [
        {
          "name": "Test Item",
          "quantity": "1",
          "base_price_money": {
            "amount": 2000,
            "currency": "USD"
          }
        }
      ]
    },
    "idempotency_key": "b9c01355-78yup-78ui-b1p9-0bslj20abdaldal"
  }'

