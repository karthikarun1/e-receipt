
# customer makes their payment using a credit card at the square POS.
# Then square POS presents the customer with option on how to receice
# their receipt - print, email, sms or receiptly.
# if the customer selects receiptly as an option then the square POS
# system will trigger the following call to /notify_payment endpoint in
# receiptly of the payment info, including the payment_id, order_id 
# and location_id

curl https://api.receiptly.com/v1/notify_payment \
  -X POST \
  -H "Authorization: Bearer YOUR_RECEIPTLY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "payment_id": "Lxk57p19VOZW7M48hwifvNDniN7YY",
    "order_id": "wUoWjHphsQYGiNZ1Fn4s611krAfZY",
    "receipt_option": "Receiptly",
    "location_id": "LYZE6ENMVZXZW"
  }'

