#curl -X GET "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/payments/N0MEA7JHKA5BW" \
#-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
#-H "Content-Type: application/json"

#{"id": "XBJB06287G3YC", "order": {"id": "CW9Y1QJBX05NA"}, "tender": {"href": "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/tenders/E05BB2Q8VET3M", "id": "E05BB2Q8VET3M"}, "amount": 3650, "employee": {"id": "EP2ZB7ZXYQXHY"}, "createdTime": 1726529265000, "clientCreatedTime": 1726529265000, "modifiedTime": 1726529264000, "result": "SUCCESS"}
#

#curl --request GET \
#     --url https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/orders/CW9Y1QJBX05NA/payments \
#     --header 'accept: application/json' \
#     --header 'authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac'

#curl -X GET "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/payments/XBJB06287G3YC?expand=cardTransaction" \
#-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
#-H "Content-Type: application/json"

curl -X GET "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/payments/FBGWVQQAFK63C?expand=cardTransaction" \
-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
-H "Content-Type: application/json"
