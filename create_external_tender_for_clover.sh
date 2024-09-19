#curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/tenders" \
#-H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
#-H "Content-Type: application/json" \
#-d '{
#  "labelKey": "External Payment",
#  "label": "External Credit Card",
#  "visible": true,
#  "opensCashDrawer": false,
#  "enabled": true
#}'

curl -X POST "https://sandbox.dev.clover.com/v3/merchants/9N7D4W6ZBXGV1/tenders" \
     -H "Authorization: Bearer 62ce1cda-5163-cc37-8c3d-514d920ac5ac" \
     --header 'content-type: application/json' \
     --data '{
  "id": "string",
  "editable": true,
  "labelKey": "External Payment",
  "label": "External Credit Card",
  "opensCashDrawer": true,
  "supportsTipping": true,
  "enabled": true,
  "visible": true,
  "instructions": "string"
}'
