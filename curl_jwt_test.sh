# Create access token

set -x
set -e

tmp_model="/tmp/tmp.pkl"

# Get endpoint. Assign default "all" if no value was provided.
endpoint=${1:-"all"} 

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

if [[ "$endpoint" == "list" || "$endpoint" == "all" ]]; then
curl -X GET http://localhost:5000/list_models -H "Authorization: Bearer ${TOKEN}" 
fi

if [[ "$endpoint" == "remove" || "$endpoint" == "all" ]]; then
curl -X DELETE http://localhost:5000/remove_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "random_forest_model.pkl", "version": "v4"}'
fi

if [[ "$endpoint" == "remove" || "$endpoint" == "all" ]]; then
curl -X DELETE http://localhost:5000/remove_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "sample_model.pkl", "version": "2.0"}'
fi

if [[ "$endpoint" == "list" || "$endpoint" == "all" ]]; then
curl -X GET http://localhost:5000/list_models -H "Authorization: Bearer ${TOKEN}" 
fi

#if [[ "$endpoint" == "download" || "$endpoint" == "all" ]]; then
#rm -f $tmp_model
#curl -X GET http://localhost:5000/download_model/random_forest_model/v4 -H "Authorization: Bearer ${TOKEN}" 
## -o $tmp_model
#fi

if [[ "$endpoint" == "download" || "$endpoint" == "all" ]]; then
rm -f $tmp_model
curl -X GET http://localhost:5000/download_model/sample_model/v0 -H "Authorization: Bearer ${TOKEN}"
# -o $tmp_model
fi

#if [[ "$endpoint" == "download" || "$endpoint" == "all" ]]; then
#rm -f $tmp_model
#curl -X GET http://localhost:5000/download_model -H "Authorization: Bearer ${TOKEN}"
## -o $tmp_model
#fi

if [[ "$endpoint" == "predict" || "$endpoint" == "all" ]]; then
curl -X POST http://localhost:5000/predict -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"data": [5.9, 3.0, 4.2, 1.5], "model_filename": "sample_model.pkl", "version": "v2"}'
fi
