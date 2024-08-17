# Create access token

#set -x
set -e

TOKEN=$(curl -s -X POST http://localhost:5000/login \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "pass1"}' | jq -r '.access_token')

# Test /upload_model endpoint using the generated token
curl -X POST http://localhost:5000/upload_model \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: multipart/form-data" \
    -F "version=2.0" \
    -F "model_file=@sample_model.pkl"

curl -X GET http://localhost:5000/list_models -H "Authorization: Bearer ${TOKEN}" 

curl -X DELETE http://localhost:5000/remove_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "random_forest_model.pkl", "version": "v4"}'

curl -X DELETE http://localhost:5000/remove_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "sample_model.pkl", "version": "2.0"}'

curl -X GET http://localhost:5000/list_models -H "Authorization: Bearer ${TOKEN}" 

curl -X GET http://localhost:5000/retrieve_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "random_forest_model.pkl", "version": "v4"}'

rm -f /tmp/tmp.pkl
curl -X GET http://localhost:5000/retrieve_model -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"model_filename": "random_forest_model.pkl", "version": "v0"}' -o /tmp/tmp.pkl

curl -X POST http://localhost:5000/predict -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"data": [5.9, 3.0, 4.2, 1.5], "model_filename": "sample_model.pkl", "version": "v2"}'
