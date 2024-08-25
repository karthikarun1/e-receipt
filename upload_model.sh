token="${1}"
version="${2}"
curl -X POST http://localhost:5000/upload_model \
-H "Authorization: Bearer ${token}" \
-F "model_name=random_model" \
-F "version=${version}" \
-F "accuracy=0.95" \
-F "description=Model Version ${version}" \
-F "model_file=@random_forest_model.pkl"
