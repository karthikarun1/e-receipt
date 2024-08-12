curl -X GET http://127.0.0.1:5000/list_models

curl -X POST http://127.0.0.1:5000/predict      -H "Content-Type: application/json"      -d '{"data": [5.9, 3.0, 4.2, 1.5], "model_filename": "sample_model.pkl"}'

curl -X POST http://localhost:5000/upload_model -F "model=@random_forest_model.pkl"
