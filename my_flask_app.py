from flask import Flask, request, jsonify, send_file
import os
import joblib
import functools

app = Flask(__name__)

# Directory to store models
MODEL_DIR = "models"

# Basic authentication
def check_auth(username, password):
    return username == 'admin' and password == 'secret'

def authenticate():
    return jsonify({"message": "Authentication required"}), 401

def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def requires_data(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if data exists in JSON or form
        data = request.json if request.is_json else request.form
        if not data:
            return jsonify({"error": "Bad Request", 
                            "message": "Request data is missing."}), 400
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health_check', methods=['GET'])
def health_check():
    return jsonify({"message": "App is running"}), 200

@app.route('/upload_model', methods=['POST'])
@requires_auth
@requires_data
def upload_model():
    data = request.json if request.is_json else request.form
    version = data.get('version')
    if not version:
        return jsonify({"message": "Model version is required"}), 400
    model_file = request.files['model']

    # Define the directory path
    model_dir = os.path.join(MODEL_DIR, version)

    # Create the directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)

    # Save the model file
    model_file.save(f'{MODEL_DIR}/{version}/{model_file.filename}')
    return jsonify({'message': f'Model {version} uploaded successfully'}), 200

@app.route('/remove_model', methods=['DELETE'])
@requires_auth
@requires_data
def remove_model():
    data = request.json if request.is_json else request.form
    model_name = data.get('model_name')
    if not model_name:
        return jsonify({"message": "Model name to remove is required"}), 400
    version = data.get('version')
    if not version:
        return jsonify({"message": "Model version is required"}), 400

    model_dir = f'{MODEL_DIR}/{version}'
    model_file = f'{MODEL_DIR}/{version}/{model_name}'

    if os.path.exists(model_file):
        try:
            os.remove(model_file)
            dir_contents = os.listdir(model_dir)
            if not dir_contents:
                os.rmdir(model_dir)
        except Exception as e:
            return jsonify({'message': str(e)}), 500
    else:
        return jsonify({'message': f'Model {model_name} not found '
                       f'for version {version}'}), 404
    return jsonify({'message': f'Removed model name '
                   f'{model_name} for version {version}'}), 200

@app.route('/predict', methods=['POST'])
@requires_auth
@requires_data
def predict():
    data = request.json if request.is_json else request.form

    version = data.get('version')
    if not version:
        return jsonify({'message': 'Model version required.'}), 400

    model_name = data.get('model_name')
    if not model_name:
        return jsonify({'message': 'Model name is required'}), 400

    model_path = os.path.join(MODEL_DIR, version, model_name)
    
    if not os.path.exists(model_path):
        #return jsonify({f'message': 'Model {model_name} not found '
        return jsonify({f'message': 'Model ' + model_name + ' not found '
                        f'for version {version}'}), 404

    # Load the model
    with open(model_path, 'rb') as f:
        model = joblib.load(f)
    
    # Adjust based on your model input format
    features = data.get('features') or data.get('data')
    
    if not features:
        return jsonify({'message': 'No features or data provided'}), 400

    # Perform prediction
    prediction = model.predict([features])
    
    return jsonify({'prediction': prediction.tolist()}), 200

@app.route('/list_models', methods=['GET'])
@requires_auth
def list_models():
    models = {}
    if os.path.exists(MODEL_DIR):
        for version in os.listdir(MODEL_DIR):
            version_path = os.path.join(MODEL_DIR, version)
            if os.path.isdir(version_path):
                models[version] = [f for f in os.listdir(version_path)]
    return jsonify(models), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
