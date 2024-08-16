from flask import Flask, request, jsonify, send_file
import os
import joblib
import json
import logging
import functools
import time


app = Flask(__name__)


logging.basicConfig(level=logging.INFO)
app.logger.addHandler(logging.StreamHandler())


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


@app.route('/retrieve_model', methods=['GET'])
@requires_auth
@requires_data
def retrieve_model():
    data = request.json if request.is_json else request.form
    version = data.get('version')
    model_filename = data.get('model_filename')

    if not version or not model_filename:
        return jsonify({"message": "Model version and filename are required"}), 400

    # Construct the path to the model file
    model_path = os.path.join(MODEL_DIR, version, model_filename)
    print ('model_path: %s' % model_path)

    # Check if the model file exists
    if os.path.exists(model_path):
        print ('yes model file {model_path} exists')
        return send_file(model_path, as_attachment=True)
    else:
        print ('no model file {model_path} does not exist')
        return jsonify({'message': f'Model {model_filename} version {version} not found'}), 404


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
            return jsonify({'error': str(e)}), 500
    else:
        return jsonify({'error': f'Model {model_name} not found '
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
        return jsonify({'error': 'Model version required.'}), 400

    model_name = data.get('model_name')
    if not model_name:
        return jsonify({'error': 'Model name is required'}), 400


    model_path = os.path.join(MODEL_DIR, version, model_name)

    print (f'model_path: {model_path}')
    
    if not os.path.exists(model_path):
        return jsonify({f'error': 'Model ' + model_name + ' not found '
                        f'for version {version}'}), 404

    # Load the model
    with open(model_path, 'rb') as f:
        model = joblib.load(f)
    
    # Adjust based on your model input format
    features = data.get('features') or data.get('data')
    
    if not features:
        return jsonify({'error': 'No features or data provided'}), 400

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


# Metrics and log collection


@app.before_request
def log_request_info():
    if request.endpoint == 'predict':
        app.logger.info(f"Predict endpoint called with data: {request.json}")


@app.before_request
def start_timer():
    if request.endpoint != 'list_models':
        request.start_time = time.time()


@app.before_request
def start_timer():
    if request.endpoint != 'list_models':
        request.start_time = time.time()


@app.before_request
def start_timer():
    if request.endpoint != 'list_models':
        request.start_time = time.time()


@app.after_request
def log_request_info(response):
    if request.endpoint != 'list_models':
        duration = time.time() - getattr(request, 'start_time', time.time())

        # Get data from request.json
        json_data = request.get_json(silent=True) if request.is_json else None
        json_str = json.dumps(json_data) if json_data else "No JSON data"

        # Get data from request.form
        form_data = request.form.to_dict()
        form_str = json.dumps(form_data) if form_data else "No form data"

        # Prepare log data
        log_message = (
            f"Request to {request.endpoint} - Method: {request.method}, "
            f"Path: {request.path}, Duration: {duration:.2f} seconds, "
            f"Status Code: {response.status_code}, "
            f"JSON Data: {json_str}, "
        )

        if request.endpoint == 'upload_model':
            # Get file information
            model_file = request.files.get('model')
            model_filename = model_file.filename if model_file else "No file uploaded"

            log_message += f"Form Data: {form_str}, "
            log_message += f"Model Filename: {model_filename}"

        app.logger.info(log_message)
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
