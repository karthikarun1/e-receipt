import os
import joblib
import json
import logging
import functools
import re
import time


from flask import Flask, request, jsonify, send_file
from flasgger import Swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename


app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

# Sample user data (in real applications, use a database)
jwt_users = {"admin": "pass1"}


# For API documentation.
swagger = Swagger(app, template={
    "securityDefinitions": {
        "basicAuth": {
            "type": "basic"
        }
    }
})


logging.basicConfig(level=logging.INFO)
app.logger.addHandler(logging.StreamHandler())


# Directory to store models
MODEL_DIR = "models"

@app.route('/login', methods=['POST'])
def login():
    """
    User login
    ---
    parameters:
      - name: username
        in: body
        required: true
        schema:
          type: string
      - name: password
        in: body
        required: true
        schema:
          type: string
    responses:
      200:
        description: Successful login
      401:
        description: Invalid credentials
    """
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # validate from database 
    #user = User.query.filter_by(username=username).first()
    #if user and check_password_hash(user.password_hash, password):
    #    access_token = create_access_token(identity={'username': user.username})
    #    return jsonify(access_token=access_token), 200
    #else:
    #    return jsonify({'msg': 'Invalid credentials'}), 401

    # validate from users dict 
    if jwt_users.get(username) == password:
        # Create JWT token if credentials are valid
        access_token = create_access_token(identity={'username': username})
        return jsonify(access_token=access_token), 200
    else:
        # Return 401 Unauthorized if credentials are invalid
        return jsonify({'msg': 'Invalid credentials'}), 401


# Basic authentication
def check_auth(username, password):
    return username == 'admin' and password == 'secret'


def authenticate():
    return jsonify({"message": "Authentication required"}), 401


# Sanitize filename by removing any potentially dangerous characters
def sanitize_filename(filename):
    return re.sub(r'[^\w\s.-]', '', filename).strip()

# Clean up input data by trimming whitespace from string values
def sanitize_input(data):
    return {key: value.strip() if isinstance(value, str) else value for key, value in data.items()}

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad Request", "message": str(error)}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not Found", "message": str(error)}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal Server Error", "message": str(error)}), 500


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
        # Check if data exists in JSON, form, or files for POST, PUT, DELETE
        if request.method in ['POST', 'PUT', 'DELETE']:
            data = request.json if request.is_json else request.form
            if not data and not request.files:
                return bad_request('Request data is missing')
        # Check if data exists in args for GET requests
        elif request.method == 'GET':
            if not request.args:
                return bad_request('Request data is missing')
        return f(*args, **kwargs)
    return decorated_function


@app.route('/health_check', methods=['GET'])
def health_check():
    return jsonify({"message": "App is running"}), 200


@app.route('/upload_model', methods=['POST'])
@jwt_required()
@requires_data
def upload_model():
    """
    Upload a model
    ---
    security:
      - JWT: []
    parameters:
      - name: model_name
        in: formData
        type: string
        description: Name of the model
        required: true
      - name: version
        in: formData
        type: string
        description: Version of the model
        required: true
      - name: model_file
        in: formData
        type: file
        description: The model file to upload
        required: true
    responses:
      200:
        description: Model uploaded successfully
      401:
        description: Unauthorized, token missing or invalid
    """
    current_user = get_jwt_identity()

    data = request.json if request.is_json else request.form
    data = sanitize_input(data)  # Clean up data

    version = data.get('version')
    if not version or not isinstance(version, str):
        return bad_request("Valid model version is required")

    model_file = request.files.get('model_file')
    if not model_file:
        return bad_request("Model file is required")

    # Sanitize model filename
    filename = sanitize_filename(model_file.filename)
    if not filename:
        return bad_request("Invalid model file name")

    # Define the directory path
    model_dir = os.path.join(MODEL_DIR, version)

    # Create the directory if it doesn't exist
    os.makedirs(model_dir, exist_ok=True)

    # Save the model file securely
    file_path = os.path.join(model_dir, secure_filename(filename))
    try:
        model_file.save(file_path)
    except Exception as e:
        return internal_error(f"Error saving model file: {str(e)}")

    return jsonify({'message': f'Version {version} of model '
                    f'{model_file.filename} uploaded successfully'}), 200


@app.route('/retrieve_model', methods=['GET'])
@requires_auth
#@requires_data
def retrieve_model():
    """
    Retrieve a machine learning model file.
    ---
    security:
      - basicAuth: []
    parameters:
      - name: model_filename
        in: query
        type: string
        required: true
        description: The name of the model to retrieve.
      - name: version
        in: query
        type: string
        required: true
        description: The version of the model to retrieve.
    responses:
      200:
        description: The requested model file
        schema:
          type: file
      400:
        description: Invalid input or missing model_filename/version
      404:
        description: Model not found
      500:
        description: Internal server error while retrieving the model
    """
    model_filename = request.args.get('model_filename')
    version = request.args.get('version')

    if not version or not model_filename:
        return bad_request('Model version and filename are required')

    # Construct the path to the model file
    model_path = os.path.join(MODEL_DIR, version, model_filename)

    # Check if the model file exists
    if os.path.exists(model_path):
        return send_file(model_path, as_attachment=True)
    else:
        return not_found(f'Model {model_filename} version {version} not found')


@app.route('/remove_model', methods=['DELETE'])
@requires_auth
@requires_data
def remove_model():
    """
    Remove a machine learning model.
    ---
    security:
      - basicAuth: []
    parameters:
      - name: model_filename
        in: formData
        type: string
        required: true
        description: The name of the model to be removed.
      - name: version
        in: formData
        type: string
        required: true
        description: The version of the model to be removed.
    responses:
      200:
        description: Model removed successfully
      400:
        description: Model name or version is missing
      404:
        description: Model not found
      500:
        description: Internal server error while removing the model
    """
    data = request.json if request.is_json else request.form
    model_filename = data.get('model_filename')
    if not model_filename:
        return bad_request('Model filename to remove is required')
    version = data.get('version')
    if not version:
        return bad_request('Model version is required')

    model_dir = f'{MODEL_DIR}/{version}'
    model_file = f'{MODEL_DIR}/{version}/{model_filename}'

    if os.path.exists(model_file):
        try:
            os.remove(model_file)
            dir_contents = os.listdir(model_dir)
            if not dir_contents:
                os.rmdir(model_dir)
        except Exception as e:
            return internal_error(str(e))
    else:
        return not_found(f'Model {model_filename} not found '
                         f'for version {version}')
    return jsonify({'message': f'Removed model name '
                   f'{model_filename} for version {version}'}), 200


@app.route('/predict', methods=['POST'])
@requires_auth
@requires_data
def predict():
    """
    Predict using a machine learning model.
    ---
    security:
      - basicAuth: []
    parameters:
      - name: data
        in: body
        required: true
        schema:
          type: object
          properties:
            data:
              type: array
              items:
                type: number
              description: The input data for prediction.
            model_filename:
              type: string
              description: The filename of the model to use for prediction.
          required:
            - data
            - model_filename
    responses:
      200:
        description: Prediction result
        schema:
          type: object
          properties:
            prediction:
              type: number
              description: The result of the prediction.
      400:
        description: Invalid input or missing model_filename/data
      404:
        description: Model not found
      500:
        description: Internal server error during prediction
    """
    data = request.json if request.is_json else request.form

    version = data.get('version')
    if not version:
        return bad_request('Model version required.')

    model_filename = data.get('model_filename')
    if not model_filename:
        return bad_request('Model filename is required')


    model_path = os.path.join(MODEL_DIR, version, model_filename)

    if not os.path.exists(model_path):
        return not_found(f'Model ' + model_filename + ' not found '
                         f'for version {version}')

    # Load the model
    with open(model_path, 'rb') as f:
        model = joblib.load(f)
    
    # Adjust based on your model input format
    features = data.get('features') or data.get('data')
    
    if not features:
        return bad_request('No features or data provided')

    # Perform prediction
    prediction = model.predict([features])
    
    return jsonify({'prediction': prediction.tolist()}), 200


@app.route('/list_models', methods=['GET'])
@requires_auth
def list_models():
    """
    List all available machine learning models.
    ---
    security:
      - basicAuth: []
    responses:
      200:
        description: A list of available models
        schema:
          type: object
          properties:
            models:
              type: array
              items:
                type: string
              description: List of model filenames.
      401:
        description: Unauthorized, authentication required
      500:
        description: Internal server error while retrieving the model list
    """
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
        json_str = json.dumps(json_data) if json_data else ''

        # Get data from request.form
        form_data = request.form.to_dict()
        form_str = json.dumps(form_data) if form_data else "No form data"

        # Prepare log data
        log_message = (
            f"Request to {request.endpoint} - Method: {request.method}, "
            f"Path: {request.path}, Duration: {duration:.2f} seconds, "
            f"Status Code: {response.status_code}, "
        )
        if json_str:
            log_message += f"JSON Data: {json_str}, "

        if request.endpoint == 'upload_model':
            # Get file information
            model_file = request.files.get('model_file')
            model_filename = model_file.filename if model_file else "No file uploaded"

            log_message += f"Form Data: {form_str}, "
            log_message += f"Model Filename: {model_filename}"

        app.logger.info(log_message)
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
