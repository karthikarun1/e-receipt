import os
import joblib
import json
import logging
import functools
import re
import shutil
import tempfile
import time

# System defined
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file
from flasgger import Swagger
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from prometheus_client import CollectorRegistry, Gauge, generate_latest, Summary
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# User defined
from storage import MlModelStorage
from metadata_store import MetadataStore


app = Flask(__name__)

# Configuration to control detailed logging
load_dotenv()

app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
jwt = JWTManager(app)

USER_FILE = 'users.json'

# Sample user data (in real applications, use a database)
jwt_users = {"admin": "pass1"}

def load_users():
    try:
        with open(USER_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open(USER_FILE, 'w') as f:
        json.dump(users, f)

USERS = load_users()

# Create a prometheus metric
registry = CollectorRegistry()
g = Gauge('example_metric', 'Example metric for demonstration', registry=registry)
REQUEST_DURATION = Summary('http_request_duration_seconds', 'Duration of HTTP requests in seconds')

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

DETAILED_LOGGING = os.getenv('DETAILED_LOGGING', 'false').lower() == 'true'

# Directory to store models
LOCAL_DIR = os.getenv('LOCAL_DIR')

USAGE_LOG_FILE_NAME='usage_logs.txt'

# Create a metric to track prediction times
PREDICTION_TIME = Summary('prediction_duration_seconds', 'Time spent processing prediction requests')

@app.route('/metrics')
def metrics():
    # Update metric values if needed
    #g.set(42)  # Example value
    #return Response(generate_latest(registry), mimetype='text/plain; version=0.0.4; charset=utf-8')
    # Expose the metrics to Prometheus
    return generate_latest()


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


def sanitize_data(data):
    # Example sanitization: Convert all strings to str type and strip whitespace
    sanitized_data = {}
    for key, value in data.items():
        if isinstance(value, str):
            sanitized_data[key] = value.strip()
        else:
            sanitized_data[key] = value
    return sanitized_data


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


@app.route('/check_logging')
def check_logging():
    return f"DETAILED_LOGGING is set to: {DETAILED_LOGGING}\n"


from io import BytesIO

def validate_model(model_file):
    try:
        # Create an in-memory copy of the file for validation
        model_file_stream = BytesIO(model_file.read())
        model_file.seek(0)  # Reset the original file stream position

        # Validate the model from the in-memory stream
        joblib.load(model_file_stream)
        return True
    except Exception as e:
        app.logger.error(f"Model validation failed: {str(e)}")
        return False


def create_model_metadata(user_id, model_name, version, file_extension,
                          description=None, accuracy=None,
                          current_user=None):
    """
    Creates and saves metadata for the uploaded model.

    Args:
        model_filename (str): The filename of the uploaded model.
        version (str): The version of the uploaded model.
        description (str, optional): Description of the model.
        accuracy (float, optional): Accuracy of the model.
        current_user (str, optional): Username of the person uploading the model.

    Returns:
        str: Path to the metadata file.
    """
    # Generate metadata
    metadata = {
        'model_name': model_name,
        'file_extension': file_extension,
        'version': version,
        'description': description or 'No description provided',
        'accuracy': accuracy if accuracy is not None else 'Accuracy not provided',
        'created_by': current_user or 'Unknown',
        'created_at': datetime.utcnow().isoformat()
    }

    # Define metadata file path
    metadata_filename = f"{model_name}_{version}_metadata.json"  # Adjust versioning as needed
    metadata_path = os.path.join(user_id, LOCAL_DIR, metadata_filename)
    
    # Save metadata to file
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    
    return metadata_path


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

    # Check if request is JSON or form
    data = request.json if request.is_json else request.form

    # Sanitize and validate input
    data = sanitize_data(data)
    model_name = data.get('model_name')
    version = data.get('version')
    accuracy = data.get('accuracy', 'N/A')
    description = data.get('description', 'No description')
    model_file = request.files.get('model_file')

    if not model_name:
        return bad_request('Model name is required')

    if not version:
        return bad_request('version is required')

    if not model_file:
        return bad_request("Model file is required")

    # Validate the model before saving
    if not validate_model(model_file):
        return bad_request('Invalid model file')

    # Secure the file name and save it
    file_extension = model_file.filename.rsplit('.', 1)[-1].lower()
    filename = f"{model_name}_{version}.{file_extension}"
    file_path = os.path.join(LOCAL_DIR, filename)

    user_id = 'admin_user_id' 
    group_id = None
    success, error = MlModelStorage().save(
        filename,
        model_file,
        version,
        model_name,
        file_extension,
        current_user, 
        user_id,
        group_id,
        description,
        accuracy,
    )

    if error:
        return bad_request(f'Error: {error}. Unable to save model version '
                           f'{version} for {model_name}')

    return jsonify({
        'model_name': model_name,
        'version': version,
    }), 201


def get_file_extension_from_metadata(model_name, version):
    """
    Obtain the file extension from the metadata file for a given model and version.

    Args:
        model_name (str): The name of the model.
        version (str): The version of the model.

    Returns:
        str: The file extension of the model file.
        None: If metadata or file extension is not found.
    """
    # Construct the metadata file path
    metadata_filename = f"{model_name}_{version}_metadata.json"
    metadata_path = os.path.join(LOCAL_DIR, metadata_filename)
    
    # Check if the metadata file exists
    if not os.path.isfile(metadata_path):
        return None, None
    
    # Read metadata to get file extension
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    return metadata_path, metadata.get('file_extension', None)


@app.route('/download_model/<string:model_name>/<string:version>', methods=['GET'])
@jwt_required()
def download_model(model_name, version):
    """
    Retrieve and download a specific model.

    This endpoint allows users to download a model by specifying its name and version.

    ---
    tags:
      - Models
    parameters:
      - name: model_name
        in: path
        required: true
        schema:
          type: string
      - name: version
        in: path
        required: true
        schema:
          type: string
    security:
      - jwtAuth: []
    responses:
      '200':
        description: Model file successfully retrieved
        content:
          application/octet-stream:
            schema:
              type: string
              format: binary
      '404':
        description: Model not found
    """
    current_user = get_jwt_identity()

    if not model_name or not version:
        return bad_request("Model name and version are required")

    # Obtain file extension from metadata
    metadata_path, file_extension = get_file_extension_from_metadata(model_name, version)

    if metadata_path is None:
        return not_found(f'Metadata for model {model_name} version '
                         f'{version} not found')
    if file_extension is None:
        return not_found('File extension not found in metadata')

    model_filename = f"{model_name}_{version}.{file_extension}"

    # Construct the path to the model file
    model_path = os.path.join(LOCAL_DIR, model_filename)

    # Check if the model file exists
    if os.path.exists(model_path):
        return send_file(model_path, as_attachment=True)
    else:
        return not_found(f'Model {model_filename} version {version} not found')


@app.route('/remove_model/<string:model_name>/<string:version>', methods=['DELETE'])
def remove_model(model_name, version):
    # Check if model_name and version are provided
    if not model_name or not version:
        return bad_request("Model name and version are required")

    metadata_path, file_extension = get_file_extension_from_metadata(model_name, version)
    model_filename = f'{model_name}_{version}.{file_extension}'
    model_file_path = os.path.join(LOCAL_DIR, model_filename)

    if metadata_path is None:
        return not_found(f'Metadata for model {model_name} version '
                         f'{version} not found')
    if file_extension is None:
        return not_found('File extension not found in metadata')

    # Remove the model file
    if os.path.exists(model_file_path):
        os.remove(model_file_path)
    else:
        return not_found(f'Model file {model_filename} not found')

    # Remove the metadata file
    if os.path.exists(metadata_path):
        os.remove(metadata_path)

    return jsonify({'message': f'Removed model {model_filename} and metadata'}), 200


def evaluate_prediction(model, input_data, expected_output=None):
    """
    Evaluate the model's prediction and optionally compare it to expected output.

    Args:
        model (object): The loaded model.
        input_data (dict): The input data for the prediction.
        expected_output (any, optional): The expected output to compare against.

    Returns:
        dict: A dictionary containing prediction results and accuracy (if applicable).
    """
    prediction = model.predict([input_data])
    result = {
        'prediction': prediction,
    }

    if expected_output is not None:
        accuracy = None
        try:
            accuracy = prediction[0] == expected_output  # Simple accuracy check
        except Exception as e:
            app.logger.error(f"Error evaluating accuracy: {str(e)}")
        result['accuracy'] = accuracy

    return result


@PREDICTION_TIME.time()
def predict_with_metrics(model_file_path, features, expected_output):
    # Load the model
    with open(model_file_path, 'rb') as f:
        model = joblib.load(f)
    result = evaluate_prediction(model, features, expected_output)
    return result


@app.route('/predict/<string:model_name>/<string:version>', methods=['POST'])
@jwt_required()
def predict(model_name, version):
    """
    Predict using a machine learning model.
    ---
    security:
      - JWT: []
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
    start_time = time.time()
    current_user = get_jwt_identity()
    data = request.json if request.is_json else request.form

    if not model_name or not version:
        return bad_request("Model name and version are required")

    metadata_path, file_extension = get_file_extension_from_metadata(model_name, version)

    if metadata_path is None:
        return not_found(f'Metadata for model {model_name} version '
                         f'{version} not found')
    if file_extension is None:
        return not_found('File extension not found in metadata')

    model_filename = f'{model_name}_{version}.{file_extension}'
    model_file_path = os.path.join(LOCAL_DIR, model_filename)

    if not os.path.exists(model_file_path):
        return not_found(f'Model ' + model_filename + ' not found '
                         f'for version {version}')

    
    # Adjust based on your model input format
    features = data.get('features') or data.get('data')
    
    if not features:
        return bad_request('No features or data provided')

    # Load the model
    #with open(model_file_path, 'rb') as f:
    #    model = joblib.load(f)

    expected_output = data.get('expected_output', None)
    #result = evaluate_prediction(model, features, expected_output)

    result = predict_with_metrics(model_file_path, features, expected_output)

    # Log usage
    if os.getenv('LOG_MODEL_USAGE', 'False').lower() == 'true':
        log_model_usage(model_name, version, features,
                        result['prediction'].tolist(),
                        result.get('accuracy'))

    duration = time.time() - start_time
    app.logger.info(f"Prediction processed in {duration:.2f} seconds")
  
    if expected_output: 
        return jsonify({'prediction': result['prediction'].tolist(),
                        'accuracy': str(result['accuracy'])}), 200
    else:
        return jsonify({'prediction': result['prediction'].tolist()}), 200


def log_model_usage(model_name, version, input_data, output, prediction_accuracy):
    log_entry = (f'{time.strftime('%Y-%m-%d %H:%M:%S')} - Model: {model_name} '
                 f'Version: {version} - Input: {input_data} - '
                 f'Output: {output}\n')
    with open(USAGE_LOG_FILE_NAME, 'a') as log_file:
        log_file.write(log_entry)


@app.route('/list_models', methods=['GET'])
@jwt_required()
def list_models():
    """
    List all available machine learning models.
    ---
    security:
      - JWT: []
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
    current_user = get_jwt_identity()

    models = {}

    if os.path.exists(LOCAL_DIR):
        for version in os.listdir(LOCAL_DIR):
            version_path = os.path.join(LOCAL_DIR, version)
            if os.path.isdir(version_path):
                models[version] = [f for f in os.listdir(version_path)]
    return jsonify(models), 200
    """
    models = {}

    if os.path.exists(LOCAL_DIR):
        for filename in os.listdir(LOCAL_DIR):
            file_path = os.path.join(LOCAL_DIR, filename)
            if os.path.isfile(file_path):
                # Extract model name and version from filename
                base_name, ext = os.path.splitext(filename)
                if ext.startswith('.'):
                    ext = ext[1:]  # Remove leading dot
                parts = base_name.rsplit('_', 1)
                if len(parts) == 2:
                    model_name, version = parts
                    if version not in models:
                        models[version] = []
                    models[version].append({
                        'model_name': model_name,
                        'file_extension': ext
                    })

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
            log_message += f"Model Filename: {model_filename}, "

        # Additional logging for the predict endpoint
        if request.endpoint == 'predict' and json_data:
            model_name = json_data.get('model_filename', 'unknown_model')
            model_version = json_data.get('version', 'unknown_version')
            log_message += (
                f", Model: {model_name}, Version: {model_version}, "
                f"Prediction Time: {duration:.2f} seconds, "
            )

        if DETAILED_LOGGING:
            # Log user identity and IP address
            user_info = request.remote_addr
            log_message += f"User IP: {user_info}, "
            user_agent = request.headers.get('User-Agent', 'Unknown')
            log_message += f"User-Agent: {user_agent}"

        app.logger.info(log_message)
    return response


@app.after_request
def record_duration(response):
    if hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
        REQUEST_DURATION.observe(duration)
    return response


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
