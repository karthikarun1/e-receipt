import os
import joblib
import json
import logging
import functools
import re
import shutil
import tempfile
import time

from datetime import datetime
from dotenv import load_dotenv
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

# Configuration to control detailed logging
load_dotenv()
DETAILED_LOGGING = os.getenv('DETAILED_LOGGING', 'false').lower() == 'true'

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


def create_model_metadata(model_name, version, file_extension,
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
    metadata_path = os.path.join('models', metadata_filename)
    
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
    file_path = os.path.join(MODEL_DIR, filename)
    model_file.save(file_path)

    # Create metadata
    metadata_path = create_model_metadata(
            model_name, version, file_extension, description,
            accuracy, current_user)

    return jsonify({
        'model_name': model_name,
        'version': version,
        'metadata_path': metadata_path
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
    metadata_path = os.path.join(MODEL_DIR, metadata_filename)
    
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
    model_path = os.path.join(MODEL_DIR, model_filename)

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
    model_file_path = os.path.join(MODEL_DIR, model_filename)

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


@app.route('/remove_model/<string:model_name>/<string:version>', methods=['DELETE'])
@jwt_required()
def remove_model1(model_name, version):
    """
    Remove a machine learning model.
    ---
    security:
      - JWT: []
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
    current_user = get_jwt_identity()

    if not model_name or not version:
        return bad_request("Model name and version are required")

    metadata_path = os.path.join(MODEL_DIR, f'{model_name}_{version}_metadata.json')
    
    # Check if the metadata file exists
    if not os.path.exists(metadata_path):
        return not_found(f'Metadata for model {model_name} version {version} not found')

    try:
        # Load metadata to get the file extension
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
            file_extension = metadata.get('file_extension', 'pkl')  # Default to 'pkl' if not found
        
        model_filename = f'{model_name}_{version}.{file_extension}'
        model_file_path = os.path.join(MODEL_DIR, model_filename)
        
        if os.path.exists(model_file_path):
            os.remove(model_file_path)
            return jsonify({'message': f'Removed model {model_filename}'}), 200
        else:
            return not_found(f'Model {model_filename} not found')

    except Exception as e:
        return internal_error(f'Error processing request: {str(e)}')


@app.route('/predict/<string:model_name>/<string:version>', methods=['POST'])
@jwt_required()
#@requires_data
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
    model_file_path = os.path.join(MODEL_DIR, model_filename)

    if not os.path.exists(model_file_path):
        return not_found(f'Model ' + model_filename + ' not found '
                         f'for version {version}')

    # Load the model
    with open(model_file_path, 'rb') as f:
        model = joblib.load(f)
    
    # Adjust based on your model input format
    features = data.get('features') or data.get('data')
    
    if not features:
        return bad_request('No features or data provided')

    # Perform prediction
    prediction = model.predict([features])
    
    return jsonify({'prediction': prediction.tolist()}), 200


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

    if os.path.exists(MODEL_DIR):
        for version in os.listdir(MODEL_DIR):
            version_path = os.path.join(MODEL_DIR, version)
            if os.path.isdir(version_path):
                models[version] = [f for f in os.listdir(version_path)]
    return jsonify(models), 200
    """
    models = {}

    if os.path.exists(MODEL_DIR):
        for filename in os.listdir(MODEL_DIR):
            file_path = os.path.join(MODEL_DIR, filename)
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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
