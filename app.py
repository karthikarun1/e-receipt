import os
import io
import joblib
import json
import jwt
import logging
import functools
import re
import shutil
import traceback
import tempfile
import time

import dynamodb_utils
import s3_utils
import utils

# System defined
from datetime import datetime
from flask import Flask, redirect, request, jsonify, render_template_string, send_file, session, url_for
from flasgger import Swagger
from input_validator import InputValidator
from prometheus_client import CollectorRegistry, Gauge, generate_latest, Summary, REGISTRY
from urllib.parse import unquote
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# User defined
from invite_type import InviteType
from metadata_store import MetadataStore
from org_management import OrganizationManager
from superuser_management import register_superuser_command
from storage import MlModelStorage
from subscription_management import SubscriptionManager
from user_management import UserManager

# load environment variables
from config_loader import load_environment
load_environment()

app = Flask(__name__)

# Register the superuser CLI command
register_superuser_command(app)

JWT_SECRET = os.getenv('JWT_SECRET')
app.secret_key = JWT_SECRET  # needed for sessions to work

# Initialize globally
table_prefix = os.getenv('TABLE_PREFIX')
dynamodb_resource = dynamodb_utils.get_dynamodb_resource()
dynamodb_client = dynamodb_utils.get_dynamodb_client()
s3_client = s3_utils.get_client()
metadata_table_name = f'{table_prefix}_' + os.getenv('METADATA_TABLE')
metadata_store = MetadataStore(table_name=metadata_table_name)
storage = MlModelStorage(metadata_store=metadata_store)

user_manager = UserManager(dynamodb_resource, table_prefix)
org_manager = OrganizationManager(dynamodb_resource, table_prefix)

# Create a prometheus metric
registry = CollectorRegistry()
g = Gauge('example_metric', 'Example metric for demonstration', registry=registry)
# Clear the registry (useful in development environments)
for collector in list(REGISTRY._collector_to_names.keys()):
    REGISTRY.unregister(collector)
REQUEST_DURATION = Summary('http_request_duration_seconds', 'Duration of HTTP requests in seconds')

# For API documentation.
swagger = Swagger(app, template={
    "securityDefinitions": {
        "basicAuth": {
            "type": "basic"
        }
    }
})

# configure logging - see README.logging
app.logger.addHandler(logging.StreamHandler())
logger = logging.getLogger(__name__)

# Set logging level
# Get the logging level from the .env file
logging_level = os.getenv('LOGGING_LEVEL', 'INFO').upper()
# Convert the logging level to the corresponding logging constant
numeric_level = getattr(logging, logging_level, logging.INFO)
logging.basicConfig(level=numeric_level)
logger.setLevel(numeric_level)
app.logger.setLevel(numeric_level)

DETAILED_LOGGING = os.getenv('DETAILED_LOGGING', 'false').lower() == 'true'
LOG_VALUEERROR = os.getenv('LOG_VALUEERROR', 'false').lower() == 'true'

USAGE_LOG_FILE_NAME='usage_logs.txt'

# Create a metric to track prediction times
PREDICTION_TIME = Summary('prediction_duration_seconds', 'Time spent processing prediction requests')

# Load the maximum model file size limit from the .env file (convert MB to bytes)
MAX_MODEL_FILE_SIZE_MB = int(os.getenv('MAX_MODEL_FILE_SIZE_MB', 100))  # Default to 100 MB if not set
MAX_MODEL_FILE_SIZE = MAX_MODEL_FILE_SIZE_MB * 1024 * 1024  # Convert MB to bytes

# Utility function to get request data
def get_request_data():
    """Retrieve data from request in a flexible way, handling JSON, form data, and query parameters."""
    data = None
    if request.is_json:
        data = request.get_json()
    elif request.form:
        data = request.form.to_dict()
    else:
        data = request.args.to_dict()
    sanitized_data = utils.sanitize_input(data)
    logger.debug (f'sanitized input data is {sanitized_data}')
    app.logger.debug (f'sanitized input data is {sanitized_data}')
    # Dynamically validate fields based on method names in InputValidator
    for key in sanitized_data.keys():
        validation_method_name = f'validate_{key}'
        if hasattr(InputValidator, validation_method_name):
            validator = getattr(InputValidator, validation_method_name)
            sanitized_data[key] = validator(sanitized_data[key])

    return sanitized_data


@app.route('/metrics')
def metrics():
    # Update metric values if needed
    #g.set(42)  # Example value
    #return Response(generate_latest(registry), mimetype='text/plain; version=0.0.4; charset=utf-8')
    # Expose the metrics to Prometheus
    return generate_latest()


# Middleware to redirect logged-in users away from unauthenticated pages
def redirect_if_logged_in(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if token:
            try:
                # Decode the token using the JWT secret
                data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
                user_id = data['user_id']

                # Check if the token is revoked
                response = user_manager.revoked_tokens_table.get_item(Key={'token': token})
                if 'Item' in response:
                    logger.error(f'Token has been revoked for user_id: {user_id}')
                    return redirect(url_for('home'))  # Redirect to home page

                # Check if the user exists in the database
                user = user_manager.get_user_details_by_id(user_id)
                if not user:
                    logger.error(f'User not found for user_id: {user_id}')
                    return redirect(url_for('home'))  # Redirect to home page

                # If everything is valid, redirect the user
                return redirect(url_for('home'))  # Redirect to home page

            except jwt.ExpiredSignatureError:
                # Handle expired token
                logger.error(f'Token has expired for user_id: {user_id}')
                return redirect(url_for('home'))  # Redirect to home page
            except jwt.InvalidTokenError:
                # Handle invalid token
                logger.error(f'Token is invalid for user_id: {user_id}')
                return redirect(url_for('home'))  # Redirect to home page
            except Exception as e:
                logger.error(f"An unexpected error occurred for user_id: {user_id}: {e}")
                traceback.print_exc()
                return redirect(url_for('home'))  # Redirect to home page

        return f(*args, **kwargs)
    return decorated_function


# Middleware to protect routes
def token_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        revokedtokens_table = dynamodb_resource.Table(f'{table_prefix}_RevokedTokens')
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            token = auth_header.split(" ")[1]  # Extract the token part from the header

        if not token:
            # Store the original URL the user was trying to access
            session['next'] = request.url
            return redirect(url_for('login'))  # Redirect to login page

        # Check if the token is in the revokedtokens_table
        response = revokedtokens_table.get_item(Key={'token': token})
        if 'Item' in response:
            return jsonify({'message': 'Token has been revoked!'}), 401

        # Decode the token using the secret
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = data['user_id']

        # Check if the user exists in the database
        user = user_manager.get_user_details_by_id(user_id)
        if not user:
            #return jsonify({'message': 'User not found!'}), 401
            return jsonify({'message': 'Invalid username or email or password!'}), 401

        return f(user, *args, **kwargs)

    return decorated


def superuser_required(f):
    @token_required
    @functools.wraps(f)
    def decorated(user, *args, **kwargs):
        if not user.get('superuser', False):
            return jsonify({'message': 'You do not have permission to access this resource.'}), 403
        return f(user, *args, **kwargs)

    return decorated


# Example protected route
@app.route('/protected_resource', methods=['GET'])
@token_required
def protected_resource(user):
    # This resource is protected and only accessible with a valid token and registered user
    return jsonify({'message': f'Welcome, {user["username"]}! This is a protected resource.'})


@app.route('/create_organization', methods=['POST'])
@token_required
def create_organization(current_user):
    data = get_request_data()

    org_name = data.get('org_name')
    if not org_name:
        return jsonify({'error': 'Organization name is required'}), 400

    # Call the create_organization method
    organization = org_manager.create_organization(
        org_name=org_name,
        creator_user_id=current_user['id']
    )

    return jsonify({'message': 'Organization created successfully', 'organization': organization}), 201


@app.route('/update_organization', methods=['POST'])
@token_required
def update_organization(current_user):
    data = get_request_data()

    org_id = data.get('org_id')
    if not org_id:
        return jsonify({'error': 'Organization ID is required'}), 400

    # Check if the organization exists
    org = org_manager.get_organization_by_id(org_id)

    # Extract the fields to update, excluding 'org_id'
    updates = {key: value for key, value in data.items() if key != 'org_id'}

    # Proceed with the update logic
    updated_org = org_manager.update_organization(
        org_id=org_id,
        user_id=current_user['id'],  # Pass the current user's ID
        updates=updates
    )

    return jsonify({'message': 'Organization updated successfully', 'organization': updated_org}), 200


@app.route('/organization/details', methods=['GET'])
@token_required
def view_organization_details(current_user):
    # Get request data
    data = get_request_data()

    # Extract organization ID from the request data
    org_id = data.get('org_id')
    if not org_id:
        return jsonify({"error": "Organization ID is required."}), 400

    # Fetch organization details with authorization check
    organization_details = org_manager.get_organization_details(org_id, current_user['id'])

    return jsonify(organization_details), 200


@app.route('/organization/invite', methods=['POST'])
@token_required
def invite_users_to_organization(current_user):
    data = get_request_data()

    org_id = data.get('org_id')
    user_ids = data.get('user_ids')
    invite_type = InviteType.ORGANIZATION  # Set the invite type as ORGANIZATION

    if not org_id or not user_ids:
        return jsonify({"error": "Organization ID and user IDs are required."}), 400

    # Invite users to the organization
    invited_users = org_manager.invite_users(org_id, current_user['id'], user_ids, invite_type)

    if not invited_users:
        return jsonify({"message": "No new invitations were sent. The specified users might already be members."}), 200

    return jsonify({"message": "Invitations sent successfully.", "invited_users": invited_users}), 200


@app.route('/invite', methods=['GET'])
def process_invite():
    data = get_request_data()
    # Extract query parameters
    invitation_id = data.get('invitation_id')
    expires_at = unquote(data.get('expires_at'))
    signature = data.get('signature')

    print (f'------invitation id {invitation_id}')
    print (f'------expires at {expires_at}')
    print (f'------ signature {signature}')

    if not invitation_id or not expires_at or not signature:
        return jsonify({"error": "Invitation ID, expiration time, and signature are required."}), 400

    # Process the invitation
    result = org_manager.process_invitation(invitation_id, expires_at, signature)

    return jsonify(result), 200


@app.route('/user/organizations', methods=['GET'])
@token_required
def list_user_organizations(current_user):
    # Get the current user's ID from the token
    user_id = current_user['id']

    # Fetch organizations the user belongs to
    organizations = org_manager.get_user_organizations(user_id)

    if not organizations:
        return jsonify({"message": "User does not belong to any organizations."}), 404

    return jsonify({"organizations": organizations}), 200


@app.route('/list_all_organizations', methods=['GET'])
@superuser_required
def list_all_organizations(current_user):
    organizations = org_manager.get_all_organizations()
    return jsonify({"organizations": organizations}), 200


@app.route('/change_password', methods=['POST'])
@token_required
def change_password(current_user):
    data = get_request_data()

    user_id = current_user['id']
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not current_password or not new_password or not confirm_new_password:
        return jsonify({"message": "Missing required fields"}), 400

    result = user_manager.change_password(
        user_id=user_id,
        current_password=current_password,
        new_password=new_password,
        confirm_new_password=confirm_new_password
    )
        
    # Invalidate the token after a successful password change
    token = request.headers['Authorization'].split(" ")[1]
    user_manager.revoke_token(token)
        
    return jsonify(result), 200


@app.route('/resend_verification_email', methods=['POST'])
@redirect_if_logged_in
def resend_verification_email():
    data = get_request_data()
    identifier = data.get('identifier')

    if not identifier:
        return bad_request('Email or Username is required.')

    # Call the method in UserManager to handle the logic
    user_manager.resend_verification_email(identifier)

    # Always return a generic response
    return jsonify({'status': 'success', 'message': 'If the user exists, a verification email has been sent.'}), 200


@app.route('/forgot_password', methods=['POST'])
@redirect_if_logged_in
def forgot_password():
    data = get_request_data()
    identifier = data.get('identifier')

    if not identifier:
        return bad_request('Email or Username is required.')

    user_manager.request_password_reset(identifier=identifier)
    return jsonify({'message': 'Password reset link sent if the provided information is correct.'}), 200


@app.route('/forgot_password', methods=['POST'])
@redirect_if_logged_in
def forgot_password_by_email():
    data = get_request_data()
    email = data.get('email')

    if not email:
        return bad_request('Email is required.')

    user_manager.request_password_reset(email)
    return jsonify({'message': 'Password reset link sent to your email.'}), 200

@app.route('/reset_password', methods=['GET', 'POST'])
@redirect_if_logged_in
def reset_password():
    if request.method == 'GET':
        return handle_reset_password_get_verify_token()
    elif request.method == 'POST':
        return handle_reset_password_post()

def handle_reset_password_get_verify_token():
    token = request.args.get('token')
    if not token:
        return bad_request('Reset token is required.')


    # Validate the token immediately
    response = user_manager.reset_tokens_table.get_item(Key={'token': token})
    token_data = response.get('Item')

    if not token_data:
        return bad_request('Invalid reset token.')
    if int(time.time()) > token_data['expires_at']:
        return bad_request('Reset token has expired.')

    # If token is valid, show the form without displaying the email
    html_form = '''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Reset Password</title>
        </head>
        <body>
            <h2>Reset Your Password</h2>
            <form action="/reset_password" method="post">
                <input type="hidden" name="token" value="{0}">
                <label for="new_password">New Password:</label><br>
                <input type="password" id="new_password" name="new_password" required><br><br>
                <button type="submit">Reset Password</button>
            </form>
        </body>
        </html>
    '''.format(token)

    return render_template_string(html_form)


def handle_reset_password_get_no_token_verification():
    token = request.args.get('token')
    if not token:
        return bad_request('Reset token is required.')

    # Simple HTML form to collect the new password
    html_form = '''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Reset Password</title>
        </head>
        <body>
            <h2>Reset Your Password</h2>
            <form action="/reset_password" method="post">
                <input type="hidden" name="token" value="{0}">
                <label for="new_password">New Password:</label><br>
                <input type="password" id="new_password" name="new_password" required><br><br>
                <button type="submit">Reset Password</button>
            </form>
        </body>
        </html>
    '''.format(token)

    return render_template_string(html_form)


def handle_reset_password_post():
    data = get_request_data()
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return bad_request('Reset token and new password are required.')

    success = user_manager.reset_password(token, new_password)
    if success:
        return jsonify({'message': 'Password has been reset successfully.'}), 200
    else:
        return bad_request('Invalid or expired reset token.')


@app.route('/register', methods=['POST'])
@redirect_if_logged_in
def register_user():
    data = get_request_data()

    # Call register_user from UserManager with the data from the request
    user_manager.register_user(
        username=data['username'],
        email=data['email'],
        password=data['password'],
        confirm_password=data['confirm_password']
    )
    return jsonify({
        'message': ('User registered successfully! Please verify your email '
                    'before you can log in. An email has been sent with a '
                    'link that you need to click on to complete the '
                    'verification. Thank you!')
}), 201


@app.route('/get_user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    email = request.args.get('email')

    if not username and not email:
        return bad_request('You must provide either a username or an email to look up a user.')

    if username:
        user = user_manager.get_user_details_by_username(username)
    else:
        user = user_manager.get_user_details_by_email(email)

    if user:
        return jsonify(user), 200
    else:
        return jsonify({'message': 'User not found'}), 404


# superuser
# Flask endpoint to list contents of a specific DynamoDB table
@app.route('/list_table/<string:table_name>', methods=['GET'])
@superuser_required
def list_table_contents(user, table_name):
    # Access the DynamoDB table
    table = dynamodb_resource.Table(table_name)

    # Scan the table to get all items
    response = table.scan()
    items = utils.convert_sets_to_lists(response.get('Items', []))

    return jsonify({'status': 'success', 'data': items}), 200


# superuser
# Flask endpoint to check token expiration time
@app.route('/token_remaining_time', methods=['POST'])
@superuser_required
def token_remaining_time(user):
    data = get_request_data()
    token = data.get("token_to_check")

    if not token:
        return jsonify({"error": "Token is required"}), 400

    remaining_time_info = utils.get_remaining_time_for_token(token, JWT_SECRET)
    return jsonify(remaining_time_info), 200


# superuser
# Flask endpoint to list all DynamoDB tables
@app.route('/list_all_tables', methods=['GET'])
@superuser_required
def list_dynamodb_tables(user):
    # List all tables in DynamoDB
    response = dynamodb_client.list_tables()
    table_names = response.get('TableNames', [])

    return jsonify({'status': 'success', 'tables': table_names}), 200


# superuser
@app.route('/describe_table/<string:table_name>', methods=['GET'])
@superuser_required
def describe_table(user, table_name):
    # Use the DynamoDB client to describe the table
    table_description = dynamodb_client.describe_table(TableName=table_name)

    return jsonify({
        'status': 'success',
        'table_description': table_description
    }), 200

# superuser
@app.route('/list_s3_contents', methods=['GET'])
@superuser_required
def list_s3_contents(user):
    # Retrieve the bucket name from environment variables
    bucket_name = os.getenv('S3_BUCKET_NAME')

    # List objects in the S3 bucket
    response = s3_client.list_objects_v2(Bucket=bucket_name)

    if 'Contents' in response:
        files = []
        for obj in response['Contents']:
            # Get additional details like ContentType (MIME type)
            head_response = s3_client.head_object(Bucket=bucket_name, Key=obj['Key'])
            files.append({
                'Key': obj['Key'],
                'LastModified': obj['LastModified'].isoformat(),
                'Size': obj['Size'],
                'ContentType': head_response['ContentType']
            })
        return jsonify({'status': 'success', 'files': files}), 200
    else:
        return jsonify({'status': 'success', 'files': []}), 200


# superuser 
@app.route('/list_all_users', methods=['GET'])
@superuser_required
def list_all_users(user):
    users = user_manager.get_all_users()
    return jsonify(users), 200


@app.route('/list_user/<string:username>', methods=['GET'])
@superuser_required
def list_user(user, username):
    listed_user = user_manager.get_user_details(username)
    return jsonify(listed_user), 200


@app.route('/whoami', methods=['GET'])
@token_required
def whoami(user):
    return jsonify(user), 200


@app.route('/login', methods=['GET', 'POST'])
@redirect_if_logged_in
def login():
    if request.method == 'GET':
        # If a GET request is made, show a login page or return a message
        return jsonify({"message": "Please log in to access this resource."}), 200
    
    if request.method == 'POST':
        data = get_request_data()
        identifier = data.get('identifier')
        password = data.get('password')

        if not identifier or not password:
            return bad_request("Username/Email and password are required.")

        token = user_manager.login_user(identifier, password)
        if token:
            session['token'] = token  # Store token in session for redirect
            next_url = session.pop('next', None)  # Get the next URL from session
            if next_url:
                return redirect(next_url)
            else:
                return jsonify({"token": token}), 200
        else:
            return bad_request("Invalid username, password, or email not verified.")


@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers['Authorization'].split(" ")[1]  # Extract the token from the Authorization header
    
    # Decode the token to get the expiration time
    decoded_token = jwt.decode(token, JWT_SECRET, algorithms=['HS256'], options={"verify_signature": False})
    expires_at = decoded_token.get('exp')

    # Add the token to the revokedtokens with its expiration time
    revokedtokens_table = dynamodb_resource.Table(f'{table_prefix}_RevokedTokens')
    revokedtokens_table.put_item(Item={
        'token': token,
        'expires_at': expires_at
    })
    
    return jsonify({"message": "Successfully logged out"}), 200


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
    return decoratee


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


@app.route('/remove_model/<string:model_name>/<string:version>', methods=['DELETE'])
@token_required
def remove_model_by_name_and_version(current_user, model_name, version):
    # Fetch the model metadata
    user_id = current_user['id']

    # Fetch the model metadata from DynamoDB
    metadata = metadata_store.get_model_metadata_by_name_and_version(user_id, model_name, version)
    if not metadata:
        return jsonify({'status': 'error', 'message': 'Model not found.'}), 404

    # Check if the current user is the owner of the model
    if metadata['user_id'] != current_user['id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized to remove this model.'}), 403

    # Get the S3 key for the model
    s3_key = user_id + '/' + metadata['filename']

    # Remove the model from S3
    storage.remove_model_by_key(s3_key)

    # Remove the model metadata from DynamoDB
    metadata_store.remove_model_metadata_by_id(user_id, metadata['id'])

    return jsonify({'status': 'success', 'message': 'Model removed successfully.'}), 200


@app.route('/remove_model/<string:model_id>', methods=['DELETE'])
@token_required
def remove_model_by_id(current_user, model_id):
    # Fetch the model metadata
    user_id = current_user['id']
    metadata = metadata_store.get_model_metadata_by_model_id(user_id, model_id)

    if not metadata:
        return jsonify({'status': 'error', 'message': 'Model not found.'}), 404

    # Check if the current user is the owner of the model
    if metadata['user_id'] != current_user['id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized to remove this model.'}), 403

    # Remove the model from S3
    s3_key = f"{metadata['user_id']}/{metadata['filename']}"
    storage.remove_model_by_key(s3_key)

    # Remove the model metadata from DynamoDB
    metadata_store.remove_model_metadata_by_id(user_id, model_id)

    return jsonify({'status': 'success', 'message': 'Model removed successfully.'}), 200


@app.route('/upload_model', methods=['POST'])
@token_required
def upload_model(current_user):
    # Check if request is JSON or form
    data = get_request_data()

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
        return bad_request('Version is required')

    if not model_file:
        return bad_request("Model file is required")

    # Check the file size to make sure it is within allowed limit
    if len(model_file.read()) > MAX_MODEL_FILE_SIZE:
        return jsonify({'message': f'Model file exceeds the maximum allowed size of {MAX_MODEL_FILE_SIZE_MB} MB'}), 400
    
    model_file.seek(0)  # Reset the file pointer after reading the file size

    # Validate the model before saving
    if not validate_model(model_file):
        return bad_request('Invalid model file')

    # Secure the file name and save it
    file_extension = model_file.filename.rsplit('.', 1)[-1].lower()
    filename = secure_filename(f"{model_name}_{version}.{file_extension}")

    user_id = current_user['id']  # Get the user ID from the authenticated user

    # Save model to S3 and metadata to DynamoDB using the MlModelStorage class
    success, error = storage.save(
        filename,
        model_file,
        version,
        model_name,
        file_extension,
        current_user['username'],
        user_id,
        description=description,
        accuracy=accuracy,
    )

    if not success:
        return bad_request(f'Error: {error}. Unable to save model version {version} for {model_name}')

    return jsonify({
        'message': 'Model uploaded successfully',
        'model_name': model_name,
        'version': version,
    }), 201


@app.route('/download_model/<model_id>', methods=['GET'])
@token_required
def download_model_by_id(current_user, model_id):
    # Get the user's ID from the JWT
    user_id = current_user['id']
    
    # Fetch the model metadata from DynamoDB
    model_metadata = metadata_store.get_model_metadata_by_model_id(user_id, model_id)
    if not model_metadata:
        return jsonify({'status': 'error', 'message': 'Model not found'}), 404
    
    # Get the S3 key for the model
    s3_key = user_id + '/' + model_metadata['filename']
    
    # Fetch the model file from S3
    bucket_name = os.getenv('S3_BUCKET_NAME')
    s3_object = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    
    # Prepare the file for download
    file_stream = io.BytesIO(s3_object['Body'].read())
    file_stream.seek(0)
    
    # Send the file to the user
    return send_file(file_stream, as_attachment=True, download_name=s3_key, mimetype='application/octet-stream')


@app.route('/download_model/<model_name>/<version>', methods=['GET'])
@token_required
def download_model_by_name_and_version(current_user, model_name, version):
    # Get the user's ID from the JWT
    user_id = current_user['id']
    
    # Fetch the model metadata from DynamoDB
    model_metadata = metadata_store.get_model_metadata_by_name_and_version(user_id, model_name, version)
    if not model_metadata:
        return jsonify({'status': 'error', 'message': 'Model not found'}), 404

    # Check if the current user is the owner of the model
    if model_metadata['user_id'] != current_user['id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized to remove this model.'}), 403
    
    # Get the S3 key for the model
    s3_key = user_id + '/' + model_metadata['filename']
    
    # Fetch the model file from S3
    bucket_name = os.getenv('S3_BUCKET_NAME')
    s3_object = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    
    # Prepare the file for download
    file_stream = io.BytesIO(s3_object['Body'].read())
    file_stream.seek(0)
    
    # Send the file to the user
    return send_file(file_stream, as_attachment=True, download_name=s3_key, mimetype='application/octet-stream')


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
@token_required
def predict(current_user, model_name, version):
    start_time = time.time()
    data = get_request_data()

    if not model_name or not version:
        return bad_request("Model name and version are required")

    # Get the user's ID from the JWT
    user_id = current_user['id']

    # Fetch the model metadata from DynamoDB
    model_metadata = metadata_store.get_model_metadata_by_name_and_version(user_id, model_name, version)
    if not model_metadata:
        return jsonify({'status': 'error', 'message': 'Model not found'}), 404

    # Check if the current user is the owner of the model
    if model_metadata['user_id'] != current_user['id']:
        return jsonify({'status': 'error', 'message': 'Unauthorized to access this model.'}), 403
    
    # Get the S3 key for the model
    s3_key = f"{user_id}/{model_metadata['filename']}"
    
    # Fetch the model file from S3
    bucket_name = os.getenv('S3_BUCKET_NAME')
    s3_object = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    
    # Prepare the model file for loading
    model_file_stream = io.BytesIO(s3_object['Body'].read())
    model_file_stream.seek(0)

    # Load the model using joblib
    model = joblib.load(model_file_stream)

    # Extract features from the input data
    features = data.get('features') or data.get('data')
    if not features:
        return bad_request('No features or data provided')

    expected_output = data.get('expected_output', None)
    result = evaluate_prediction(model, features, expected_output)

    # Log usage if enabled
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
@token_required
def list_models(current_user):
    # Get the user's ID from the JWT
    user_id = current_user['id']
    
    # Query the DynamoDB table for models belonging to this user
    response = metadata_store.list_models_for_user(user_id)

    # Return the list of models
    return jsonify({'status': 'success', 'models': response.get('Items', [])}), 200


@app.route('/download_model/<string:model_name>/<string:version>', methods=['GET'])
@token_required
def download_model(current_user, model_name, version):
    user_id = current_user['id']  # Get the user ID from the authenticated user

    model_file = storage.retrieve_model(user_id, model_name, version)
    if model_file:
        return send_file(model_file, as_attachment=True)
    else:
        return not_found(f'Model {model_name} version {version} not found')


@app.route('/verify_email', methods=['GET'])
def verify_email():
    code = request.args.get('code')
    if not code:
        return bad_request('Missing verification code')
    
    # Call the UserManager's verify_email method
    result = user_manager.verify_email(code)

    if result:
        return jsonify({'message': 'Email verified successfully'}), 200
    else:
        return bad_request('Verification failed or code expired')


# Metrics and log collection


@app.before_request
def log_request_info():
    if request.endpoint == 'predict':
        data = get_request_data()
        app.logger.info(f"Predict endpoint called with data: {data}")


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


# Error handlers for the Flask application
import traceback

@app.errorhandler(ValueError)
def handle_value_error(error):
    if LOG_VALUEERROR:
        logger.error("Validation error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": str(error)}), 400

@app.errorhandler(LookupError)
def handle_lookup_error(error):
    logger.error("Lookup error: %s", str(error))
    return jsonify({"error": str(error)}), 404

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    logger.error("Unexpected error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500

@app.errorhandler(jwt.ExpiredSignatureError)
def handle_expired_signature_error(error):
    logger.error("Token expired with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "Your session has expired. Please log in again."}), 401

@app.errorhandler(jwt.InvalidTokenError)
def handle_invalid_token_error(error):
    logger.error("Invalid token with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "Authentication failed. Please log in again."}), 401

@app.errorhandler(AttributeError)
def handle_attribute_error(error):
    logger.error("Attribute error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "An internal error occurred. Please try again later."}), 500

@app.errorhandler(KeyError)
def handle_key_error(error):
    logger.error("Key error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "A required key is missing. Please check your input and try again."}), 400

@app.errorhandler(TypeError)
def handle_type_error(error):
    logger.error("Type error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "An internal error occurred. Please try again later."}), 500

@app.errorhandler(IOError)
def handle_io_error(error):
    logger.error("IO error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "An error occurred while accessing a resource. Please try again later."}), 500

@app.errorhandler(PermissionError)
def handle_permission_error(error):
    logger.error(f"Permission denied: {str(error)}")
    return jsonify({'error': str(error)}), 403

class MyCustomException(Exception):
    pass

# Example of handling a custom exception
@app.errorhandler(MyCustomException)
def handle_custom_exception(error):
    logger.error("Custom error with stack trace: %s", traceback.format_exc())
    return jsonify({"error": "A custom error occurred. Please contact support."}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
