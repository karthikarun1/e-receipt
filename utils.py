import bleach
import boto3
import jwt
import html
import inspect
import logging
import os
import re
import time
import traceback

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Load environment variables
from config_loader import load_environment
load_environment()

table_prefix = os.getenv('TABLE_PREFIX')

def list_dynamodb_items(table_name, dynamodb_resource):
    """
    List all items in a DynamoDB table.

    :param table_name: The name of the DynamoDB table.
    :param dynamodb_resource: An initialized boto3 DynamoDB resource.
    :return: A list of items in the table.
    """
    table = dynamodb_resource.Table(table_name)
    try:
        response = table.scan()
        items = response['Items']
        return items
    except Exception as e:
        print(f"Error listing items: {e}")
        return []

def list_dynamodb_tables(dynamodb_client):
    """
    List all tables in a DynamoDB instance.

    :param dynamodb_client: An initialized boto3 DynamoDB client.
    :return: A list of table names.
    """
    try:
        response = dynamodb_client.list_tables()
        return response.get('TableNames', [])
    except Exception as e:
        print(f"Error listing tables: {e}")
        return []

def list_s3_objects(bucket_name, s3_client):
    """
    List all objects in an S3 bucket.

    :param bucket_name: The name of the S3 bucket.
    :param s3_client: An initialized boto3 S3 client.
    :return: A list of object keys in the bucket.
    """
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            return [obj['Key'] for obj in response['Contents']]
        else:
            return []
    except Exception as e:
        print(f"Error listing objects: {e}")
        return []

def list_s3_buckets(s3_client):
    """
    List all S3 buckets.

    :param s3_client: An initialized boto3 S3 client.
    :return: A list of bucket names.
    """
    try:
        response = s3_client.list_buckets()
        return [bucket['Name'] for bucket in response.get('Buckets', [])]
    except Exception as e:
        print(f"Error listing buckets: {e}")
        return []

def get_s3_object_metadata(bucket_name, object_key, s3_client):
    """
    Get metadata for an S3 object.

    :param bucket_name: The name of the S3 bucket.
    :param object_key: The key (path) of the S3 object.
    :param s3_client: An initialized boto3 S3 client.
    :return: Metadata of the S3 object.
    """
    try:
        response = s3_client.head_object(Bucket=bucket_name, Key=object_key)
        return {
            'ContentType': response.get('ContentType', 'Unknown'),
            'ContentLength': response.get('ContentLength', 'Unknown'),
            'LastModified': response.get('LastModified', 'Unknown'),
            'ETag': response.get('ETag', 'Unknown'),
            'Metadata': response.get('Metadata', {})
        }
    except s3_client.exceptions.ClientError as e:
        print(f"Error retrieving object metadata: {e}")
        return {}

# Example usage
if __name__ == "__main__":
    # Initialize DynamoDB resource and client
    dynamodb_resource = boto3.resource('dynamodb', endpoint_url='http://localhost:8000', region_name='us-east-1')
    dynamodb_client = boto3.client('dynamodb', endpoint_url='http://localhost:8000', region_name='us-east-1')
    s3_client = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1')
    
    # Example usage of utility functions
    print("DynamoDB Tables:")
    print(list_dynamodb_tables(dynamodb_client))

    table_name = 'MyTable'
    print(f"\nItems in table '{table_name}':")
    print(list_dynamodb_items(table_name, dynamodb_resource))

    bucket_name = 'my-bucket'
    print(f"\nObjects in bucket '{bucket_name}':")
    print(list_s3_objects(bucket_name, s3_client))

    print("\nS3 Buckets:")
    print(list_s3_buckets(s3_client))

    object_key = 'admin_user_id/sample_v0.pkl'
    print(f"\nMetadata for object '{object_key}':")
    print(get_s3_object_metadata(bucket_name, object_key, s3_client))


def clear_dynamodb_table(dynamodb, table_name):
    """Clear all items from a DynamoDB table."""
    table = dynamodb.Table(table_name)
    
    try:
        # Get the key schema to construct keys for deletion
        key_schema = table.key_schema
        key_names = [key['AttributeName'] for key in key_schema]
        
        # Scan the table to get all items
        response = table.scan()
        items = response.get('Items', [])

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response.get('Items', []))

        # Delete each item
        for item in items:
            key = {name: item[name] for name in key_names if name in item}
            table.delete_item(Key=key)

        print(f"Cleared all items from table: {table_name}")

    except ClientError as e:
        print(f"Error clearing table {table_name}: {e}")


def handle_exception(e, message=None):
    """Utility function to handle exceptions with optional traceback."""
    if message:
        print(f"{message}: {e}")
    else:
        print(f"Error: {e}")

    # Check environment variable to determine if traceback should be printed
    if os.getenv('PRINT_TRACEBACK', 'false').lower() == 'true':
        traceback.print_exc()

    # Log the stack trace based on environment settings
    if os.getenv('LOG_STACKTRACE', 'false').lower() == 'true':
        logger.error(traceback.format_exc())


def cleanup_revokedtokens():
    """Cleansup expired tokens that are stored in RevokedTokens table 
       (after the client is logged out) for immediate login denial if 
       the token is used again for login attempts after client logout.
       This would have to be run periodically (using a cronjob or some
       other mechanism). Also this table would be used to store other
       tokens other than login purposes too.
    """
    revokedtokens_table = dynamodb.Table(f'{table_prefix}_RevokedTokens')
    current_time = int(time.time())
    scan = revokedtokens_table.scan()
    for item in scan['Items']:
        if item['expires_at'] < current_time:
            denylist_table.delete_item(Key={'token': item['token']})
    print("RevokedTokens cleanup complete.")


# superuser
def get_remaining_time_for_token(token, secret_key):
    print (f'------utils grtt: token {token}')
    print (f'------utils grtt: secret_key {secret_key}')
    try:
        # Decode the JWT token to extract its payload
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])

        # Get the current time and the expiration time
        current_time = int(time.time())
        expiration_time = payload.get('exp')

        # Calculate the remaining time in seconds
        remaining_time = expiration_time - current_time

        if remaining_time > 0:
            remaining_minutes = remaining_time // 60
            remaining_hours = remaining_minutes // 60
            return {
                "remaining_seconds": remaining_time,
                "remaining_minutes": remaining_minutes,
                "remaining_hours": remaining_hours
            }
        else:
            return {"error": "Token has already expired"}

    except jwt.ExpiredSignatureError:
        return {"error": "Token has already expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

# decorator function to print all arguments of a python function
def print_function_arguments(func):
    def wrapper(*args, **kwargs):
        # Get the function signature
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        
        # Print all arguments with their names and values
        print(f"Arguments for function {func.__name__}:")
        for name, value in bound_args.arguments.items():
            print(f"{name}: {value}")
        
        # Call the actual function
        return func(*args, **kwargs)
    return wrapper


def is_valid_email(email):
    # Regular expression for validating an email
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None



def sanitize_input(data):
    """
    Sanitizes input data to prevent security vulnerabilities.
    """
    if isinstance(data, dict):
        sanitized_data = {}
        for key, value in data.items():
            sanitized_key = sanitize_input(key)
            sanitized_value = sanitize_input(value)
            sanitized_data[sanitized_key] = sanitized_value
        return sanitized_data
    elif isinstance(data, list):
        return [sanitize_input(item) for item in data]
    elif isinstance(data, str):
        # Strip leading/trailing whitespace
        sanitized_data = data.strip()
        # Remove null bytes
        sanitized_data = sanitized_data.replace('\x00', '')
        # Escape HTML characters
        sanitized_data = html.escape(sanitized_data)
        # Escape SQL characters (basic)
        sanitized_data = re.sub(r"[\'\"\\;]", "", sanitized_data)
        # Remove dangerous special characters (you can customize this based on your needs)
        # Currently allows the following:
        # Alphanumeric characters: a-zA-Z0-9
        # Underscores: _
        # Hyphens: -
        # Spaces: \s
        # At symbol: @
        # Periods: .
        sanitized_data = re.sub(r"[^a-zA-Z0-9_\-\s@.]", "", sanitized_data)
        # Optional: Use bleach to allow only certain HTML tags if necessary
        # sanitized_data = bleach.clean(sanitized_data, tags=[], attributes={}, strip=True)
        return sanitized_data
    else:
        return data
