import boto3
import os

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from dotenv import load_dotenv
# Load environment variables from .env file
load_dotenv()


def get_client():      
    storage_type = os.getenv('STORAGE_TYPE')
    if storage_type == 'local_s3':
        return boto3.client('s3', endpoint_url='http://localhost:4566')
    else:
        return boto3.client('s3')


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
    s3_client = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1')
    
    bucket_name = 'my-bucket'
    print(f"\nObjects in bucket '{bucket_name}':")
    print(list_s3_objects(bucket_name, s3_client))

    print("\nS3 Buckets:")
    print(list_s3_buckets(s3_client))

    object_key = 'admin_user_id/sample_v0.pkl'
    print(f"\nMetadata for object '{object_key}':")
    print(get_s3_object_metadata(bucket_name, object_key, s3_client))
