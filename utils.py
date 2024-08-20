import boto3
from boto3.dynamodb.conditions import Key

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
