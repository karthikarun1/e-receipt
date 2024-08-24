import boto3

# Local S3
s3 = boto3.client(
    's3',
    endpoint_url='http://localhost:4566'
)

# Example of creating a bucket in local S3
def create_bucket():
    s3.create_bucket(Bucket='my-bucket')
