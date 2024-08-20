import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

# Initialize the DynamoDB resource for local setup
dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000',  # Point to local DynamoDB
)

def verify_aws_credentials():
    """Verify if AWS credentials are correctly configured for local DynamoDB."""
    try:
        dynamodb_client = boto3.client('dynamodb', endpoint_url='http://localhost:8000')
        response = dynamodb_client.list_tables()
        print("Successfully connected to AWS.")
        print("DynamoDB Tables:", response['TableNames'])
    except NoCredentialsError:
        print("Error: No credentials found.")
    except PartialCredentialsError:
        print("Error: Incomplete credentials.")
    except ClientError as e:
        print(f"ClientError: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def create_groups_table():
    """Create the Groups table if it doesn't exist."""
    try:
        if not table_exists('Groups'):
            dynamodb.create_table(
                TableName='Groups',
                KeySchema=[
                    {'AttributeName': 'id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print("Groups table created.")
        else:
            print("Groups table already exists.")
    except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error creating Groups table: {e}")

def create_permissions_table():
    """Create the Permissions table if it doesn't exist."""
    try:
        if not table_exists('Permissions'):
            dynamodb.create_table(
                TableName='Permissions',
                KeySchema=[
                    {'AttributeName': 'user_id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'user_id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print("Permissions table created.")
        else:
            print("Permissions table already exists.")
    except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error creating Permissions table: {e}")

def create_users_table():
    """Create the Users table if it doesn't exist."""
    try:
        if not table_exists('Users'):
            dynamodb.create_table(
                TableName='Users',
                KeySchema=[
                    {'AttributeName': 'id', 'KeyType': 'HASH'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'id', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            )
            print("Users table created.")
        else:
            print("Users table already exists.")
    except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error creating Users table: {e}")

def create_user_group_membership_table():
    """Create the UserGroupMembership table."""
    table = dynamodb.create_table(
        TableName='UserGroupMembership',
        KeySchema=[
            {'AttributeName': 'user_id', 'KeyType': 'HASH'},  # Partition key
            {'AttributeName': 'group_id', 'KeyType': 'RANGE'}  # Sort key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'user_id', 'AttributeType': 'S'},
            {'AttributeName': 'group_id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    table.wait_until_exists()
    print("UserGroupMembership table created successfully.")

def table_exists(table_name):
    """Check if a DynamoDB table exists."""
    try:
        table = dynamodb.Table(table_name)
        table.load()  # Attempt to load table metadata
        return True
    except ClientError:
        return False

if __name__ == "__main__":
    verify_aws_credentials()
    if not table_exists('Users'):
        create_users_table()
    if not table_exists('Groups'):
        create_groups_table()
    if not table_exists('Permissions'):
        create_permissions_table()
    if not table_exists('UserGroupMembership'):
        create_user_group_membership_table()
