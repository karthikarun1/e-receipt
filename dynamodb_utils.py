import boto3
import os
import traceback
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError
from boto3.dynamodb.conditions import Key


# Load environment variables
from config_loader import load_environment
load_environment()


def get_dynamodb_resource(region_name='us-west-2'):
    # Initialize the DynamoDB resource
    if os.getenv('DATABASE_LOCATION') == 'local':
        return boto3.resource(
            'dynamodb',
            endpoint_url='http://localhost:8000',  # Point to local DynamoDB
        )
    else:
        return boto3.resource('dynamodb', region_name=region_name)

def get_dynamodb_client(region_name='us-west-2'):
    # Initialize the DynamoDB resource
    if os.getenv('DATABASE_LOCATION') == 'local':
        return boto3.client(
            'dynamodb',
            endpoint_url='http://localhost:8000',  # Point to local DynamoDB
        )
    else:
         return boto3.client('dynamodb', region_name=region_name)



def drop_tables_with_prefix(dynamodb_resource, table_prefix):
    table_names = [
        f'{table_prefix}_Subscriptions',
        f'{table_prefix}_Organizations',
        f'{table_prefix}_Groups',
        f'{table_prefix}_Users',
        f'{table_prefix}_UserGroupMembership',
        f'{table_prefix}_EmailVerification',
        f'{table_prefix}_ResetTokens',
        f'{table_prefix}_Permissions',
        f'{table_prefix}_Invites',
        f'{table_prefix}_RevokedTokens',
        f'{table_prefix}_MlModelMetadata',
    ]
    for table_name in table_names:
        try:
            table = dynamodb_resource.Table(table_name)  # Use dynamodb resource, not client
            table.load()  # This will check if the table exists
            table.delete()
            table.wait_until_not_exists()
            print(f"Deleted table {table_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"Table {table_name} does not exist, skipping deletion.")
            else:
                print(f"Error deleting table {table_name}: {e}")
        except Exception as e:
            print(f"Error deleting table {table_name}: {e}")

def create_mlmodel_metadata_table(dynamodb_resource, prefix):
    table_name = f"{prefix}_MlModelMetadata"
    try:
        table = dynamodb_resource.create_table(
            TableName=table_name,
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'},  # Partition key
                {'AttributeName': 'id', 'KeyType': 'RANGE'}  # Sort key
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        table.wait_until_exists()
        print(f"Table {table_name} created successfully.")
    except dynamodb_resource.meta.client.exceptions.ResourceInUseException:
        print(f"Table {table_name} already exists.")
    except Exception as e:
        print(f"Error creating table {table_name}: {str(e)}")


def create_revokedtokens_table(dynamodb_resource, prefix):
    # If you want to implement a more secure logout by revoking the token, you can use a denylist approach:
    # Create a RevokedTokens Table in DynamoDB: 
    revokedtokens_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_RevokedTokens",
        KeySchema=[
            {'AttributeName': 'token', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'token', 'AttributeType': 'S'},
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )


def create_users_table(dynamodb_resource, prefix):
    # Create Users table
    users_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Users",
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'},
            {'AttributeName': 'email', 'AttributeType': 'S'},
            {'AttributeName': 'username', 'AttributeType': 'S'}  # Define the username attribute
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'email-index',
                'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            },
            {
                'IndexName': 'username-index',
                'KeySchema': [{'AttributeName': 'username', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    users_table.wait_until_exists()
    print("Users table created successfully.")
    print(f"Table {prefix}_Users created successfully.")


def create_subscriptions_table(dynamodb_resource, prefix):
    subscriptions_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Subscriptions",
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    subscriptions_table.wait_until_exists()
    print(f"Table {prefix}_Subscriptions created successfully.")


def create_permissions_table(dynamodb_resource, prefix):
    permissions_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Permissions",
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    permissions_table.wait_until_exists()
    print(f"Table {prefix}_Permissions created successfully.")


def create_organization_table(dynamodb_resource, prefix):
    organizations_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Organizations",
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    organizations_table.wait_until_exists()
    print(f"Table {prefix}_Organizations created successfully.")


def create_groups_table(dynamodb_resource, prefix):
    groups_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Groups",
        KeySchema=[
            {'AttributeName': 'id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    groups_table.wait_until_exists()
    print(f"Table {prefix}_Groups created successfully.")


def create_groups_membership_table(dynamodb_resource, prefix):
    user_group_membership_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_UserGroupMembership",
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
    user_group_membership_table.wait_until_exists()


def create_email_verification_table(dynamodb_resource, prefix):
    email_verification_table = dynamodb_resource.create_table(
        TableName=f'{prefix}_EmailVerification',
        KeySchema=[
            {'AttributeName': 'verification_code', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'verification_code', 'AttributeType': 'S'},
            {'AttributeName': 'email', 'AttributeType': 'S'}  # Attribute for GSI
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'email-index',  # Name of the GSI
                'KeySchema': [{'AttributeName': 'email', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},  # Project all attributes
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    email_verification_table.wait_until_exists()
    print(f"Table {prefix}_EmailVerification created successfully with GSI on email.")


def create_reset_tokens_table(dynamodb_resource, prefix):
    reset_tokens_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_ResetTokens",
        KeySchema=[
            {'AttributeName': 'token', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'token', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    reset_tokens_table.wait_until_exists()
    print(f"Table {prefix}_ResetTokens created successfully.")


def create_invites_table(dynamodb_resource, prefix):
    invites_table = dynamodb_resource.create_table(
        TableName=f"{prefix}_Invites",
        KeySchema=[
            {'AttributeName': 'invite_id', 'KeyType': 'HASH'}  # Partition key
        ],
        AttributeDefinitions=[
            {'AttributeName': 'invite_id', 'AttributeType': 'S'}
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5
        }
    )
    invites_table.wait_until_exists()
    print(f"Table {prefix}_Invites created successfully.")


def create_all_tables(dynamodb_resource, prefix):
    try:
        create_mlmodel_metadata_table(dynamodb_resource, prefix)
        create_revokedtokens_table(dynamodb_resource, prefix)
        create_users_table(dynamodb_resource, prefix)
        create_subscriptions_table(dynamodb_resource, prefix)
        create_permissions_table(dynamodb_resource, prefix)
        create_organization_table(dynamodb_resource, prefix)
        create_groups_table(dynamodb_resource, prefix)
        create_groups_membership_table(dynamodb_resource, prefix)
        create_email_verification_table(dynamodb_resource, prefix)
        create_reset_tokens_table(dynamodb_resource, prefix)
        create_invites_table(dynamodb_resource, prefix)
    except Exception as e:
        print(f"Error creating tables: {str(e)}")
        traceback.print_exc()  # This prints the full stack trace


def drop_all_tables(dynamodb_client):
    try:
        # List all tables
        response = dynamodb_client.list_tables()
        table_names = response.get('TableNames', [])
        
        if not table_names:
            print("No tables found in DynamoDB.")
            return
        
        for table_name in table_names:
            # Drop each table
            print(f"Dropping table: {table_name}")
            dynamodb_client.delete_table(TableName=table_name)
            # Wait for table deletion to complete
            dynamodb_client.get_waiter('table_not_exists').wait(TableName=table_name)
            print(f"Table {table_name} dropped successfully.")
        
        print("All tables wiped out successfully.")
    except Exception as e:
        print(f"Error wiping out tables: {str(e)}")


def verify_aws_credentials():
    """Verify if AWS credentials are correctly configured."""
    try:
        dynamodb_client = boto3.client('dynamodb')
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

# Example usage
if __name__ == "__main__":
    # Initialize DynamoDB resource and client
    table_prefix = 'Dev'
    dynamodb_resource = boto3.resource('dynamodb', endpoint_url='http://localhost:8000', region_name='us-east-1')
    dynamodb_client = boto3.client('dynamodb', endpoint_url='http://localhost:8000', region_name='us-east-1')

    are_you_sure = input('Are you sure you want to drop and recreate all tables? (y/n):')
    if are_you_sure.lower() in ('y', 'yes'):
        drop_all_tables(dynamodb_client)
        create_all_tables(dynamodb_resource, table_prefix)
