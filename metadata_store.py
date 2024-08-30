# metadata_store.py

import boto3
import dynamodb_utils
import json
import os
import traceback

from boto3.dynamodb.conditions import Key  # Add this import statement

# Load environment variables
from config_loader import load_environment
load_environment()


database_location = os.getenv('DATABASE_LOCATION').lower()
database_type = os.getenv('DATABASE_TYPE').lower()
local_dir = os.getenv('LOCAL_DIR').lower()


class MetadataStore:

    def __init__(self, dynamodb_resource=None, table_name=None):
        self.table_name = table_name
        self.dynamodb_resource = (
            dynamodb_resource or dynamodb_utils.get_dynamodb_resource())
        table_name = table_name or os.getenv('METADATA_TABLE')
        self.table = self.dynamodb_resource.Table(table_name)
        

    def save_metadata(self, metadata):
        print (f'----------table is {self.table}')
        print (f'----------data is  {metadata}')
        self.table.put_item(Item=metadata)
        return True

    def get_model_metadata_by_model_id(self, user_id, model_id):
        try:
            table = self.dynamodb_resource.Table(self.table_name)
            response = table.get_item(
                Key={
                    'user_id': user_id,
                    'id': model_id
                }
            )
            return response.get('Item')
        except Exception as e:
            print(f"Error fetching model metadata for user {user_id}, model {model_id}: {e}")
            traceback.print_exc()
            raise

    def get_model_metadata_by_name_and_version(self, user_id, model_name, version):
        try:
            # Construct the composite key
            model_id = f"{model_name}-{version}-{user_id}"
        
            # Query the table using the composite key
            table = self.dynamodb_resource.Table('Dev_MlModelMetadata')  # Use your actual table name
            response = table.get_item(
                Key={
                    'user_id': user_id,  # Partition Key
                    'id': model_id       # Sort Key (composite key)
                }
            )
            return response.get('Item')
        except Exception as e:
            print(f"Error fetching model metadata for user {user_id}, model {model_name}, version {version}: {e}")
            traceback.print_exc()
            raise

    def get_model_metadata_old(self, model_id, user_id):
        """
        Get model metadata and check if the user has access to it.
        
        :param model_id: The ID of the model to retrieve.
        :param user_id: The ID of the user requesting access.
        :return: Metadata of the model if the user has access.
        """
        response = self.table.get_item(Key={'Id': model_id})
        item = response.get('Item', {})
        
        # Check if user has access
        if item.get('user_id') == user_id or item.get('group_id') in self.get_user_groups(user_id):
            return item
        else:
            raise PermissionError("User does not have access to this model.")
    
    def get_user_groups(self, user_id):
        """
        Get the list of groups a user belongs to.
        
        :param user_id: The ID of the user.
        :return: List of group IDs the user belongs to.
        """
        try:
            response = self.group_table.get_item(Key={'user_id': user_id})
            return response.get('Item', {}).get('group_ids', [])
        except Exception as e:
            print(f"Error retrieving user groups: {e}")
            return []


    def list_models_for_user(self, user_id):
        #try:
        print (f'------------user_id {user_id}')
        print (f'------------table name is {self.table_name}')
        table = self.dynamodb_resource.Table(self.table_name)
        response = table.query(
            KeyConditionExpression=Key('user_id').eq(user_id)
        )

        #Ensure that response['Items'] is handled correctly
        if 'Items' in response and isinstance(response['Items'], list):
            return response
        else:
            return {'Items': []}  # Return an empty list if no items found or if response is not as expected
        #except Exception as e:
        #    print(f"Error listing models for user {user_id}: {e}")
        #    traceback.print_exc()
        #    raise

    def remove_model_metadata_by_id(self, user_id, model_id):
        """
        Remove model metadata from the DynamoDB table by model_id.

        :param user_id: The ID of the user who owns the model.
        :param model_id: The ID of the model to be removed.
        """
        try:
            table = self.dynamodb_resource.Table(self.table_name)
            table.delete_item(
                Key={
                    'user_id': user_id,
                    'id': model_id
                }
            )
            print(f"Model metadata with ID '{model_id}' successfully removed from DynamoDB.")
        except Exception as e:
            print(f"Error removing model metadata from DynamoDB: {e}")
            traceback.print_exc()
            raise


# Example usage
if __name__ == "__main__":
    store = MetadataStore()
    
    # Example metadata including user_id and group_id
    metadata = {
        'Id': 'example_model~v1.0~timestamp',
        'user_id': 'user123',
        'group_id': 'group456',
        'model_name': 'example_model',
        'version': 'v1.0',
        'timestamp': '2024-08-19T00:00:00Z',
        'metadata': 'additional_metadata'
    }
    store.save_metadata(metadata)
    
    # Retrieve metadata
    model_id = 'example_model~v1.0~timestamp'
    user_id = 'user123'
    try:
        print(store.get_model_metadata(model_id, user_id))
    except PermissionError as e:
        print(e)
