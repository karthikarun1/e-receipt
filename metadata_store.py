# metadata_store.py

import boto3
import json
import os

from dotenv import load_dotenv
load_dotenv()

database_location = os.getenv('DATABASE_LOCATION').lower()
database_type = os.getenv('DATABASE_TYPE').lower()
local_dir = os.getenv('LOCAL_DIR').lower()


def save_metadata_to_file(metadata):
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
    # Define metadata file path
    model_name = metadata['model_name']
    version = metadata['version']
    user_id = metadata['user_id']
    metadata_filename = f"{model_name}_{version}_metadata.json"  # Adjust versioning as needed
    metadata_path = os.path.join(local_dir, user_id, metadata_filename)
    
    # Save metadata to file
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=4)
    
    return metadata_path


class MetadataStore:
    def __init__(self, table_name=None, group_table_name=None):
        self.set_dynamo_db(os.getenv('DATABASE_LOCATION', 'local'))
        table_name = table_name or os.getenv('METADATA_TABLE')
        self.table = self.dynamodb.Table(table_name)
        
        # Initialize the user-groups table
        group_table_name = group_table_name or os.getenv('GROUP_TABLE')
        self.group_table = self.dynamodb.Table(group_table_name)

    def set_dynamo_db(self, database_location):
        if database_location == 'local':
            self.dynamodb = boto3.resource(
                'dynamodb',
                endpoint_url='http://localhost:8000'  # Point to local DynamoDB
            )
        else:  # Connect to remote db by inputting proper URL
            self.dynamodb = boto3.resource('dynamodb')

    def save_metadata(self, metadata):
        # Ensure metadata includes user_id and group_id
        if 'user_id' not in metadata or 'group_id' not in metadata:
            raise ValueError("Metadata must include 'user_id' and 'group_id'")
        
        self.table.put_item(Item=metadata)

    def get_model_metadata(self, model_id, user_id):
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
