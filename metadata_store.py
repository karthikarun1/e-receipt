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
    def __init__(self, table_name=None):
        self.set_dynamo_db(database_location)
        table_name = table_name or os.getenv('METADATA_TABLE')
        self.table = self.dynamodb.Table(
            table_name or os.getenv('METADATA_TABLE'))

    def set_dynamo_db(self, database_location):
        if database_location == 'local':
            self.dynamodb = boto3.resource(
                'dynamodb',
                endpoint_url='http://localhost:8000'  # Point to local DynamoDB
            )
        else:  # Connect to remote db by inputing proper url
            self.dynamodb = boto3.resource('dynamodb')

    def save_metadata(self, metadata):
        self.table.put_item(Item=metadata)
