# storage.py

import os
import traceback
import utils

from boto3 import client
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime
from metadata_store import MetadataStore


class MlModelStorage:
    def __init__(self, storage_type=None, s3_bucket_name=None, metadata_store=None):

        self.storage_type = storage_type or os.getenv('STORAGE_TYPE')

        if 's3' in self.storage_type:
            self.s3_bucket_name = s3_bucket_name or os.getenv('S3_BUCKET_NAME')
            if self.storage_type == 'local_s3':
                self.s3_client = client('s3', endpoint_url='http://localhost:4566')
            elif storage_type == 's3':
                self.s3_client = client('s3') 
        self.metadata_store = metadata_store or MetadataStore()


    def save(self, filename, model_file, version, model_name, file_extension,
             current_username, user_id, group_id=None, description=None, accuracy=None):
        if self.storage_type == 'local_file':
            success, error = self._save_local(filename, model_file, version, model_name, user_id, group_id)
        elif 's3' in self.storage_type:
            success, error = self._save_s3(filename, model_file, version, model_name, user_id, group_id)
        else:
            raise ValueError("Invalid storage type")

        if success:
            self._save_metadata(filename, version, model_name, file_extension,
                                current_username, user_id, group_id, description,
                                accuracy)
        return success, error

    def _save_s3(self, filename, model_file, version, model_name, user_id, group_id):
        try:
            key = f'{user_id}/{filename}'
            self.s3_client.upload_fileobj(model_file, self.s3_bucket_name, key)
            return True, None
        except (NoCredentialsError, PartialCredentialsError) as e:
            return False, str(e)

    @utils.print_function_arguments
    def _save_metadata(self, filename, version, model_name, file_extension,
                       current_username, user_id, group_id=None, description='N/A',
                       accuracy='N/A'):
        print (f'---------------=GROUP ID +++++++++++ is {group_id} ' + repr(group_id))
        group_id = group_id or 'N/A'
        print (f'---------------=GROUP ID +++++++++++ is {group_id} ' + repr(group_id))
        metadata = {
            'id': f'{model_name}-{version}-{user_id}',
            'filename': filename,
            'model_name': model_name,
            'version': version,
            'file_extension': file_extension,
            'description': description or 'N/A',
            'accuracy': accuracy,
            'username': current_username,
            'user_id': user_id,
            'group_id': group_id or 'N/A',
            'created_by': current_username,
            'created_at': datetime.utcnow().isoformat()
        }
        '''
        metadata = {
            'user_id': 'eaadb29b-9e4c-4360-9735-52d301f32f28',  # Ensure this is a string
            'id': 'sample_model-v0-eaadb29b-9e4c-4360-9735-52d301f32f28',  # Ensure this is a string
            'model_name': 'sample_model',
            'version': 'v0'
        }
        '''
        self.metadata_store.save_metadata(metadata)

    def remove_model_by_key(self, s3_key):
        """
        Remove a model from S3 storage using the provided S3 key.

        :param s3_key: The S3 key of the model file to be deleted.
        """
        try:
            self.s3_client.delete_object(Bucket=self.s3_bucket_name, Key=s3_key)
            print(f"Model with key '{s3_key}' successfully removed from S3.")
        except self.s3_client.exceptions.NoSuchKey:
            print(f"Model with key '{s3_key}' not found in S3.")
            raise
        except Exception as e:
            print(f"Error removing model from S3: {e}")
            traceback.print_exc()
            raise

    def remove_model(self, user_id, model_name, version):
        try:
            # Construct the S3 key
            s3_key = f"{user_id}/{model_name}/{version}/"
            
            # Remove the model file from S3
            self.s3_client.delete_object(Bucket=self.s3_bucket_name, Key=s3_key)
            
            # Remove the corresponding metadata from DynamoDB
            self.metadata_table.delete_item(
                Key={
                    'user_id': user_id,
                    'model_name_version': f"{model_name}_{version}"
                }
            )
            
            return True, None
        except ClientError as e:
            return False, str(e)
