# storage.py

import os
from boto3 import client
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from datetime import datetime
from metadata_store import MetadataStore, save_metadata_to_file


class MlModelStorage:
    def __init__(self, storage_type=None, s3_bucket_name=None, metadata_store=None, local_dir=None):

        self.storage_type = storage_type or os.getenv('STORAGE_TYPE')

        if 's3' in self.storage_type:
            self.s3_bucket_name = s3_bucket_name or os.getenv('S3_BUCKET_NAME')
            if self.storage_type == 'local_s3':
                self.s3_client = client('s3', endpoint_url='http://localhost:4566')
            elif storage_type == 's3':
                self.s3_client = client('s3') 

        if self.storage_type == 'local_file':
            self.local_dir = local_dir or os.getenv('LOCAL_DIR') 
        else:
            self.metadata_store = metadata_store or MetadataStore()


    def save(self, filename, model_file, version, model_name, file_extension,
             current_user, user_id, group_id=None, description=None, accuracy=None):
        if self.storage_type == 'local_file':
            success, error = self._save_local(filename, model_file, version, model_name, user_id, group_id)
        elif 's3' in self.storage_type:
            success, error = self._save_s3(filename, model_file, version, model_name, user_id, group_id)
        else:
            raise ValueError("Invalid storage type")

        if success:
            self._save_metadata(filename, version, model_name, file_extension,
                                current_user, user_id, group_id, description,
                                accuracy)
        return success, error

    def _save_local(self, filename, model_file, version, model_name, user_id, group_id):
        user_dir = os.path.join(self.local_dir, user_id)
        os.makedirs(user_dir, exist_ok=True)
        file_path = os.path.join(user_dir, filename)
        if os.path.exists(file_path):
            return False, (f'Model version {version} for {model_name} model '
                           f'already exists for user {user_id}')
        model_file.save(file_path)
        return True, None

    def _save_s3(self, filename, model_file, version, model_name, user_id, group_id):
        try:
            key = f'{user_id}/{filename}'
            self.s3_client.upload_fileobj(model_file, self.s3_bucket_name, key)
            return True, None
        except (NoCredentialsError, PartialCredentialsError) as e:
            return False, str(e)

    def _save_metadata(self, filename, version, model_name, file_extension,
                       current_user, user_id, group_id=None, description=None,
                       accuracy=None):
        metadata = {
            'id': f'{model_name}-{version}-{user_id}',
            'filename': filename,
            'model_name': model_name,
            'version': version,
            'file_extension': file_extension,
            'description': description,
            'accuracy': accuracy,
            'username': current_user,
            'user_id': user_id,
            'group_id': group_id,
            'created_by': current_user or 'Unknown',
            'created_at': datetime.utcnow().isoformat()
        }
        if self.storage_type == 'local_file':
            save_metadata_to_file(metadata)
        else:
            self.metadata_store.save_metadata(metadata)
