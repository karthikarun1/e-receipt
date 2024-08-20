from botocore.exceptions import ClientError
from enum import Enum


class Permission(Enum):
    ADD_USER_TO_GROUP = 'add_user_to_group'
    REMOVE_USER_FROM_GROUP = 'remove_user_from_group'
    CREATE_GROUP = 'create_group'
    MANAGE_PERMISSIONS = 'manage_permissions'
    UPLOAD_MODEL = 'upload_model'
    LIST_MODELS = 'list_models'
    REMOVE_MODEL = 'remove_model'
    PREDICT = 'predict'
    DOWNLOAD_MODEL = 'download_model'

class PermissionsManager:
    def __init__(self, dynamodb):
        self.permissions_table = dynamodb.Table('Permissions')
        self.groups_table = dynamodb.Table('Groups')
        self.user_table = dynamodb.Table('Users')

    def _convert_permissions_to_strings(self, permissions):
        """Convert list of Permission enums to strings."""
        return [permission.value if isinstance(permission, Permission) else permission for permission in permissions]

    def add_user_permissions(self, user_id, permissions):
        """Add permissions to a user."""
        try:
            permissions = self._convert_permissions_to_strings(permissions)
            response = self.permissions_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="SET #perm = list_append(if_not_exists(#perm, :empty_list), :permissions)",
                ExpressionAttributeNames={
                    '#perm': 'permissions'
                },
                ExpressionAttributeValues={
                    ':permissions': permissions,
                    ':empty_list': []
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error adding user permissions: {e}")
            raise

    def remove_user_permissions(self, user_id, permissions):
        """Remove permissions from a user."""
        try:
            # Convert permissions to strings
            permissions = self._convert_permissions_to_strings(permissions)

            # Get current permissions
            current_permissions = self.get_user_permissions(user_id)

            # Ensure current permissions are in string format
            current_permissions = self._convert_permissions_to_strings(current_permissions)

            # Remove specified permissions
            updated_permissions = [p for p in current_permissions if p not in permissions]

            # Update item in DynamoDB
            response = self.permissions_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="SET #perm = :permissions",
                ExpressionAttributeNames={
                    '#perm': 'permissions'
                },
                ExpressionAttributeValues={
                    ':permissions': updated_permissions
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error removing user permissions: {e}")
            raise

    def remove_user_permissions_old(self, user_id, permissions):
        """Remove permissions from a user."""
        try:
            permissions = self._convert_permissions_to_strings(permissions)
            current_permissions = self.get_user_permissions(user_id)
            updated_permissions = [p for p in current_permissions if p not in permissions]

            response = self.permissions_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression="SET #perm = :permissions",
                ExpressionAttributeNames={
                    '#perm': 'permissions'
                },
                ExpressionAttributeValues={
                    ':permissions': updated_permissions
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error removing user permissions: {e}")
            raise

    def add_group_permissions(self, group_id, permissions):
        """Add permissions to a group."""
        try:
            permissions = self._convert_permissions_to_strings(permissions)
            response = self.groups_table.update_item(
                Key={'id': group_id},
                UpdateExpression="SET #perm = list_append(if_not_exists(#perm, :empty_list), :permissions)",
                ExpressionAttributeNames={
                    '#perm': 'permissions'
                },
                ExpressionAttributeValues={
                    ':permissions': permissions,
                    ':empty_list': []
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error adding group permissions: {e}")
            raise

    def remove_group_permissions(self, group_id, permissions):
        """Remove permissions from a group."""
        try:
            permissions = self._convert_permissions_to_strings(permissions)
            current_permissions = self.get_group_permissions(group_id)
            updated_permissions = [p for p in current_permissions if p not in permissions]

            response = self.groups_table.update_item(
                Key={'id': group_id},
                UpdateExpression="SET #perm = :permissions",
                ExpressionAttributeNames={
                    '#perm': 'permissions'
                },
                ExpressionAttributeValues={
                    ':permissions': updated_permissions
                },
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error removing group permissions: {e}")
            raise

    def get_user_permissions(self, user_id):
        """Get the effective permissions for a user."""
        try:
            user_response = self.user_table.get_item(Key={'id': user_id})
            user = user_response.get('Item')
            if not user:
                return set()
            
            group_ids = user.get('group_ids', [])
            user_permissions = set()
            
            # Get group permissions
            for group_id in group_ids:
                group_response = self.groups_table.get_item(Key={'id': group_id})
                group = group_response.get('Item')
                if group:
                    group_permissions = set(group.get('permissions', []))
                    user_permissions.update(group_permissions)
            
            # Get direct user permissions
            user_permissions_response = self.permissions_table.get_item(Key={'user_id': user_id})
            direct_permissions = set(user_permissions_response.get('Item', {}).get('permissions', []))
            user_permissions.update(direct_permissions)
            
            return {Permission(p) for p in user_permissions}
        except ClientError as e:
            print(f"Error retrieving user permissions: {e}")
            return set()

    def get_group_permissions(self, group_id):
        """Retrieve a group's permissions."""
        try:
            response = self.groups_table.get_item(Key={'id': group_id})
            return response.get('Item', {}).get('permissions', [])
        except ClientError as e:
            print(f"Error retrieving group permissions: {e}")
            return []

    def check_permission(self, user_id, permission):
        """Check if a user has a specific permission."""
        permissions = self.get_user_permissions(user_id)
        return permission in permissions

    def manage_permissions(self, executor_user_id, target_user_id, operation, permission):
        """Manage permissions (assign/remove) for a user or group."""
        if not self.check_permission(executor_user_id, Permission.MANAGE_PERMISSIONS):
            return "Permission denied"

        if operation == 'add':
            self.add_user_permissions(target_user_id, [permission])
        elif operation == 'remove':
            # Here you might need to implement removal logic
            pass

    def initialize_admin_permissions(self, admin_user_id):
        """Initialize permissions for an admin user."""
        try:
            admin_permissions = [
                Permission.ADD_USER_TO_GROUP,
                Permission.REMOVE_USER_FROM_GROUP,
                Permission.CREATE_GROUP,
                Permission.MANAGE_PERMISSIONS,
                Permission.UPLOAD_MODEL,
                Permission.LIST_MODELS,
                Permission.REMOVE_MODEL,
                Permission.PREDICT,
                Permission.DOWNLOAD_MODEL
            ]
            self.add_user_permissions(admin_user_id, admin_permissions)
        except Exception as e:
            print(f"Error initializing admin permissions: {e}")

# Example usage:
if __name__ == "__main__":
    manager = PermissionsManager()
    
    # Create tables if they don't exist
    # manager.create_permissions_table() # Optionally create table if needed
    # manager.create_groups_table() # Optionally create table if needed

    # Add permissions to a group
    group_id = 'example_group_id'  # Replace with actual group ID
    manager.add_group_permissions(group_id, [Permission.UPLOAD_MODEL, Permission.LIST_MODELS])

    # Add permissions to a user
    user_id = 'user_123'
    manager.add_user_permissions(user_id, [Permission.DOWNLOAD_MODEL])

    # Check user permissions
    has_upload_permission = manager.check_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User has upload permission: {has_upload_permission}")
