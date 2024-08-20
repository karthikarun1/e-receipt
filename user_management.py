from botocore.exceptions import ClientError
import hashlib
import uuid
from permissions_management import PermissionsManager, Permission
from boto3.dynamodb.conditions import Key  # Add this import statement


class UserManager:
    def __init__(self, dynamodb):
        self.dynamodb = dynamodb
        self.user_table = dynamodb.Table('Users')
        self.groups_table = dynamodb.Table('Groups')
        self.user_group_membership_table = dynamodb.Table('UserGroupMembership')
        self.permissions_manager = PermissionsManager(dynamodb)

    def _convert_permission_to_string(self, permission):
        """Convert a Permission enum to a string."""
        return permission.value if isinstance(permission, Permission) else permission

    def register_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user_id = str(uuid.uuid4())
        try:
            self.user_table.put_item(
                Item={
                    'id': user_id,
                    'username': username,
                    'password': hashed_password,
                    'group_ids': []  # Start with no groups
                }
            )
            return user_id
        except ClientError as e:
            print(f"Error registering user: {e}")
            return None

    def login_user(self, username, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            response = self.user_table.get_item(Key={'username': username})
            user = response.get('Item')
            if user and user['password'] == hashed_password:
                return user['id']
            else:
                return None
        except ClientError as e:
            print(f"Error logging in user: {e}")
            return None

    def create_group(self, group_name, creator_user_id):
        if not self.permissions_manager.check_permission(creator_user_id, Permission.CREATE_GROUP):
            return "Permission denied"

        group_id = str(uuid.uuid4())
        try:
            self.groups_table.put_item(
                Item={
                    'id': group_id,
                    'name': group_name,
                    'permissions': []  # Initialize with no permissions
                }
            )
            return group_id
        except ClientError as e:
            print(f"Error creating group: {e}")
            return None

    def get_user_groups(self, user_id):
        """Retrieve the list of groups a user is a member of."""
        try:
            response = self.user_group_membership_table.query(
                KeyConditionExpression=Key('user_id').eq(user_id)
            )
            group_ids = [item['group_id'] for item in response.get('Items', [])]
            return group_ids
        except ClientError as e:
            print(f"Error retrieving user groups: {e}")
            return []

    def add_user_to_group(self, executor_user_id, user_id, group_id):
        """Add a user to a group."""
        if not self.permissions_manager.check_permission(executor_user_id, Permission.ADD_USER_TO_GROUP):
            return "Unauthorized: You don't have permission to add users to groups."

        try:
            self.user_group_membership_table.put_item(
                Item={
                    'user_id': user_id,
                    'group_id': group_id
                }
            )
            return "User added to group"
        except ClientError as e:
            print(f"Error adding user to group: {e}")
            return "Error adding user to group"

    def remove_user_from_group(self, executor_user_id, user_id, group_id):
        """Remove a user from a group."""
        if not self.permissions_manager.check_permission(executor_user_id, Permission.REMOVE_USER_FROM_GROUP):
            return "Unauthorized: You don't have permission to remove users from groups."

        try:
            self.user_group_membership_table.delete_item(
                Key={
                    'user_id': user_id,
                    'group_id': group_id
                }
            )
            return "User removed from group"
        except ClientError as e:
            print(f"Error removing user from group: {e}")
            return "Error removing user from group"

    def check_model_permission(self, user_id, permission):
        """Check if the user can perform a given model operation considering both user and group permissions."""
        permission_str = self._convert_permission_to_string(permission)
        # Check user-specific permissions
        user_permissions = self.permissions_manager.get_user_permissions(user_id)
        print(f"User permissions for {user_id}: {user_permissions}")  # Debugging line
        if permission in user_permissions:
            return True 

        # Check group permissions if user-specific permissions don't include the permission
        group_ids = self.get_user_groups(user_id)
        print(f"Groups for user {user_id}: {group_ids}")  # Debugging line
        for group_id in group_ids:
            group_permissions = self.permissions_manager.get_group_permissions(group_id)
            print(f"Permissions for group {group_id}: {group_permissions}")  # Debugging line
            print (f'permission {permission_str} in group_permissions {group_permissions} {permission_str in group_permissions}')
            if permission_str in group_permissions:
                return True

        # Permission not found
        return False

    def check_model_permission_old(self, user_id, permission):
        """Check if the user can perform a given model operation considering both user and group permissions."""
        # Check user-specific permissions
        user_permissions = self.permissions_manager.get_user_permissions(user_id)
        if permission in user_permissions:
            return True

        # Check group permissions if user-specific permissions don't include the permission
        group_ids = self.get_user_groups(user_id)
        for group_id in group_ids:
            group_permissions = self.permissions_manager.get_group_permissions(group_id)
            if permission in group_permissions:
                return True

        # Permission not found
        return False

# Example usage:
if __name__ == "__main__":
    manager = UserManager()
    
    # Register a new user
    user_id = manager.register_user('john_doe', 'secure_password')
    print(f"Registered user ID: {user_id}")

    # Login a user
    logged_in_user_id = manager.login_user('john_doe', 'secure_password')
    print(f"Logged in user ID: {logged_in_user_id}")

    # Create a group
    group_id = manager.create_group('example_group', logged_in_user_id)
    print(f"Created group ID: {group_id}")

    # Add user to group
    result = manager.add_user_to_group(logged_in_user_id, logged_in_user_id, group_id)
    print(result)

    # Remove user from group
    result = manager.remove_user_from_group(logged_in_user_id, logged_in_user_id, group_id)
    print(result)

    # Check model permissions
    can_upload = manager.check_model_permission(logged_in_user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
