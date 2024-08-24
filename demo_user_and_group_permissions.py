import boto3
import utils

from setup_dynamodb import create_users_table, create_groups_table, create_permissions_table, table_exists, create_user_group_membership_table
from user_management import UserManager
from permissions_management import PermissionsManager, Permission

dynamodb = boto3.resource(
    'dynamodb',
    endpoint_url='http://localhost:8000'  # Point to local DynamoDB
)

TABLES = ('Users', 'Groups', 'UserGroupMembership', 'Permissions')

def setup_dynamodb():
    """Ensure DynamoDB tables are created if they don't exist."""
    if not table_exists('Users'):
        create_users_table()
    if not table_exists('Groups'):
        create_groups_table()
    if not table_exists('Permissions'):
        create_permissions_table()
    if not table_exists('UserGroupMembership'):
        create_user_group_membership_table()

def print_table_contents():
    for table_name in TABLES:
        print (f'------ {table_name} -------')
        print(utils.list_dynamodb_items(table_name, dynamodb))

def clear_table_contents():
    for table_name in TABLES:
        utils.clear_dynamodb_table(dynamodb, table_name)

def main():
    # Setup DynamoDB tables
    setup_dynamodb()

    clear_table_contents()

    # Create UserManager and PermissionsManager instances with DynamoDB tables
    user_manager = UserManager(dynamodb)
    permissions_manager = PermissionsManager(dynamodb)

    # Initialize an admin user
    print("Initializing admin user...")
    admin_user_id = user_manager.register_user('admin', 'admin_password')
    print(f"Admin user ID: {admin_user_id}")
    print_table_contents()
    print()
    permissions_manager.initialize_admin_permissions(admin_user_id)

    '''
    # Register a regular user
    print("Registering regular user...")
    user_id = user_manager.register_user('john_doe', 'secure_password')
    print(f"Regular user ID: {user_id}")
    print_table_contents()
    print()

    # Create a group
    print("Creating a new group...")
    group_id = user_manager.create_group('example_group', admin_user_id)
    print(f"Group ID: {group_id}")
    print_table_contents()
    print()

    # Add user to the group
    print("Adding user to the group...")
    result = user_manager.add_user_to_group(admin_user_id, user_id, group_id)
    print(result)
    print_table_contents()
    print()

    # Check if user has permissions to upload a model
    print("Checking user permissions...")
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
    print_table_contents()
    print()

    # Add additional permissions to the user
    print("Adding additional permissions to the user...")
    permissions_manager.add_user_permissions(user_id, [Permission.UPLOAD_MODEL])
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can now upload model: {can_upload}")
    print_table_contents()
    print()

    # Remove user permissions and check again
    print("Removing permissions from the user...")
    permissions_manager.remove_user_permissions(user_id, [Permission.UPLOAD_MODEL])
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model after removal: {can_upload}")
    print_table_contents()
    print()

    # Add permissions to the group and verify
    print("Adding permissions to the group...")
    permissions_manager.add_group_permissions(group_id, [Permission.UPLOAD_MODEL, Permission.REMOVE_MODEL])
    group_permissions = permissions_manager.get_group_permissions(group_id)
    print(f"Group permissions: {group_permissions}")
    print_table_contents()
    print()

    # Check if user has permissions to upload a model
    print("Checking user permissions...")
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
    print_table_contents()
    print()

    # Remove user from the group
    print("Removing user from the group...")
    result = user_manager.remove_user_from_group(admin_user_id, user_id, group_id)
    print(result)
    print_table_contents()
    print()

    # Check if user has permissions to upload a model
    print("Checking user permissions...")
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
    print_table_contents()
    print()

    # Add user to the group
    print("Adding user to the group...")
    result = user_manager.add_user_to_group(admin_user_id, user_id, group_id)
    print(result)
    print_table_contents()
    print()

    # Check if user has permissions to upload a model
    print("Checking user permissions...")
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
    print_table_contents()
    print()

    # Remove permissions from the group and verify
    print("Removing permissions from the group...")
    permissions_manager.remove_group_permissions(group_id, [Permission.UPLOAD_MODEL])
    group_permissions = permissions_manager.get_group_permissions(group_id)
    print(f"Group permissions after removal: {group_permissions}")
    print_table_contents()
    print()

    # Check if user has permissions to upload a model
    print("Checking user permissions...")
    can_upload = user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
    print_table_contents()
    print()

    # Remove user from the group
    print("Removing user from the group...")
    result = user_manager.remove_user_from_group(admin_user_id, user_id, group_id)
    print(result)
    print_table_contents()
    print()
    '''


if __name__ == "__main__":
    main()
