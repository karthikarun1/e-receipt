import os
import boto3
import utils
import dynamodb_utils
from dotenv import load_dotenv
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from org_management import OrganizationManager
from permissions_management import PermissionsManager, Permission
from subscription_management import SubscriptionManager
from user_management import UserManager
from email_util import EmailUtil

# Load environment variables from .env file
load_dotenv()

TABLE_PREFIX = os.getenv('TABLE_PREFIX')

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


def main():
    # Create all tables again 
    dynamodb_resource = get_dynamodb_resource()
    dynamodb_client = get_dynamodb_client()

    #dynamodb_utils.wipe_out_all_tables(dynamodb_client)
    #dynamodb_utils.create_all_required_tables(dynamodb_resource, 'Dev')
    
    # List tables
    tables = dynamodb_utils.list_dynamodb_tables(dynamodb_client)
    print ('\n'.join(tables))

    # Initialize management classes
    email_util = EmailUtil()
    subscription_management = SubscriptionManager(dynamodb_resource, email_util, TABLE_PREFIX)
    user_management = UserManager(dynamodb_resource, TABLE_PREFIX)
    permissions_management = PermissionsManager(dynamodb_resource, TABLE_PREFIX)
    org_management = OrganizationManager(dynamodb_resource, email_util, TABLE_PREFIX)

    # Step 1: Register a User
    #user_management.register_user(
    #    username='user_1',
    #    email='karthikarun@gmail.com',
    #    password='testing11',
    #    confirm_password='testing11'
    #)
    #print("User 'user_1' registered successfully.")
    # Retrieve and print user data

    user_data = user_management.get_user_details('user_1')
    print("User data after registration:", user_data)

    '''
    # Step 2: Create an Organization and Add the User
    try:
        org_id = org_management.create_organization('org_1', 'Organization 1')
        org_management.add_user_to_organization(user_id='user_1', org_id=org_id)
        print(f"User 'user_1' added to organization '{org_id}' successfully.")
    except Exception as e:
        print(f"Failed to create organization or add user: {str(e)}")

    team_subscription_id = subscription_management.create_subscription(user_id='user_2', plan_type='team')
    print(f"Created team subscription: {team_subscription_id}")

    # Confirm subscription for team user
    subscription_management.confirm_subscription(team_subscription_id)
    print(f"Confirmed team subscription: {team_subscription_id}")

    # List all subscriptions
    subscriptions = subscription_management.list_subscriptions()
    print(f"List of all subscriptions: {subscriptions}")

    # Organization Manager Tests
    print("\n--- Organization Manager Tests ---")
    try:
        org_id = org_management.create_organization(org_name='My Organization', admin_user_id='user_1')
        print(f"Created organization: {org_id}")
    except PermissionError as e:
        print(f"Error: {e}")

    org_id = org_management.create_organization(org_name='My Team Org', admin_user_id='user_2')
    print(f"Created organization with team plan: {org_id}")

    org_management.rename_organization(org_id=org_id, new_org_name='My Renamed Org')
    print(f"Renamed organization: {org_id}")

    org_management.add_user_to_organization(org_id=org_id, user_id='user_3')
    print(f"Added user to organization: user_3")

    org_management.add_group_to_organization(org_id=org_id, group_id='group_1')
    print(f"Added group to organization: group_1")

    org_management.add_admins(org_id=org_id, admin_user_ids=['user_3'])
    print(f"Added admin to organization: user_3")

    org_management.remove_user_from_organization(org_id=org_id, user_id='user_3')
    print(f"Removed user from organization: user_3")

    org_management.remove_group_from_organization(org_id=org_id, group_id='group_1')
    print(f"Removed group from organization: group_1")

    org_management.remove_admins(org_id=org_id, admin_user_ids=['user_2'])
    print(f"Removed admin from organization: user_2")

    # User Manager Tests
    print("\n--- User Manager Tests ---")
    user_id = user_management.register_user(username='john_doe', email='john@example.com', password='password123', confirm_password='password123')
    print(f"Registered user: {user_id}")

    user_management.request_password_reset(email='john@example.com')
    print("Requested password reset for john@example.com")

    user_management.verify_email(email='john@example.com', verification_code='123456')  # Replace '123456' with the actual code sent via email
    print("Verified email for john@example.com")

    user_management.login_user(username='john_doe', password='password123')
    print("Logged in user john_doe")

    # Group Manager Tests
    print("\n--- Group Manager Tests ---")
    group_id = user_management.create_group(group_name='Dev Team', creator_user_id=user_id)
    print(f"Created group: {group_id}")

    user_management.add_user_to_group(executor_user_id=user_id, user_id=user_id, group_id=group_id)
    print(f"Added user {user_id} to group {group_id}")

    user_management.remove_user_from_group(executor_user_id=user_id, user_id=user_id, group_id=group_id)
    print(f"Removed user {user_id} from group {group_id}")

    user_groups = user_management.get_user_groups(user_id=user_id)
    print(f"Groups for user {user_id}: {user_groups}")

    # Permissions Manager Tests
    print("\n--- Permissions Manager Tests ---")
    permissions_management.add_user_permissions(user_id=user_id, permissions=[Permission.UPLOAD_MODEL])
    print(f"Added permissions to user: {user_id}")

    can_upload = permissions_management.check_permission(user_id=user_id, permission=Permission.UPLOAD_MODEL)
    print(f"Can user {user_id} upload model? {can_upload}")

    permissions_management.remove_user_permissions(user_id=user_id, permissions=[Permission.UPLOAD_MODEL])
    print(f"Removed permissions from user: {user_id}")

    permissions_management.add_group_permissions(group_id=group_id, permissions=[Permission.DELETE_MODEL])
    print(f"Added permissions to group: {group_id}")

    group_permissions = permissions_management.get_group_permissions(group_id=group_id)
    print(f"Permissions for group {group_id}: {group_permissions}")

    permissions_management.remove_group_permissions(group_id=group_id, permissions=[Permission.DELETE_MODEL])
    print(f"Removed permissions from group: {group_id}")

    # Email Utility Tests
    print("\n--- Email Utility Tests ---")
    email_util.send_confirmation_email(to_email='john@example.com', subscription_id=individual_subscription_id)
    print("Sent confirmation email for subscription.")

    email_util.send_activation_email(to_email='john@example.com', subscription_id=individual_subscription_id)
    print("Sent activation email for subscription.")

    email_util.send_invite_email(to_email='john@example.com', org_name='My Renamed Org', invite_link='https://example.com/invite')
    print("Sent invitation email for organization.")

    # Final cleanup (optional)
    cleanup_tables(dynamodb)
    '''

if __name__ == "__main__":
    main()
