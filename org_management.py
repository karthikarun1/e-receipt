import boto3
import logging
import uuid

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
from datetime import datetime

# Import setup for DynamoDB from setup_dynamodb.py
from base_management import BaseManager
from subscription_management import SubscriptionManager, SubscriptionPlanType
from permissions_management import PermissionsManager
from user_management import UserManager
from org_updates import OrganizationUpdater

logger = logging.getLogger(__name__)

class OrganizationManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.subscription_manager = SubscriptionManager(dynamodb, table_prefix)
        self.user_manager = UserManager(dynamodb, table_prefix)
        self.permissions_manager = PermissionsManager(dynamodb, table_prefix)
        self.updater = OrganizationUpdater(
            self, self.user_manager, self.permissions_manager,
            dynamodb, self.org_table_name)

    def create_organization(self, org_name, creator_user_id):
        """Create a new organization and assign the creator as the admin."""

        # Check if the user exists
        user = self.users_table.get_item(Key={'id': creator_user_id}).get('Item')
        if not user:
            raise ValueError("Invalid user ID: User does not exist.")

        # Check if the organization name already exists
        response = self.dynamodb.Table(self.org_table_name).scan(
            FilterExpression=Attr('org_name').eq(org_name)
        )
        if response.get('Items'):
            raise ValueError(f"Organization name '{org_name}' already exists. "
                             f"Please choose a different name.")

        # Automatically determine the user's plan type
        plan_type = self.subscription_manager.get_user_plan_type(creator_user_id)

        org_id = str(uuid.uuid4())  # Generate a unique organization ID

        # Add the organization to the table
        table = self.dynamodb.Table(self.org_table_name)
        item = {
            'id': org_id,
            'org_name': org_name,
            'plan_type': plan_type.value,  # Store the plan type as a string
            'admins': [creator_user_id],  # Assign the creator as the first admin
            'users': [creator_user_id],   # Add the creator as a user as well
            'created_at': str(datetime.utcnow()),  # Store creation time
            'updated_at': str(datetime.utcnow())
        }
        table.put_item(Item=item)

        logger.info(f"Organization '{org_name}' created successfully with "
                    f"ID: {org_id} under the {plan_type.value} plan.")

        # Assign admin permissions to the creator
        self.permissions_manager.initialize_admin_permissions(creator_user_id)

        return org_id

    def is_org_name_taken(self, org_name):
        """
        Check if an organization name is already taken.

        :param org_name: str - The organization name to check.
        :return: bool - True if the organization name is taken, False otherwise.
        """
        table = self.dynamodb.Table(self.org_table_name)
        response = table.scan(
            FilterExpression=Attr('org_name').eq(org_name)
        )
        items = response.get('Items', [])
        return len(items) > 0

    def rename_organization(self, org_id, new_org_name):
        # Check if the new organization name is unique
        table = self.dynamodb.Table(self.org_table_name)
        response = table.scan(
            FilterExpression="org_name = :new_org_name",
            ExpressionAttributeValues={":new_org_name": new_org_name}
        )
        if response.get('Items'):
            raise ValueError("Organization name must be unique.")

        # Update the organization name
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="SET org_name = :new_org_name, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':new_org_name': new_org_name,
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
            print(f"Organization {org_id} renamed to {new_org_name}.")
        except ClientError as e:
            print(e.response['Error']['Message'])

    def get_organization_by_id(self, org_id):
        """
        Retrieve an organization by its ID.

        :param org_id: str - The unique identifier for the organization.
        :return: dict - The organization's details.
        :raises ValueError: If the organization does not exist.
        """
        table = self.dynamodb.Table(self.org_table_name)
        response = table.get_item(Key={'id': org_id})
        org = response.get('Item')
        if not org:
            raise ValueError(f"Organization not found.")
        return org

    def get_organization(self, org_id):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            response = table.get_item(Key={'org_id': org_id})
            return response.get('Item')
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def get_org_id_by_name(self, org_name):
        """
        Retrieve the organization ID given the organization name.

        :param org_name: str - The name of the organization.
        :return: str - The organization ID.
        :raises ValueError: If the organization with the given name is not found.
        """
        table = self.dynamodb.Table(self.org_table_name)
        response = table.scan(
            FilterExpression=Attr('org_name').eq(org_name)
        )

        items = response.get('Items', [])
        if not items:
            raise ValueError(f"Organization with name '{org_name}' not found.")

        if len(items) > 1:
            raise ValueError(f"Multiple organizations found with the name '{org_name}'. Please use a unique name.")

        return items[0]['id']

    def update_organization(self, org_id, user_id, updates):
        return self.updater.update_organization(org_id, user_id, updates)

    def update_organization_old(self, org_id, org_name=None):
        table = self.dynamodb.Table(self.org_table_name)
        update_expression = "SET updated_at = :updated_at"
        expression_attribute_values = {':updated_at': str(datetime.utcnow())}

        if org_name:
            update_expression += ", org_name = :org_name"
            expression_attribute_values[':org_name'] = org_name

        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def delete_organization(self, org_id):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            table.delete_item(Key={'org_id': org_id})
        except ClientError as e:
            print(e.response['Error']['Message'])

    def add_user_to_organization(self, org_id, user_id):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="ADD users :user_id",
                ExpressionAttributeValues={':user_id': {user_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def remove_user_from_organization(self, org_id, user_id):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="DELETE users :user_id",
                ExpressionAttributeValues={':user_id': {user_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def add_group_to_organization(self, org_id, group_id):
        table = self.dynamodb.Table(self.groups_table_name)
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="ADD groups :group_id",
                ExpressionAttributeValues={':group_id': {group_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def remove_group_from_organization(self, org_id, group_id):
        table = self.dynamodb.Table(self.groups_table_name)
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="DELETE groups :group_id",
                ExpressionAttributeValues={':group_id': {group_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def list_groups_in_organization(self, org_id):
        try:
            response = self.groups_table.scan(
                FilterExpression=Key('org_id').eq(org_id)
            )
            return response.get('Items', [])
        except ClientError as e:
            print(f"Error listing groups in organization: {e}")
            return []

    def add_admins(self, org_id, admin_user_ids):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            response = table.get_item(Key={'org_id': org_id})
            current_admins = set(response['Item'].get('admins', []))
            new_admins = current_admins.union(set(admin_user_ids))

            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="SET admins = :admins, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':admins': list(new_admins),
                    ':updated_at': str(datetime.utcnow()),
                    ':admins': list(new_admins),
                    ':updated_at': str(datetime.utcnow()),
                },
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def remove_admins(self, org_id, admin_user_ids):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            response = table.get_item(Key={'org_id': org_id})
            current_admins = response['Item'].get('admins', [])
            updated_admins = [admin for admin in current_admins if admin not in admin_user_ids]

            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="SET admins = :admins, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':admins': updated_admins,
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def invite_user_to_organization(self, org_id, user_id):
        user = self.user_management.get_user_details(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} does not exist.")
        
        invite_id = str(uuid.uuid4())
        invites_table = self.dynamodb.Table(self.invites_table_name)

        try:
            invites_table.put_item(
                Item={
                    'invite_id': invite_id,
                    'org_id': org_id,
                    'user_id': user_id,
                    'status': 'pending',
                    'created_at': str(datetime.utcnow()),
                    'expires_at': str(datetime.utcnow())  # Add expiration logic as needed
                }
            )
            print(f"Invitation sent to user {user_id} to join organization {org_id}.")
            return invite_id
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def accept_invite(self, invite_id):
        invites_table = self.dynamodb.Table(self.invites_table_name)
        
        try:
            response = invites_table.get_item(Key={'invite_id': invite_id})
            invite = response.get('Item')
            if not invite:
                raise ValueError(f"Invite with ID {invite_id} does not exist.")
            if invite['status'] != 'pending':
                raise ValueError(f"Invite with ID {invite_id} is not pending.")

            org_id = invite['org_id']
            user_id = invite['user_id']

            # Add user to organization
            self.add_user_to_organization(org_id, user_id)

            # Update invite status
            invites_table.update_item(
                Key={'invite_id': invite_id},
                UpdateExpression="SET status = :status, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':status': 'accepted',
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
            print(f"User {user_id} accepted the invite to join organization {org_id}.")
        except ClientError as e:
            print(e.response['Error']['Message'])

    def reject_invite(self, invite_id):
        invites_table = self.dynamodb.Table(self.invites_table_name)
        
        try:
            response = invites_table.get_item(Key={'invite_id': invite_id})
            invite = response.get('Item')
            if not invite:
                raise ValueError(f"Invite with ID {invite_id} does not exist.")
            if invite['status'] != 'pending':
                raise ValueError(f"Invite with ID {invite_id} is not pending.")

            # Update invite status
            invites_table.update_item(
                Key={'invite_id': invite_id},
                UpdateExpression="SET status = :status, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':status': 'rejected',
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
            print(f"User {invite['user_id']} rejected the invite to join organization {invite['org_id']}.")
        except ClientError as e:
            print(e.response['Error']['Message'])

    def list_organizations(self):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            response = table.scan()
            return response.get('Items', [])
        except ClientError as e:
            print(e.response['Error']['Message'])
            return []

    def _check_free_plan_limits(self, org_id):
        """Check if the organization under the free plan has reached its user or group limits."""
        # Define limits
        MAX_USERS = int(os.getenv('FREE_PLAN_MAX_USERS', 5))  # Default to 5 if not set
        MAX_GROUPS = int(os.getenv('FREE_PLAN_MAX_GROUPS', 2))  # Default to 2 if not set

        # Get the organization details
        org = self.get_organization(org_id)
        if not org:
            raise ValueError("Organization not found")

        # Check user limit
        if len(org.get('users', [])) >= MAX_USERS:
            raise ValueError(f"Organization has reached the maximum user limit of {MAX_USERS}.")

        # Check group limit
        if len(org.get('groups', [])) >= MAX_GROUPS:
            raise ValueError(f"Organization has reached the maximum group limit of {MAX_GROUPS}.")

        return True

    # Example usage in add_user_to_organization
    def add_user_to_organization(self, org_id, user_id):
        # Check limits before adding a user
        self._check_free_plan_limits(org_id)
        
        # Existing logic to add a user
        table = self.dynamodb.Table(self.org_table_name)
        try:
            table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="ADD users :user_id",
                ExpressionAttributeValues={':user_id': {user_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])


# Example usage:
if __name__ == "__main__":
    org_mgmt = OrganizationManager()
    org_id = org_mgmt.create_organization('My Organization', 'user_123')
    print(f'Created organization with ID: {org_id}')

    org = org_mgmt.get_organization(org_id)
    print(f'Organization details: {org}')
