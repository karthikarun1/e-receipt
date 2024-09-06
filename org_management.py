import boto3
import logging
import os
import uuid

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr
from datetime import datetime, timedelta

# Import setup for DynamoDB from setup_dynamodb.py
from base_management import BaseManager
from invitation_manager_by_email import InvitationManager
from invite_type import InviteType
from permissions_management import PermissionsManager
from subscription_management import SubscriptionManager, SubscriptionPlanType
from user_management import UserManager
from org_updates import OrganizationUpdater

# Load environment variables
from config_loader import load_environment
load_environment()

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
        self.invitation_manager = InvitationManager(dynamodb, table_prefix)

    def get_all_organizations(self):
        try:
            # Scan the entire organizations table to retrieve all organizations
            response = self.org_table.scan()
            organizations = response.get('Items', [])

            return organizations

        except ClientError as e:
            logging.error(e)
            raise LookupError("An error occurred while retrieving all organizations.") from e

    def get_user_organizations(self, user_id):
        try:
            # Retrieve the user record
            response = self.users_table.get_item(Key={'id': user_id})
            user = response.get('Item')

            if not user:
                raise LookupError("User not found.")

            # Use expression attribute names to avoid reserved keywords
            response = self.org_table.scan(
                FilterExpression="contains(#users_attr, :user_id)",
                ExpressionAttributeNames={"#users_attr": "users"},
                ExpressionAttributeValues={":user_id": user_id}
            )

            organizations = response.get('Items', [])
            return organizations

        except ClientError as e:
            logging.error(e)
            raise LookupError("An error occurred while retrieving user organizations.") from e

    def get_organization_details(self, org_id, user_id):
        try:
            # Fetch the organization details
            organization = self.get_organization(org_id)

            if not organization:
                raise LookupError("Organization not found.")

            # Check if the user is authorized to view the organization details
            if user_id not in organization.get('users', []) and user_id not in organization.get('admins', []):
                raise PermissionError("User is not authorized to view this organization's details.")

            # Fetch details of users and admins
            users = []
            admins = []
            for org_user_id in organization.get('users', []):
                user_response = self.users_table.get_item(Key={'id': org_user_id})
                user = user_response.get('Item')
                if user:
                    users.append({'id': user['id'], 'username': user['username'], 'email': user['email']})
                    if org_user_id in organization.get('admins', []):
                        admins.append(user['username'])

            organization_details = {
                "organization_id": organization['id'],
                "organization_name": organization['org_name'],
                "plan_type": organization['plan_type'],
                "created_at": organization['created_at'],
                "updated_at": organization['updated_at'],
                "users": users,
                "admins": admins
            }

            return organization_details

        except ClientError as e:
            logging.error(e)
            raise LookupError("An error occurred while retrieving organization details.") from e

    def create_organization(self, org_name, creator_user_id):
        """Create a new organization and assign the creator as the admin."""

        # Check if the user exists
        user = self.users_table.get_item(Key={'id': creator_user_id}).get('Item')
        if not user:
            raise ValueError("Invalid user ID: User does not exist.")

        # Check if the organization name already exists
        response = self.org_table.scan(
            FilterExpression=Attr('org_name').eq(org_name)
        )
        if response.get('Items'):
            raise ValueError(f"Organization name '{org_name}' already exists. "
                             f"Please choose a different name.")

        # Automatically determine the user's plan type
        plan_type = self.subscription_manager.get_user_plan_type(creator_user_id)

        org_id = str(uuid.uuid4())  # Generate a unique organization ID

        # Add the organization to the table
        item = {
            'id': org_id,
            'org_name': org_name,
            'plan_type': plan_type.value,  # Store the plan type as a string
            'admins': {creator_user_id},  # Assign the creator as the first admin
            'users': {creator_user_id},   # Add the creator as a user as well
            'created_at': str(datetime.utcnow()),  # Store creation time
            'updated_at': str(datetime.utcnow())
        }
        self.org_table.put_item(Item=item)

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
        response = self.org_table.scan(
            FilterExpression=Attr('org_name').eq(org_name)
        )
        items = response.get('Items', [])
        return len(items) > 0

    def rename_organization(self, org_id, new_org_name):
        # Check if the new organization name is unique
        response = self.org_table.scan(
            FilterExpression="org_name = :new_org_name",
            ExpressionAttributeValues={":new_org_name": new_org_name}
        )
        if response.get('Items'):
            raise ValueError("Organization name must be unique.")

        # Update the organization name
        try:
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET org_name = :new_org_name, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':new_org_name': new_org_name,
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def get_organization_by_id(self, org_id):
        """
        Retrieve an organization by its ID.

        :param org_id: str - The unique identifier for the organization.
        :return: dict - The organization's details.
        :raises ValueError: If the organization does not exist.
        """
        response = self.org_table.get_item(Key={'id': org_id})
        org = response.get('Item')
        if not org:
            raise ValueError(f"Organization not found.")
        return org

    def get_organization(self, org_id):
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            return response.get('Item')
        except ClientError as e:
            logging.error(e)
            raise ValueError(e.response['Error']['Message'])

    def get_org_id_by_name(self, org_name):
        """
        Retrieve the organization ID given the organization name.

        :param org_name: str - The name of the organization.
        :return: str - The organization ID.
        :raises ValueError: If the organization with the given name is not found.
        """
        response = self.org_table.scan(
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
        update_expression = "SET updated_at = :updated_at"
        expression_attribute_values = {':updated_at': str(datetime.utcnow())}

        if org_name:
            update_expression += ", org_name = :org_name"
            expression_attribute_values[':org_name'] = org_name

        try:
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def delete_organization(self, org_id):
        try:
            self.org_table.delete_item(Key={'id': org_id})
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def add_user_to_organization(self, org_id, user_id):
        try:
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="ADD users :user_id",
                ExpressionAttributeValues={':user_id': {user_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def remove_user_from_organization(self, org_id, user_id):
        try:
            self.org_table.update_item(
                Key={'id': org_id},  # Assuming 'id' is the primary key for the organization table
                UpdateExpression="DELETE #users_attr :user_id",
                ExpressionAttributeNames={"#users_attr": "users"},  # Escaping 'users'
                ExpressionAttributeValues={':user_id': {user_id}},  # Ensure user_id is in a set
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def add_group_to_organization(self, org_id, group_id):
        try:
            self.groups_table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="ADD groups :group_id",
                ExpressionAttributeValues={':group_id': {group_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def remove_group_from_organization(self, org_id, group_id):
        try:
            self.groups_table.update_item(
                Key={'org_id': org_id},
                UpdateExpression="DELETE groups :group_id",
                ExpressionAttributeValues={':group_id': {group_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def list_groups_in_organization(self, org_id):
        try:
            response = self.groups_table.scan(
                FilterExpression=Key('org_id').eq(org_id)
            )
            return response.get('Items', [])
        except ClientError as e:
            logger.error(f"Error listing groups in organization: {e}")
            return []

    def add_admins(self, org_id, admin_user_ids):
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            current_admins = set(response['Item'].get('admins', []))
            new_admins = current_admins.union(set(admin_user_ids))

            self.org_table.update_item(
                Key={'id': org_id},
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
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def remove_admins(self, org_id, admin_user_ids):
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            current_admins = response['Item'].get('admins', [])
            updated_admins = [admin for admin in current_admins if admin not in admin_user_ids]

            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET admins = :admins, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':admins': updated_admins,
                    ':updated_at': str(datetime.utcnow())
                },
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def promote_to_admin(self, user_id: str, org_id: str):
        """
        Promotes a user to admin status within the specified organization.
        """
        # Fetch organization details
        organization = self.get_organization_by_id(org_id)
        
        if not organization:
            raise ValueError("Organization does not exist")

        org_name = organization.get('org_name', 'Unknown organization')

        # Fetch user details
        user = self.user_manager.get_user_details_by_id(user_id)
        if not user:
            raise ValueError("User does not exist")
        
        username = user.get('username', 'Unknown user')

        # Check if the user is a member of the organization
        if user_id not in organization.get('users', []):
            raise ValueError(f"User '{username}' does not belong to the organization '{org_name}'")

        # Check if the user is already an admin
        if user_id in organization.get('admins', []):
            raise ValueError(f"User '{username}' is already an admin in organization '{org_name}'")

        # Use the existing add_admins function to promote the user
        self.add_admins(org_id, [user_id])

        return f"User '{username}' promoted to admin in organization '{org_name}'"

    def demote_from_admin(self, user_id: str, org_id: str):
        """
        Demotes a user from admin status within the specified organization.
        """
        # Fetch organization details
        organization = self.get_organization_by_id(org_id)

        if not organization:
            raise ValueError("Organization does not exist")

        org_name = organization.get('org_name', 'Unknown organization')

        # Fetch user details
        user = self.user_manager.get_user_details_by_id(user_id)
        if not user:
            raise ValueError("User does not exist")
        
        username = user.get('username', 'Unknown user')

        # Check if the user is an admin
        if user_id not in organization.get('admins', []):
            raise ValueError(f"User '{username}' is not an admin in organization '{org_name}'")

        # Ensure at least one admin remains in the organization
        if len(organization["admins"]) == 1 and user_id in organization["admins"]:
            raise ValueError(f"Cannot demote the last admin of organization '{org_name}'")

        # Use the existing remove_admins function to demote the user
        self.remove_admins(org_id, [user_id])

        return f"User '{username}' demoted from admin in organization '{org_name}'"

    def list_organizations(self):
        try:
            response = self.org_table.scan()
            return response.get('Items', [])
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            return []

    def list_users_in_organization(self, org_id, requester_user_id):
        """
        Lists all users within the organization by their details.
        """
        # Check if org_id is provided
        if not org_id:
            raise ValueError("Organization ID is required.")
        
        # Fetch organization details
        organization = self.get_organization_by_id(org_id)

        # Check if organization exists
        if not organization:
            raise ValueError("Organization not found.")

        # Check if the requesting user is part of the organization or an admin
        if requester_user_id not in organization.get('users', []) and requester_user_id not in organization.get('admins', []):
            raise PermissionError("User is not authorized to view this organization's users.")

        user_ids = organization.get('users', [])
        users = []

        # Edge case: No users in the organization
        if not user_ids:
            return []

        # Retrieve details for each user
        for user_id in user_ids:
            user_response = self.user_manager.get_user_details_by_id(user_id)
            if user_response:
                users.append({
                    'id': user_response.get('id'),
                    'username': user_response.get('username'),
                    'email': user_response.get('email')
                })

        return users

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

    def add_user_to_organization(self, org_id, user_id):
        # Check limits before adding a user
        self._check_free_plan_limits(org_id)
        
        # Existing logic to add a user
        try:
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="ADD users :user_id",
                ExpressionAttributeValues={':user_id': {user_id}},
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            logger.error(f"ClientError: {e.response['Error']['Message']}")
            # Re-raise the error to be caught by the error handler in app.py
            raise

    def invite_users(self, org_id, inviter_id, user_ids, invite_type):
        return self.invitation_manager.invite_users(
            org_id, inviter_id, user_ids, invite_type
        )

    def invite_user_to_organization(self, org_id, user_id):
        return self.invitation_manager.invite_users(
            org_id, inviter_id=None, user_ids=[user_id], 
            invite_type=InviteType.ORGANIZATION
        )

    def process_invitation(self, invitation_id, expires_at, signature):
        return self.invitation_manager.process_invitation(
            invitation_id, expires_at, signature
        )


# Example usage:
if __name__ == "__main__":
    org_mgmt = OrganizationManager()
    org_id = org_mgmt.create_organization('My Organization', 'user_123')
    print(f'Created organization with ID: {org_id}')

    org = org_mgmt.get_organization(org_id)
    print(f'Organization details: {org}')
