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
from org_permissions import OrganizationPermissions
from permissions_management import PermissionsManager
from role_management import RoleManager, Role, Permission
from subscription_management import SubscriptionManager, SubscriptionPlanType
from user_management import UserManager
from org_updates import OrganizationUpdater

# Load environment variables
from config_loader import load_environment
load_environment()

logger = logging.getLogger(__name__)

_AUTHORIZED_ROLES_TO_VIEW_ORGANIZATION_DETAILS = [r.name.lower() for r in Role]

class OrganizationManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.subscription_manager = SubscriptionManager(dynamodb, table_prefix)
        self.role_manager = RoleManager(dynamodb, table_prefix)
        self.user_manager = UserManager(dynamodb, table_prefix)
        self.permissions_manager = PermissionsManager(dynamodb, table_prefix)
        self.updater = OrganizationUpdater(
            self,
            self.user_manager,
 	    self.role_manager,
            dynamodb, 
            self.org_table_name
        )
        self.invitation_manager = InvitationManager(dynamodb, table_prefix)
        self.organization_permissions = OrganizationPermissions(dynamodb, table_prefix)

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
            if not self._is_user_authorized(user_id, organization):
                raise PermissionError("User is not authorized to view this organization's details.")

            # Fetch details of users
            users = []
            for org_user_id in list(organization.get('user_roles', {}).keys()):
                user_response = self.users_table.get_item(Key={'id': org_user_id})
                user = user_response.get('Item')
                if user:
                    users.append({
                        'id': user['id'],
                        'username': user['username'],
                        'email': user['email']
                    })

            # Fetch the roles from the separate 'user_roles' structure
            roles = organization.get('user_roles', {})  # Assuming 'user_roles' is a separate dict in organization

            organization_details = {
                "organization_id": organization['id'],
                "organization_name": organization['org_name'],
                "plan_type": organization.get('plan_type', SubscriptionPlanType.FREE.value),
                "created_at": organization['created_at'],
                "updated_at": organization['updated_at'],
                "users": users,
                "user_roles": roles  # Include roles directly from the separate structure
            }

            return organization_details

        except ClientError as e:
            logging.error(e)
            raise LookupError("An error occurred while retrieving organization details.") from e

    def _is_user_authorized(self, user_id, organization):
        """
        Check if a user has the necessary role to access the organization details.
        Returns True if authorized, False otherwise.
        """
        # Fetch the roles from the separate 'user_roles' structure
        roles = organization.get('user_roles', {})

        # Check if the user has one of the authorized roles
        user_role = roles.get(user_id)
        return user_role in _AUTHORIZED_ROLES_TO_VIEW_ORGANIZATION_DETAILS

    def _get_user_role(self, user_id, organization):
        """
        Get the role of a user within an organization.
        Returns the role as a string.
        """
        # Fetch the roles from the separate 'user_roles' structure
        roles = organization.get('user_roles', {})
        
        # Return the role of the user, or 'member' as default if no role is found
        return roles.get(user_id, "member")

    def create_organization(self, org_name, description, creator_user_id):
        """Creates a new organization and assigns the creator as SuperAdmin."""
        try:
            # Check if an organization with the same org_name already exists
            response = self.org_table.scan(
                FilterExpression="org_name = :org_name",
                ExpressionAttributeValues={':org_name': org_name}
            )
            if response['Items']:
                raise ValueError(f"An organization with the name '{org_name}' already exists.")

            # Create the organization in the database
            org_id = str(uuid.uuid4())
            created_at = str(datetime.utcnow())
            organization_data = {
                'id': org_id,
                'org_name': org_name,
                'created_at': created_at,
                'updated_at': created_at,
                'description': description,  # Default description
                'plan_type': SubscriptionPlanType.FREE.value,  # Default plan type
                'user_roles': {
                    creator_user_id: Role.SUPERADMIN.value  # Assign the creator as SuperAdmin
                }
            }
            self.org_table.put_item(Item=organization_data)

            logger.info(f"Organization '{org_name}' created with ID {org_id} by user {creator_user_id}")

            return org_id

        except Exception as e:
            logger.error(f"Error creating organization {org_name}: {str(e)}")
            raise

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
        """
        Removes a user from the organization and removes their role from the 'user_roles' structure.
        """
        try:
            # Remove the user's role from the 'user_roles' structure
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="REMOVE user_roles.#user_id",
                ExpressionAttributeNames={"#user_id": user_id},
                ReturnValues="UPDATED_NEW"
            )

            logger.info(f"User {user_id} removed from organization {org_id}")

        except ClientError as e:
            logger.error(f"Error removing user {user_id} from organization {org_id}: {e}")
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

        # Check if the requesting user is authorized (either part of the organization or has a role)
        if not self._is_user_authorized(requester_user_id, organization):
            raise PermissionError("User is not authorized to view this organization's users.")

        user_ids = list(organization.get('user_roles', {}).keys())
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
                    'email': user_response.get('email'),
                    'role': self._get_user_role(user_id, organization)  # Fetch the role from the separate roles structure
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
        if len(org.get('user_roles', [])) >= MAX_USERS:
            raise ValueError(f"Organization has reached the maximum user limit of {MAX_USERS}.")

        # Check group limit
        if len(org.get('groups', [])) >= MAX_GROUPS:
            raise ValueError(f"Organization has reached the maximum group limit of {MAX_GROUPS}.")

        return True

    def add_user_to_organization(self, org_id, user_id):
        """
        Adds a user to an organization and assigns a default role.
        """
        # Check limits before adding a user
        self._check_free_plan_limits(org_id)
        
        try:
            # Add the user to the organization
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET users.#user_id = :empty_map",
                ExpressionAttributeNames={"#user_id": user_id},
                ExpressionAttributeValues={':empty_map': {}},  # No additional user info initially
                ReturnValues="UPDATED_NEW"
            )

            # Assign the default role to the user in the 'user_roles' structure (e.g., 'viewer')
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET roles.#user_id = :default_role",
                ExpressionAttributeNames={"#user_id": user_id},
                ExpressionAttributeValues={':default_role': Role.VIEWER.value},  # Default role
                ReturnValues="UPDATED_NEW"
            )

            logger.info(f"User {user_id} added to organization {org_id} with default role {Role.VIEWER.value}")

        except ClientError as e:
            logger.error(f"Error adding user {user_id} to organization {org_id}: {e}")
            raise

    def invite_users(self, org_id, inviter_id, user_ids, invite_type, role):
        return self.invitation_manager.invite_users(
            org_id, inviter_id, user_ids, invite_type, role
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
