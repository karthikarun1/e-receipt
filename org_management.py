import boto3
import logging
import os
import uuid

from botocore.exceptions import ClientError
from datetime import datetime, timedelta

from base_management import BaseManager
from invitation_manager_by_email import InvitationManager
from invite_type import InviteType
from role_management import RoleManager, Role, Permission
from subscription_management import SubscriptionManager, SubscriptionPlanType
from user_management import UserManager
from org_updates import OrganizationUpdater
from org_group_management import OrgGroupManager, OrgGroup

# Load environment variables
from config_loader import load_environment
load_environment()

logger = logging.getLogger(__name__)

_AUTHORIZED_ROLES_TO_VIEW_ORGANIZATION_DETAILS = [r.name.lower() for r in Role]

class OrganizationManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.subscription_manager = SubscriptionManager()
        self.role_manager = RoleManager()
        self.user_manager = UserManager()
        self.org_group_manager = OrgGroupManager()
        self.updater = OrganizationUpdater(
            self,
            self.user_manager,
 	    self.role_manager,
        )
        self.invitation_manager = InvitationManager()

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
        """
        Fetch the details of an organization, including user roles, group roles, and permissions.
        """
        try:
            # Step 1: Fetch the organization from the Organizations table
            response = self.org_table.get_item(Key={'org_id': org_id})
            org = response.get('Item')

            if not org:
                raise ValueError(f"Organization with id {org_id} not found.")
            
            # Step 2: Get user's individual role in the organization (if applicable)
            user_role = org.get('user_roles', {}).get(user_id)
            
            # Step 3: Fetch all groups for this organization
            groups = self.org_group_manager.list_groups_in_organization(org_id, user_id)

            # Step 4: Check if the user belongs to any group and inherit the group's role
            group_role = None
            for group in groups:
                if user_id in group['users']:
                    group_role = group.get('role')
                    break

            # Step 5: Combine user role and group role (if both exist, individual role takes precedence)
            effective_role = user_role or group_role

            # Step 6: Return organization details along with the effective role
            org_details = {
                'org_id': org_id,
                'org_name': org['org_name'],
                'description': org['description'],
                'plan_type': org['plan_type'],
                'created_at': org['created_at'],
                'updated_at': org['updated_at'],
                'effective_role': effective_role,  # User's effective role (individual or group)
                'groups': groups  # List of groups in the organization
            }

            return org_details

        except Exception as e:
            logger.error(f"Failed to get organization details for org_id {org_id}: {e}")
            raise

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
        """
        Create a new organization and automatically assign the creator to a 'superadmin' group.
        """
        try:
            # Step 1: Create the organization
            org_id = str(uuid.uuid4())
            created_at = str(datetime.utcnow())
            org_data = {
                'id': org_id,
                'org_name': org_name,
                'description': description,
                'plan_type': SubscriptionPlanType.FREE.value,  # Using SubscriptionType enum
                'created_at': created_at,
                'created_by': creator_user_id,
                'updated_at': created_at,
                'user_roles': {}  # Will be phased out with group roles
            }
            
            # Save organization to the Organizations table
            self.org_table.put_item(Item=org_data)

            # Step 2: Create a default 'Org Super Admins' group using enum
            self.org_group_manager.create_group(org_id, OrgGroup.ORG_SUPERADMIN.value, creator_user_id, is_org_creation=True)
            
            # Step 3: Assign the 'superadmin' role to the group
            # No need to do this as in org_group_manager.create_group we explicitly add
            # Role.ORG_SUPERADMIN to the group that is created
            #self.org_group_manager.assign_role_to_group(org_id, group_id, Role.ORG_SUPERADMIN, creator_user_id, is_org_creation=True)
            
            # Step 4: Add the creator to the 'Org Super Admins' group
            # No need to do this as in org_group_manager.create_group we explicitly add the creator
            # to the group
            #self.org_group_manager.add_user_to_group(org_id, group_id, creator_user_id, creator_user_id)

            return org_id
        
        except Exception as e:
            logger.error(f"Failed to create organization: {e}")
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

    def get_users_with_roles(self, requesting_user_id, org_id):
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            organization = response.get('Item')
            if not organization:
                raise ValueError("Organization not found.")
            
            roles = organization.get('user_roles', {})
            user_ids = list(roles.keys())
            if requesting_user_id not in user_ids:
                raise PermissionError("You don't have permission to view this org.")

            user_with_roles = {}
            for user_id, role in roles.items():
                user = self.user_manager.get_user_details_by_id(user_id)
                username = user['username']
                key = f'{user_id} - {username}'
                user_with_roles[key] = role
            return user_with_roles
        except Exception as e:
            logger.error(f"Error retrieving users for organization: {str(e)}")
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
                UpdateExpression="SET user_roles.#user_id = :default_role",
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
