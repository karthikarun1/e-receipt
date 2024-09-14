import logging
from enum import Enum
from base_management import BaseManager
from botocore.exceptions import ClientError
from user_management import UserManager
from email_util import EmailUtil

logger = logging.getLogger(__name__)

class Role(Enum):
    ORG_SUPERADMIN = 'org_superadmin'
    ORG_ADMIN = 'org_admin'
    CONTRIBUTOR = 'contributor'
    VIEWER = 'viewer'

class Permission(Enum):
    UPLOAD_MODEL = 'upload_model'
    LIST_MODELS = 'list_models'
    REMOVE_MODEL = 'remove_model'
    DOWNLOAD_MODEL = 'download_model'
    MANAGE_USERS = 'manage_users'

_ADMIN_ROLES = [Role.ORG_SUPERADMIN, Role.ORG_ADMIN]

class RoleManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.user_manager = UserManager()

    def change_user_role(self, org_id, user_id, requesting_user_id, new_role: Role):
        """Changes user role after checks.

        Args:
           org_id: id of the organization.
           user_id: The user whose role needs to be changed.
           requesting_user_id: The user who is initiating this role change.
           new_role: The string representing the new_role for the user whose role is changed.
        """
        
        from notification_manager import NotificationManager

        try:
            current_role = Role(self._get_user_role(org_id, user_id))
            requesting_user_role = Role(self._get_user_role(org_id, requesting_user_id))

            user = self.user_manager.get_user_details_by_id(user_id)
            if not user:
                raise ValueError(f'No user found for user_id {user_id}')

            requesting_user = self.user_manager.get_user_details_by_id(requesting_user_id)
            if not requesting_user:
                raise ValueError(f'No requesting user found for requesting_user_id {requesting_user_id}')

            organization = self._get_organization(org_id)

            # Run the necessary validation checks
            self._sanity_check(requesting_user_role, current_role, new_role)
            self._check_self_promotion(user_id, requesting_user_id)

            # Prevent demotion of the last Admins
            self._prevent_last_superadmin_demotion(org_id, current_role, new_role)
            self._prevent_last_orgadmin_demotion(org_id, current_role, new_role, requesting_user_role)

            # Update the user's role in the 'user_roles' structure
            self._update_user_role(org_id, user_id, new_role)

            user_email = user['email']
            NotificationManager(EmailUtil).send_role_change_notification(
                user_email=user_email,
                new_role=new_role,
                org_name=organization['org_name']
            )

            logger.info(f"User {user_id} role changed to {new_role} by {requesting_user_id}")

            username = user['username']
            return f"User {username}'s role updated to {new_role}."

        except Exception as e:
            logger.error(f"Error changing user role for user {user_id} in organization {org_id}: {e}")
            raise

    def _sanity_check(self, requesting_user_role, current_role, new_role):

        if requesting_user_role not in _ADMIN_ROLES:
            raise PermissionError("You don't have permissions to do role change.")

        if ((current_role == Role.ORG_SUPERADMIN or new_role == Role.ORG_SUPERADMIN) and (requesting_user_role != Role.ORG_SUPERADMIN)):
            raise PermissionError("Only SuperAdmins can promote to or demote from SuperAdmin.")

        if ((current_role == Role.ORG_ADMIN or new_role == Role.ORG_ADMIN) and (requesting_user_role != Role.ORG_SUPERADMIN)):
            raise PermissionError("Only SuperAdmins can promote to or demote from OrganizationAdmin.")

        if current_role == new_role:
            raise ValueError('No role change detected.')

    def _get_organization(self, org_id):
        """
        Retrieve the organization data by org_id.
        """
        response = self.org_table.get_item(Key={'id': org_id})
        organization = response.get('Item')
        if not organization:
            raise ValueError(f'No organization found for org_id {org_id}')
        return organization

    def _check_self_promotion(self, user_id, requesting_user_id):
        """
        Prevent self-promotion or self-demotion.
        """
        if user_id == requesting_user_id:
            raise PermissionError("You cannot change your own role.")

    def _prevent_last_superadmin_demotion(self, org_id, current_role, new_role):
        """
        Prevent demotion of the last SuperAdmin.
        """
        if current_role == Role.ORG_SUPERADMIN and new_role != Role.ORG_SUPERADMIN:
            if self._is_last_role(org_id, Role.ORG_SUPERADMIN):
                raise ValueError("Cannot demote the last SuperAdmin.")

    def _prevent_last_orgadmin_demotion(self, org_id, current_role, new_role, requesting_user_role):
        """
        Prevent demotion of the last OrganizationAdmin, unless the action is performed by a SuperAdmin.
        """
        if current_role == Role.ORG_ADMIN and new_role != Role.ORG_ADMIN:
            # Allow SuperAdmins to demote the last OrganizationAdmin
            if requesting_user_role == Role.ORG_SUPERADMIN:
                return  # SuperAdmins can demote the last OrganizationAdmin

            if self._is_last_role(org_id, Role.ORG_ADMIN):
                raise ValueError("Cannot demote the last OrganizationAdmin in the organization.")

    def _update_user_role(self, org_id, user_id, new_role):
        """
        Update the user's role in the 'user_roles' structure of the organization.
        """
        self.org_table.update_item(
            Key={'id': org_id},
            UpdateExpression="SET user_roles.#user_id = :new_role",
            ExpressionAttributeNames={"#user_id": user_id},
            ExpressionAttributeValues={':new_role': new_role.value},
            ReturnValues="UPDATED_NEW"
        )

    def is_orgadmin_or_superadmin(self, org_id, user_id):
        """
        Check if a user has the OrganizationAdmin or SuperAdmin role in the 'user_roles' structure.
        """
        # Fetch the user's role from the organization
        user_role = Role(self._get_user_role(org_id, user_id))

        # Check if the user's role is either OrganizationAdmin or SuperAdmin
        return user_role in [Role.ORG_ADMIN, Role.ORG_SUPERADMIN]

    def check_user_permission(self, org_id, user_id, permission: Permission):
        """
        Check if a user has the necessary permissions based on their role in the 'user_roles' structure.
        """
        # Fetch the user's role from the organization
        role = self._get_user_role(org_id, user_id)

        # SuperAdmins have all permissions
        if role == Role.ORG_SUPERADMIN:
            return True

        # Define role-based permissions
        role_permissions = {
            Role.ORG_ADMIN: [
                Permission.UPLOAD_MODEL,
                Permission.LIST_MODELS,
                Permission.REMOVE_MODEL,
                Permission.MANAGE_USERS
            ],
            Role.CONTRIBUTOR: [
                Permission.UPLOAD_MODEL,
                Permission.LIST_MODELS,
                Permission.REMOVE_MODEL
            ],
            Role.VIEWER: [
                Permission.LIST_MODELS,
                Permission.DOWNLOAD_MODEL
            ]
        }

        # Check if the user's role has the required permission
        return permission in role_permissions.get(role, [])

    def _get_user_role(self, org_id, user_id):
        """
        Retrieve the current role of the user in the organization from the 'user_roles' structure.
        Returns the role as a string.
        """
        try:
            # Fetch the organization data
            response = self.org_table.get_item(Key={'id': org_id})
            if 'Item' not in response:
                raise ValueError(f"Organization {org_id} does not exist.")

            organization = response['Item']
            roles = organization.get('user_roles', {})

            # Return the role for the specific user within the organization
            return roles.get(user_id, Role.VIEWER)  # Default to "member" if no role is found

        except ClientError as e:
            logger.error(f"Error fetching user role for {user_id} in organization {org_id}: {e}")
            raise

    def _organization_exists(self, org_id):
        """Check if the organization exists in the database."""
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            return 'Item' in response
        except ClientError as e:
            logger.error(f"Error checking organization existence: {e}")
            return False

    def _update_user_role_bak(self, org_id, user_id, new_role):
        """
        Update the user's role in the 'user_roles' structure of the organization.
        """
        try:
            # Update the role in the organization
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET user_roles.#user_id = :new_role",
                ExpressionAttributeNames={"#user_id": user_id},
                ExpressionAttributeValues={':new_role': new_role},
                ReturnValues="UPDATED_NEW"
            )

            logger.info(f"User {user_id} role updated to {new_role} in organization {org_id}")

        except ClientError as e:
            logger.error(f"Error updating user role in organization {org_id}: {e}")
            raise

    def _is_user_in_organization(self, org_id, user_id):
        """Check if the user is part of the organization."""
        response = self.org_table.get_item(Key={'id': org_id})
        user_ids = list(response['Item'].get('user_roles', {}).keys())
        return user_id in user_ids

    def _validate_role_change(self, current_role, new_role, org_id=None, requesting_user_id=None):
        """Validate if the role change is allowed."""
        if current_role == Role.ORG_SUPERADMIN and new_role != Role.ORG_SUPERADMIN:
            if self._is_last_role(org_id, Role.ORG_SUPERADMIN):
                raise ValueError("Cannot demote the last SuperAdmin")

        # Check if the user is already in the target role
        if current_role == new_role:
            raise ValueError(f"User is already a {new_role}")

        # Check if trying to demote the last OrganizationAdmin in the organization
        if current_role == Role.ORG_ADMIN and new_role != Role.ORG_ADMIN:
            if self._is_last_role(org_id, Role.ORG_ADMIN):
                raise ValueError("Cannot demote the last OrganizationAdmin in the organization")

        # Ensure only SuperAdmins can change roles to/from SuperAdmin
        if new_role == Role.ORG_SUPERADMIN or current_role == Role.ORG_SUPERADMIN:
            requesting_user_role = self._get_user_role(requesting_user_id)
            if requesting_user_role != Role.ORG_SUPERADMIN:
                raise PermissionError("Only SuperAdmins can promote or demote SuperAdmins")


    def _is_last_role(self, org_id, role: Role):
        """Check if the current user is the last one with a specific role (e.g., SuperAdmin, OrganizationAdmin) in the organization."""
        try:
            response = self.org_table.get_item(Key={'id': org_id})
            organization = response.get('Item', {})
            
            # Get all user roles within the organization
            user_roles = organization.get('user_roles', {})
            
            # Count how many users have the specified role
            role_count = sum(1 for user_role in user_roless() if user_role == role)
            
            # Check if there's only one user left with the specified role
            return role_count == 1
        
        except ClientError as e:
            logger.error(f"Error checking for last {role} in organization {org_id}: {e}")
            raise
