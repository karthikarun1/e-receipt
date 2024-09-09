import logging
from base_management import BaseManager
from user_management import UserManager
from org_management import OrganizationManager
from role_management import RoleManager, Role

class UserRemovalManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.user_manager = UserManager(dynamodb, table_prefix)
        self.org_manager = OrganizationManager(dynamodb, table_prefix)
        self.role_manager = RoleManager(dynamodb, table_prefix)
        self.logger = logging.getLogger(__name__)

    def remove_user(self, admin_id, org_id, username_or_email):
        """
        Remove a user from an organization with comprehensive checks.

        Args:
            admin_id (str): The admin performing the removal.
            org_id (str): The organization ID.
            username_or_email (str): The username or email of the user to remove.
        
        Raises:
            ValueError: If there are any issues with the inputs or user state.
        Returns:
            dict: A message indicating the success of the removal.
        """
        # Get organization details
        organization = self.org_manager.get_organization_by_id(org_id)

        # Verify that the user performing the action is a superadmin or admin of the organization
        if not self.role_manager.is_orgadmin_or_superadmin(org_id, admin_id):
            raise PermissionError("You do not have the necessary permissions to remove users.")

        # Retrieve user details by username or email
        user = self._get_user_by_username_or_email(username_or_email)
        if not user:
            raise ValueError(f"User '{username_or_email}' not found.")

        user_id = user['id']
        username = user['username']

        # Ensure the user is part of the organization
        if user_id not in organization['user_roles']:
            raise ValueError(f"User '{username}' is not a member of the organization.")

        # Prevent admin from removing themselves
        if admin_id == user_id:
            raise ValueError("You cannot remove yourself from the organization.")

        # Get the role of the user being removed
        user_role = Role(organization['user_roles'][user_id])
        
        # Get the role of the admin performing the removal
        admin_role = Role(organization['user_roles'][admin_id])

        # Ensure an organization admin cannot remove a superadmin or organization admin
        # only a superadmin should be able to do that.
        if admin_role != Role.SUPERADMIN:
            if user_role == Role.ORGANIZATION_ADMIN:
                raise PermissionError("Only a superadmin can remove a organization admin.")
            if user_role == Role.SUPERADMIN:
                raise PermissionError("Only a superadmin can remove another superadmin.")

        # Remove the user from the organization
        self.org_manager.remove_user_from_organization(org_id, user_id)

        # Send notification email to the user (optional)
        self._notify_user(user['email'], organization['org_name'])

        # Log the removal
        self.logger.info(f"User '{username}' (email: {user['email']}) was removed from organization '{organization['org_name']}' by admin {admin_id}.")

        return {"message": f"User '{username}' was successfully removed from the organization."}

    def _get_user_by_username_or_email(self, username_or_email):
        """Helper function to retrieve user by username or email."""
        user = self.user_manager.get_user_details_by_username(username_or_email)
        if not user:
            user = self.user_manager.get_user_details_by_email(username_or_email)
        return user

    def _notify_user(self, email, org_name):
        """Send an email notification to the user informing them they've been removed."""
        subject = f"Removed from Organization: {org_name}"
        body = f"You have been removed from the organization '{org_name}'. If you have any questions, please contact the admin."
        self.email_util.send_email(email, subject, body)
