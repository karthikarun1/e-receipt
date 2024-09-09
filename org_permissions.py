import logging
from enum import Enum
from botocore.exceptions import ClientError
from role_management import Role, Permission

logger = logging.getLogger(__name__)


class OrganizationPermissions:
    def __init__(self, dynamodb, table_prefix):
        self.dynamodb = dynamodb
        self.table_prefix = table_prefix
        self.org_table = f"{table_prefix}_Organizations"
        self.users_table = f"{table_prefix}_Users"
        
    def assign_role(self, org_id, user_id, role: Role):
        """Assign a role to a user in the organization."""
        current_role = self.get_user_role(org_id, user_id)
        if current_role == role.value:
            raise ValueError(f"User {user_id} is already a {role.value} in the organization.")
        
        if not self.is_user_organization_admin(org_id, get_current_user_id()) and not self.is_user_superadmin(get_current_user_id()):
            raise PermissionError("Only OrganizationAdmins or SuperAdmins can assign roles.")
        
        self._update_user_role(org_id, user_id, role.value)
    
    def is_user_organization_admin(self, org_id, user_id):
        """Check if a user is an OrganizationAdmin in the organization."""
        org = self._get_org(org_id)
        return user_id in org.get('admins', [])
    
    def is_user_superadmin(self, user_id):
        """Check if a user is a SuperAdmin."""
        user = self._get_user(user_id)
        return user.get('role') == Role.SUPERADMIN.value
    
    def check_user_permission(self, org_id, user_id, permission: Permission):
        """Check if a user has permission to perform a specific action based on their role."""
        role = self.get_user_role(org_id, user_id)
        if role == Role.SUPERADMIN.value:
            return True  # SuperAdmins have all permissions
        elif role == Role.ORGANIZATION_ADMIN.value:
            return permission in [
                Permission.UPLOAD_MODEL.value,
                Permission.LIST_MODELS.value,
                Permission.REMOVE_MODEL.value,
                Permission.MANAGE_USERS.value
            ]
        elif role == Role.CONTRIBUTOR.value:
            return permission in [
                Permission.UPLOAD_MODEL.value,
                Permission.LIST_MODELS.value,
                Permission.REMOVE_MODEL.value
            ]
        elif role == Role.VIEWER.value:
            return permission in [Permission.LIST_MODELS.value, Permission.DOWNLOAD_MODEL.value]
        else:
            return False

    def promote_user_to_organizationadmin(self, org_id, user_id):
        """Promote a regular user (contributor/viewer) to OrganizationAdmin."""
        if self.is_user_organization_admin(org_id, user_id):
            raise ValueError(f"User {user_id} is already an OrganizationAdmin.")
        
        if self.is_user_superadmin(user_id):
            raise ValueError(f"User {user_id} is a SuperAdmin and does not need promotion to OrganizationAdmin.")
        
        # Update the user role to OrganizationAdmin
        self._update_user_role(org_id, user_id, Role.ORGANIZATION_ADMIN.value)

    def promote_user_to_superadmin(self, user_id):
        """Promote a regular user (contributor/viewer) to SuperAdmin."""
        if self.is_user_superadmin(user_id):
            raise ValueError(f"User {user_id} is already a SuperAdmin.")
        
        # Update the user role to SuperAdmin
        self._update_user_to_superadmin(user_id)

    def promote_organizationadmin_to_superadmin(self, org_id, user_id):
        """Promote an OrganizationAdmin to SuperAdmin."""
        if not self.is_user_organization_admin(org_id, user_id):
            raise ValueError(f"User {user_id} is not an OrganizationAdmin and cannot be promoted to SuperAdmin.")
        
        if self.is_user_superadmin(user_id):
            raise ValueError(f"User {user_id} is already a SuperAdmin.")
        
        # Update the user role to SuperAdmin
        self._update_user_to_superadmin(user_id)

    def demote_organizationadmin_to_user(self, org_id, user_id, new_role: Role = Role.CONTRIBUTOR):
        """Demote an OrganizationAdmin to a regular user (contributor/viewer)."""
        org = self._get_org(org_id)
        if len(org.get('admins', [])) <= 1:
            raise ValueError("Cannot remove the last OrganizationAdmin in the organization.")
        
        # Demote to the specified regular user role
        self.assign_role(org_id, user_id, new_role)

    def demote_superadmin_to_organizationadmin(self, org_id, user_id):
        """Demote a SuperAdmin to OrganizationAdmin in a specific organization."""
        if not self.is_user_superadmin(user_id):
            raise ValueError(f"User {user_id} is not a SuperAdmin and cannot be demoted.")
        
        # Demote to OrganizationAdmin
        self._update_user_role(org_id, user_id, Role.ORGANIZATION_ADMIN.value)

    def demote_superadmin_to_user(self, user_id, new_role: Role = Role.CONTRIBUTOR):
        """Demote a SuperAdmin to a regular user (contributor/viewer)."""
        if not self.is_user_superadmin(user_id):
            raise ValueError(f"User {user_id} is not a SuperAdmin and cannot be demoted.")
        
        # Update the user role to the new regular user role
        self._update_superadmin_to_user(user_id, new_role.value)

    # Helper function to update user role to SuperAdmin
    def _update_user_to_superadmin(self, user_id):
        """Internal helper to promote a user to SuperAdmin."""
        user = self._get_user(user_id)
        user['role'] = Role.SUPERADMIN.value
        self._save_user(user_id, user)

    # Helper function to update SuperAdmin to a regular user role
    def _update_superadmin_to_user(self, user_id, role):
        """Internal helper to demote a SuperAdmin to a regular user role."""
        user = self._get_user(user_id)
        if user.get('role') != Role.SUPERADMIN.value:
            raise ValueError(f"User {user_id} is not a SuperAdmin.")
        
        user['role'] = role
        self._save_user(user_id, user)

    def _save_user(self, user_id, user):
        """Save the updated user record to DynamoDB."""
        table = self.dynamodb.Table(self.users_table)
        try:
            table.put_item(Item=user)
        except ClientError as e:
            logger.error(f"Error saving user {user_id}: {e}")
            raise

    
    def remove_user(self, org_id, user_id):
        """Remove a user from the organization."""
        if self.is_user_organization_admin(org_id, user_id):
            self.demote_admin_to_user(org_id, user_id)
        
        self._remove_user_from_org(org_id, user_id)
    
    def get_user_role(self, org_id, user_id):
        """Retrieve the role of a user in the organization."""
        org = self._get_org(org_id)
        if user_id in org.get('admins', []):
            return Role.ORGANIZATION_ADMIN.value
        elif user_id in org.get('contributors', []):
            return Role.CONTRIBUTOR.value
        elif user_id in org.get('viewers', []):
            return Role.VIEWER.value
        # SuperAdmin is checked globally
        if self.is_user_superadmin(user_id):
            return Role.SUPERADMIN.value
        return None
    
    def list_users_with_roles(self, org_id):
        """List all users in the organization along with their roles."""
        org = self._get_org(org_id)
        admins = org.get('admins', [])
        contributors = org.get('contributors', [])
        viewers = org.get('viewers', [])
        return {"admins": admins, "contributors": contributors, "viewers": viewers}
    
    def _update_user_role(self, org_id, user_id, role):
        """Update a user's role in the organization."""
        org = self._get_org(org_id)
        # Remove user from all roles
        org['admins'] = [uid for uid in org.get('admins', []) if uid != user_id]
        org['contributors'] = [uid for uid in org.get('contributors', []) if uid != user_id]
        org['viewers'] = [uid for uid in org.get('viewers', []) if uid != user_id]
        
        # Add user to the new role
        if role == Role.ORGANIZATION_ADMIN.value:
            org['admins'].append(user_id)
        elif role == Role.CONTRIBUTOR.value:
            org['contributors'].append(user_id)
        elif role == Role.VIEWER.value:
            org['viewers'].append(user_id)
        else:
            raise ValueError(f"Invalid role {role} specified.")
        
        self._save_org(org_id, org)
    
    def _remove_user_from_org(self, org_id, user_id):
        """Remove a user from the organization."""
        org = self._get_org(org_id)
        # Remove the user from all roles
        org['admins'] = [uid for uid in org.get('admins', []) if uid != user_id]
        org['contributors'] = [uid for uid in org.get('contributors', []) if uid != user_id]
        org['viewers'] = [uid for uid in org.get('viewers', []) if uid != user_id]
        
        self._save_org(org_id, org)
    
    def _get_org(self, org_id):
        """Retrieve the organization record from DynamoDB."""
        table = self.dynamodb.Table(self.org_table)
        try:
            response = table.get_item(Key={'id': org_id})
            return response.get('Item', {})
        except ClientError as e:
            logger.error(f"Error fetching organization {org_id}: {e}")
            raise
    
    def _get_user(self, user_id):
        """Retrieve the user record from DynamoDB."""
        table = self.dynamodb.Table(self.users_table)
        try:
            response = table.get_item(Key={'id': user_id})
            return response.get('Item', {})
        except ClientError as e:
            logger.error(f"Error fetching user {user_id}: {e}")
            raise

    def _save_org(self, org_id, org):
        """Save the updated organization record to DynamoDB."""
        table = self.dynamodb.Table(self.org_table)
        try:
            table.put_item(Item=org)
        except ClientError as e:
            logger.error(f"Error saving organization {org_id}: {e}")
            raise
