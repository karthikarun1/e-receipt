import logging
import uuid
from datetime import datetime
from enum import Enum
from base_management import BaseManager
from role_management import Role, RoleManager

logger = logging.getLogger(__name__)

class OrgGroup(Enum):
    ORG_SUPERADMIN = "Org Super Admins"
    ORG_ADMIN = "Org Admins"

class OrgGroupManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.dynamodb = dynamodb
        self.role_manager = RoleManager(dynamodb, table_prefix)

class OrgGroupManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.dynamodb = dynamodb
        self.role_manager = RoleManager(dynamodb, table_prefix)

class OrgGroupManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.dynamodb = dynamodb
        self.role_manager = RoleManager(dynamodb, table_prefix)
        self.org_table = dynamodb.Table(f'{table_prefix}_Organizations')  # Assuming the organization table

    def create_group(self, org_id, group_name, creator_user_id, is_org_creation=False):
        """
        Create a new group in the organization, automatically add the creator to the group, 
        and link the group to the organization.

        :param org_id: ID of the organization
        :param group_name: Name of the group to be created
        :param creator_user_id: ID of the user creating the group
        :param is_org_creation: Flag to indicate if this is during organization creation
        :return: group_id of the newly created group
        """
        try:
            # Step 1: If not during org creation, check if creator has the necessary permissions
            if not is_org_creation:
                if not self.role_manager.is_orgadmin_or_superadmin(org_id, creator_user_id):
                    raise PermissionError("You don't have permission to create a group.")
            
            # Step 2: Create the group
            group_id = str(uuid.uuid4())
            created_at = str(datetime.utcnow())
            
            # Create group data with the creator added to the group
            group_data = {
                'id': group_id,
                'org_id': org_id,
                'group_name': group_name,
                'created_at': created_at,
                'created_by': creator_user_id,
                'updated_at': created_at,
                'users': [creator_user_id],  # Add creator to the group initially
                'role': Role.ORG_SUPERADMIN.value  # Assign the 'superadmin' role immediately
            }
            
            # Save the group to the Groups table
            self.groups_table.put_item(Item=group_data)
            
            # Step 3: Link the group to the organization
            self.org_table.update_item(
                Key={'id': org_id},
                UpdateExpression="SET groups = list_append(if_not_exists(groups, :empty_list), :group_id)",
                ExpressionAttributeValues={
                    ':group_id': [group_id],  # Append the newly created group
                    ':empty_list': []  # Handle case where 'groups' attribute doesn't exist
                }
            )

            logger.info(f"Group {group_name} created in organization {org_id} by user {creator_user_id}")

            return group_id

        except Exception as e:
            logger.error(f"Failed to create group: {e}")
            raise

    def add_user_to_group(self, org_id, group_id, user_id, actor_user_id):
        """Add a user to a group"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to add users to this group.")
            
            group = self.get_group_by_id(org_id, group_id)

            if user_id in group['users']:
                raise ValueError("User already in group.")
            
            group['users'].append(user_id)
            self.groups_table.update_item(
                Key={'group_id': group_id},
                UpdateExpression="SET users = :users, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':users': group['users'],
                    ':updated_at': str(datetime.utcnow())
                }
            )
            logger.info(f"User {user_id} added to group {group_id} in organization {org_id}")
        except Exception as e:
            logger.error(f"Failed to add user to group: {e}")
            raise

    def remove_user_from_group(self, org_id, group_id, user_id, actor_user_id):
        """Remove a user from a group"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to remove users from this group.")
            
            group = self.get_group_by_id(org_id, group_id)

            if user_id not in group['users']:
                raise ValueError("User not found in group.")
            
            group['users'].remove(user_id)
            self.groups_table.update_item(
                Key={'group_id': group_id},
                UpdateExpression="SET users = :users, updated_at = :updated_at",
                ExpressionAttributeValues={
                    ':users': group['users'],
                    ':updated_at': str(datetime.utcnow())
                }
            )
            logger.info(f"User {user_id} removed from group {group_id} in organization {org_id}")
        except Exception as e:
            logger.error(f"Failed to remove user from group: {e}")
            raise

    def assign_role_to_group(self, org_id, group_id, role, actor_user_id, is_org_creation=False):
        """Assign a role to a group"""
        print (f'---------artg 10: org_id, {org_id}, group_id, {group_id}, role, {role}, actor_user_id, {actor_user_id}, is_org_creation, {is_org_creation}')
        try:
            if not is_org_creation:
                # Check if actor has permission
                if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                    raise PermissionError("You don't have permission to assign a role to this group.")
            
            group = self.get_group_by_id(org_id, group_id)
            
            if not isinstance(role, Role):
                raise ValueError("Invalid role assignment.")
            
            group['role'] = role.value
            self.groups_table.update_item(
                Key={
                    'org_id': org_id,  # Partition key
                    'id': group_id     # Sort key
                },
                UpdateExpression="SET #role = :role, updated_at = :updated_at",
                ExpressionAttributeNames={
                    '#role': 'role'  # Use an alias for the reserved keyword
                },
                ExpressionAttributeValues={
                    ':role': role.value,
                    ':updated_at': str(datetime.utcnow())
                }
            )
            logger.info(f"Role {role} assigned to group {group_id} in organization {org_id}")
        except Exception as e:
            logger.error(f"Failed to assign role to group: {e}")
            raise

    def update_group_role(self, org_id, group_id, new_role, actor_user_id):
        """Update the role of a group"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to update the group's role.")
            
            self.assign_role_to_group(org_id, group_id, new_role, actor_user_id)
            logger.info(f"Role updated for group {group_id} in organization {org_id}")
        except Exception as e:
            logger.error(f"Failed to update group role: {e}")
            raise

    def list_users_in_group(self, org_id, group_id, actor_user_id):
        """List all users in a group"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to view users in this group.")
            
            group = self.get_group_by_id(org_id, group_id)
            return group['users']
        except Exception as e:
            logger.error(f"Failed to list users in group: {e}")
            raise

    def delete_group(self, org_id, group_id, actor_user_id):
        """Delete a group from an organization"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to delete this group.")
            
            self.groups_table.delete_item(Key={'group_id': group_id})
            logger.info(f"Group {group_id} deleted from organization {org_id}")
        except Exception as e:
            logger.error(f"Failed to delete group: {e}")
            raise

    def list_groups_in_organization(self, org_id, actor_user_id):
        """List all groups in an organization"""
        try:
            # Check if actor has permission
            if not self.role_manager.is_orgadmin_or_superadmin(org_id, actor_user_id):
                raise PermissionError("You don't have permission to list groups in this organization.")
            
            response = self.groups_table.scan(
                FilterExpression="id = :org_id",
                ExpressionAttributeValues={":org_id": org_id}
            )
            groups = response.get('Items', [])
            return groups
        except Exception as e:
            logger.error(f"Failed to list groups in organization: {e}")
            raise

    def get_group_by_id(self, org_id, group_id):
        """
        Retrieve a group by its ID and organization ID.
        :param org_id: The ID of the organization.
        :param group_id: The ID of the group.
        :return: Group data if found, otherwise raises ValueError.
        """
        try:
            # Query using both the org_id (partition key) and id (sort key)
            response = self.groups_table.get_item(Key={
                'org_id': org_id,
                'id': group_id  # 'id' is the sort key
            })
            group = response.get('Item')
            if not group:
                raise ValueError(f"Group {group_id} not found in organization {org_id}.")
            return group
        except Exception as e:
            logger.error(f"Failed to retrieve group {group_id}: {e}")
            raise
