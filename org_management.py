import boto3
from botocore.exceptions import ClientError
from uuid import uuid4
from datetime import datetime

# Import setup for DynamoDB from setup_dynamodb.py
from user_management import UserManager
from permissions_management import PermissionsManager
from subscription_management import SubscriptionManager

class OrganizationManager:
    def __init__(self, dynamodb, email_util, table_prefix):
        self.dynamodb = dynamodb
        self.org_table_name = f'{table_prefix}_Organizations'
        self.groups_table_name = f'{table_prefix}_Groups'
        self.users_table_name = f'{table_prefix}_Users'
        self.subscriptions_table_name = f'{table_prefix}_Subscriptions'
        self.invites_table_name = f'{table_prefix}_Invites'
        self.user_management = UserManager(dynamodb, table_prefix)
        self.permissions_management = PermissionsManager(dynamodb, table_prefix)
        self.subscription_management = SubscriptionManager(dynamodb, email_util, table_prefix)

    def create_organization(self, org_name, admin_user_id):
        # Check if the user is subscribed to a team plan
        if not self.subscription_management.is_team_plan(admin_user_id):
            raise PermissionError("User must be subscribed to a team plan to create an organization.")
        
        # Check if the user has admin permissions using PermissionsManager
        if not self.permissions_manager.check_admin_permissions(admin_user_id):
            raise Exception(f"User '{admin_user_id}' does not have permissions to create an organization.")
        
        org_id = str(uuid4())
        table = self.dynamodb.Table(self.organizations_table_name)
        try:
            item = {
                'id': org_id,  # Keeping 'id' consistent as the primary key
                'org_name': org_name,
                'admins': [admin_user_id],  # List of admins
                'users': [admin_user_id],   # List of users, starting with the admin
                'created_at': str(datetime.utcnow()),
                'updated_at': str(datetime.utcnow())
            }
            table.put_item(Item=item)
            print(f"Organization '{org_name}' created successfully with ID: {org_id}.")
            return org_id
        except Exception as e:
            print(f"Error creating organization: {str(e)}")
            return None

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

    def get_organization(self, org_id):
        table = self.dynamodb.Table(self.org_table_name)
        try:
            response = table.get_item(Key={'org_id': org_id})
            return response.get('Item')
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def update_organization(self, org_id, org_name=None):
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
        
        invite_id = str(uuid4())
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

# Example usage:
if __name__ == "__main__":
    org_mgmt = OrganizationManager()
    org_id = org_mgmt.create_organization('My Organization', 'user_123')
    print(f'Created organization with ID: {org_id}')

    org = org_mgmt.get_organization(org_id)
    print(f'Organization details: {org}')
