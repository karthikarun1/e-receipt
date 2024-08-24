import unittest
import boto3
from botocore.exceptions import ClientError
from moto import mock_dynamodb2
from user_management import UserManager
from permissions_management import PermissionsManager, Permission

class TestUserManagementAndPermissions(unittest.TestCase):
    @mock_dynamodb2
    def setUp(self):
        """Set up DynamoDB and initialize UserManager and PermissionsManager"""
        # Initialize DynamoDB mock
        self.dynamodb = boto3.resource('dynamodb', region_name='us-east-1')

        # Create tables
        self.create_tables()

        # Initialize managers
        self.user_manager = UserManager(self.dynamodb)
        self.permissions_manager = PermissionsManager(self.dynamodb)

    def create_tables(self):
        """Create mock tables"""
        # Create Users table
        self.dynamodb.create_table(
            TableName='Users',
            KeySchema=[
                {'AttributeName': 'id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

        # Create Groups table
        self.dynamodb.create_table(
            TableName='Groups',
            KeySchema=[
                {'AttributeName': 'id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

        # Create UserGroupMembership table
        self.dynamodb.create_table(
            TableName='UserGroupMembership',
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'},
                {'AttributeName': 'group_id', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'},
                {'AttributeName': 'group_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

        # Create Permissions table
        self.dynamodb.create_table(
            TableName='Permissions',
            KeySchema=[
                {'AttributeName': 'user_id', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'user_id', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )

    def test_user_permissions(self):
        """Test adding and checking user permissions"""
        # Add user
        user_id = self.user_manager.register_user('test_user', 'password')
        
        # Add permission
        self.permissions_manager.add_user_permissions(user_id, [Permission.UPLOAD_MODEL])
        
        # Check permissions
        self.assertTrue(self.user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL))
        
        # Remove permission
        self.permissions_manager.remove_user_permissions(user_id, [Permission.UPLOAD_MODEL])
        
        # Check permissions again
        self.assertFalse(self.user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL))

    def test_group_permissions(self):
        """Test adding and checking group permissions"""
        # Add user and group
        user_id = self.user_manager.register_user('test_user', 'password')
        group_id = self.user_manager.create_group('test_group', user_id)
        
        # Add permission to group
        self.permissions_manager.add_group_permissions(group_id, [Permission.UPLOAD_MODEL])
        
        # Add user to group
        self.user_manager.add_user_to_group(user_id, group_id)
        
        # Check permissions
        self.assertTrue(self.user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL))
        
        # Remove permission from group
        self.permissions_manager.remove_group_permissions(group_id, [Permission.UPLOAD_MODEL])
        
        # Check permissions again
        self.assertFalse(self.user_manager.check_model_permission(user_id, Permission.UPLOAD_MODEL))

    def test_user_group_management(self):
        """Test adding and removing users from groups"""
        # Add user and group
        user_id = self.user_manager.register_user('test_user', 'password')
        group_id = self.user_manager.create_group('test_group', user_id)
        
        # Add user to group
        self.user_manager.add_user_to_group(user_id, group_id)
        
        # Check user groups
        user_groups = self.user_manager.get_user_groups(user_id)
        self.assertIn(group_id, user_groups)
        
        # Remove user from group
        self.user_manager.remove_user_from_group(user_id, group_id)
        
        # Check user groups again
        user_groups = self.user_manager.get_user_groups(user_id)
        self.assertNotIn(group_id, user_groups)

if __name__ == '__main__':
    unittest.main()

