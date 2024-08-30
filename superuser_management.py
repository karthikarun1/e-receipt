import click
import getpass
import os

import dynamodb_utils

from user_management import UserManager  # Replace with the actual path to your UserManager

# load environment variables
from config_loader import load_environment
load_environment()

TABLE_PREFIX = os.getenv('TABLE_PREFIX')

dynamodb_resource = dynamodb_utils.get_dynamodb_resource()

def register_superuser_command(app):
    @app.cli.command("make-superuser")
    @click.argument("email")
    def make_superuser(email):
        user_manager = UserManager(dynamodb_resource, TABLE_PREFIX)
    
        # Retrieve the user by email
        user = user_manager.get_user_details_by_email(email)
        if not user:
            print(f"User with email {email} not found.")
            return
    
        # Check if the email is verified
        if not user.get('verified', False):
            print(f"Cannot make user a superuser. The email {email} is not verified.")
            return
    
        # Confirmation prompt
        confirmation = input(f"Are you sure you want to make {email} a superuser? (yes/no): ")
        if confirmation.lower() != "yes":
            print("Operation canceled.")
            return
    
        # Password prompt for the person executing the command
        executor_password = getpass.getpass("Enter your password to confirm this action: ")
    
        # Verify executor's password (Assuming the executor is logged in and we have their user_id)
        executor_user_id = os.getenv('CURRENT_USER_ID') 
        executor_user = user_manager.get_user_details_by_id(executor_user_id)
    
        if not user_manager._check_password(executor_password, executor_user['password']):
            print("Password is incorrect. Operation aborted.")
            return
    
        # Grant superuser status
        # Set the user as a superuser in the database
        user_id = user['id']
        user_manager.users_table.update_item(
            Key={'id': user_id},
            UpdateExpression="SET superuser = :superuser",
            ExpressionAttributeValues={':superuser': True}
        )
        print(f"User {email} is now a superuser.")
