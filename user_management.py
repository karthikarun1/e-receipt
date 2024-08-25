import bcrypt
import jwt
import hashlib
import os
import uuid
import time
import re
import traceback
import traceback
import utils

from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from permissions_management import PermissionsManager, Permission
from boto3.dynamodb.conditions import Key  # Add this import statement
from datetime import datetime, timedelta
from email_util import EmailUtil
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

PASSWORD_RESET_TOKEN_VALIDITY_SECONDS = os.getenv('PASSWORD_RESET_TOKEN_VALIDITY_SECONDS')
LOGIN_VALIDITY_SECONDS = os.getenv('LOGIN_VALIDITY_SECONDS')


class UserManager:
    def __init__(self, dynamodb, table_prefix):

        self.dynamodb = dynamodb
        self.email_util = EmailUtil()  # Initialize EmailUtil

        self.username_index = 'username-index'
        self.email_index = 'email-index'
        self.permissions_manager = PermissionsManager(dynamodb, table_prefix)

        self.users_table = dynamodb.Table(f'{table_prefix}_Users')
        self.groups_table = dynamodb.Table(f'{table_prefix}_Groups')
        self.user_group_membership_table = dynamodb.Table(f'{table_prefix}_UserGroupMembership')
        self.verification_table = dynamodb.Table(f'{table_prefix}_EmailVerification')
        self.reset_tokens_table = dynamodb.Table(f'{table_prefix}_ResetTokens')
        self.revoked_tokens_table = dynamodb.Table(f'{table_prefix}_RevokedTokens')
        self.jwt_secret = os.getenv('JWT_SECRET')

    def _hash_password(self, password):
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _check_password(self, password, hashed_password):
        """Check if the provided password matches the hashed password."""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    def _username_exists(self, username):
        """Check if a username already exists."""
        response = self.users_table.query(
            IndexName=self.username_index,
            KeyConditionExpression=Key('username').eq(username)
        )
        return len(response.get('Items', [])) > 0

    def _email_exists(self, email):
        """Check if an email already exists."""
        response = self.users_table.query(
            IndexName=self.email_index,
            KeyConditionExpression=Key('email').eq(email)
        )
        return len(response.get('Items', [])) > 0

    def resend_verification_email(self, identifier):
        """Resend the email verification link, creating a new entry if none exists."""
        try:
            # First, try to find the user by username
            response = self.users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(identifier)
            )
            user = response.get('Items', [])

            if not user:  # If no user found by username, try by email
                response = self.users_table.query(
                    IndexName='email-index',
                    KeyConditionExpression=Key('email').eq(identifier)
                )
                user = response.get('Items', [])

            #if not user:
            #    raise ValueError("User not found.")
            if not user:
                # If the user is not found, return early (no email to resend)
                return

            user = user[0]  # Get the first (and only) result
            email = user['email']

            # Query using the GSI to find the item by email
            response = self.verification_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            items = response.get('Items', [])
            
            if not items:
                # If no verification entry exists, create a new one
                verification_code = str(uuid.uuid4())
                expires_at = int(time.time()) + 3600  # New code valid for 1 hour

                self.verification_table.put_item(
                    Item={
                        'email': email,
                        'verification_code': verification_code,
                        'expires_at': expires_at
                    }
                )
            else:
                # If an entry exists, check its expiration
                item = items[0]
                current_time = int(time.time())
                if current_time > item['expires_at']:
                    # Code has expired, generate a new one
                    verification_code = str(uuid.uuid4())
                    expires_at = current_time + 3600  # New code valid for 1 hour

                    # Update the table with the new code and expiration time
                    self.verification_table.put_item(
                        Item={
                            'email': email,
                            'verification_code': verification_code,
                            'expires_at': expires_at
                        }
                    )
                else:
                    # Code is still valid
                    verification_code = item['verification_code']

            # Resend the verification email
            self._send_verification_email(email, verification_code)

        except Exception as e:
            print(f"Error resending verification email: {e}")
            traceback.print_exc()
            raise  # Let the calling function handle the HTTP response

    def resend_verification_email_old(self, email):
        """Resend the email verification link, creating a new entry if none exists."""
        try:
            # Query using the GSI to find the item by email
            response = self.verification_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            items = response.get('Items', [])
            
            if not items:
                # If no verification entry exists, create a new one
                verification_code = str(uuid.uuid4())
                expires_at = int(time.time()) + 3600  # New code valid for 1 hour

                self.verification_table.put_item(
                    Item={
                        'email': email,
                        'verification_code': verification_code,
                        'expires_at': expires_at
                    }
                )
            else:
                # If an entry exists, check its expiration
                item = items[0]
                current_time = int(time.time())
                if current_time > item['expires_at']:
                    # Code has expired, generate a new one
                    verification_code = str(uuid.uuid4())
                    expires_at = current_time + 3600  # New code valid for 1 hour

                    # Update the table with the new code and expiration time
                    self.verification_table.put_item(
                        Item={
                            'email': email,
                            'verification_code': verification_code,
                            'expires_at': expires_at
                        }
                    )
                else:
                    # Code is still valid
                    verification_code = item['verification_code']

            # Resend the verification email
            self._send_verification_email(email, verification_code)

        except Exception as e:
            print(f"Error resending verification email: {e}")
            traceback.print_exc()
            raise  # Let the calling function handle the HTTP response

    def _send_verification_email(self, email, verification_code):
        """Send verification email with a code using EmailUtil."""
        link = f"{self.email_util.verification_url}?code={verification_code}"
        subject = "Email Verification"
        body = f"Please verify your email by clicking on the following link: {link}"
        self.email_util.send_email(email, subject, body)

    def _send_reset_email(self, email, reset_token):
        """Send a password reset email with a token using EmailUtil."""
        link = f"{self.email_util.reset_url}?token={reset_token}"
        subject = "Password Reset"
        body = f"Please reset your password by clicking on the following link: {link}"
        self.email_util.send_email(email, subject, body)

    def request_password_reset(self, identifier):
        """Request a password reset by sending a reset token to the user's email."""
        try:
            # Try to find the user by username
            response = self.users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(identifier)
            )
            user = response.get('Items', [])

            if not user:  # If no user found by username, try by email
                response = self.users_table.query(
                    IndexName='email-index',
                    KeyConditionExpression=Key('email').eq(identifier)
                )
                user = response.get('Items', [])

            if not user:
                raise ValueError("User not found.")

            user = user[0]  # Get the first (and only) result
            reset_token = str(uuid.uuid4())  # Generate a unique reset token

            # Store the reset token with expiration
            self.reset_tokens_table.put_item(
                Item={
                    'email': user['email'],
                    'token': reset_token,
                    'expires_at': int(time.time()) + int(PASSWORD_RESET_TOKEN_VALIDITY_SECONDS)
                }
            )

            # Send reset email
            self._send_reset_email(user['email'], reset_token)

        except ClientError as e:
            print(f"Error requesting password reset: {e}")
            traceback.print_exc()
            raise
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
            traceback.print_exc()
            raise

    def request_password_reset_old(self, email):
        """Request a password reset by sending a reset token to the user's email."""
        print(f"-----------Attempting to request password reset for email: {email}")
        try:
            # Query the users table by email index
            response = self.users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            items = response.get('Items', [])

            print(f"Query response: {response}")

            if not items:
                raise ValueError("User not found.")

            user = items[0]
            reset_token = str(uuid.uuid4())  # Generate a unique reset token

            # Store the reset token with expiration
            self.reset_tokens_table.put_item(
                Item={
                    'email': email,
                    'token': reset_token,
                    'expires_at': int(time.time()) + int(PASSWORD_RESET_TOKEN_VALIDITY_SECONDS)
                }
            )

            # Send reset email
            self._send_reset_email(email, reset_token)

        except ClientError as e:
            print(f"Error requesting password reset: {e}")
            traceback.print_exc()
            raise
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")
            traceback.print_exc()
            raise

    def reset_password(self, token, new_password):
        print(f"Attempting to reset password with token: {token}")
        try:
            # Retrieve the reset token record from DynamoDB
            response = self.reset_tokens_table.get_item(
                Key={'token': token}
            )
            print(f"GetItem response: {response}")

            token_data = response.get('Item')
            if not token_data:
                print("No token data found.")
                return False

            if int(time.time()) > token_data['expires_at']:
                print("Reset token has expired.")
                return False

            email = token_data['email']

            # Retrieve user by email
            user_response = self.users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(email)
            )
            user_items = user_response.get('Items', [])
            if not user_items:
                return False

            user = user_items[0]
            user_id = user['id']

            # Update the user's password
            hashed_password = self._hash_password(new_password)
            self.users_table.update_item(
                Key={'id': user_id},
                UpdateExpression="SET password = :password",
                ExpressionAttributeValues={':password': hashed_password}
            )
            print(f"Password updated successfully for user ID: {user_id}")

            # Delete the used reset token
            self.reset_tokens_table.delete_item(
                Key={'token': token}
            )
            print(f"Reset token deleted successfully: {token}")

            return True

        except Exception as e:
            print(f"Exception during password reset: {e}")
            traceback.print_exc()
            return False

    def reset_password_with_email(self, email, reset_token, new_password):
        """Reset the user's password using the provided reset token."""
        try:
            # Verify the reset token
            response = self.reset_tokens_table.get_item(Key={'email': email})
            token_data = response.get('Item')

            if not token_data:
                raise ValueError("Invalid reset token request.")

            if token_data['reset_token'] != reset_token:
                raise ValueError("Invalid reset token.")

            if int(time.time()) > token_data['expires_at']:
                raise ValueError("Reset token expired.")

            # Update the user's password
            self.users_table.update_item(
                Key={'email': email},
                UpdateExpression="SET password = :new_password",
                ExpressionAttributeValues={':new_password': self._hash_password(new_password)} 
            )

            # Remove the reset token
            self.reset_tokens_table.delete_item(Key={'email': email})

            print("Password successfully reset.")
        except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
            print(f"Error resetting password: {e}")
            raise

    def register_user(self, username, email, password, confirm_password):
        """Register a new user with username, email, and password."""
        if not utils.is_valid_email(email):
            raise ValueError(f'Email {email} is invalid.')

        if password != confirm_password:
            raise ValueError("Passwords do not match.")

        if self._username_exists(username):
            raise ValueError("Username already exists.")

        if self._email_exists(email):
            raise ValueError("Email already exists.")

        user_id = str(uuid.uuid4())  # Generate a unique user ID
        verification_code = str(uuid.uuid4())  # Generate a unique verification code

        try:
            # Add user to the table
            self.users_table.put_item(
                Item={
                    'id': user_id,
                    'username': username,
                    'email': email,
                    'password': self._hash_password(password),
                    'created_at': str(datetime.utcnow()),  # Add the created_at timestamp
                    'last_login': None,  # Initialize last_login as None or the same as created_at
                    'verified': False  # Email verification status
                }
            )

            # Store verification code with expiration
            print (f'kar99---------------------table is {self.verification_table}')
            self.verification_table.put_item(
                Item={
                    'email': email,
                    'verification_code': verification_code,
                    'expires_at': int(time.time()) + 3600  # Valid for 1 hour
                }
            )

            # Send verification email
            self._send_verification_email(email, verification_code)

            return user_id
        except ClientError as e:
            print(f"Error registering user: {e}")
            raise

    def verify_email(self, verification_code):
        """Verify a user's email using a verification code."""
        try:
            # Query the verification table using the provided verification code
            response = self.verification_table.get_item(Key={'verification_code': verification_code})
            item = response.get('Item')

            # Debugging: Check if the item is retrieved correctly
            print(f"Retrieved item: {item}")

            if not item:
                raise ValueError("Invalid or expired verification code.")

            # Check if the verification code has expired
            current_time = int(time.time())
            if current_time > item['expires_at']:
                raise ValueError("Verification code has expired.")

            # Query the Users table to find the user by email using the email-index
            response = self.users_table.query(
                IndexName='email-index',
                KeyConditionExpression=Key('email').eq(item['email'])
            )
            if response['Items']:
                user_id = response['Items'][0]['id']

                # Update the user's verification status
                self.users_table.update_item(
                    Key={'id': user_id},
                    UpdateExpression="SET verified = :v",
                    ExpressionAttributeValues={':v': True}
                )

                # Delete the verification entry from the verification table
                self.verification_table.delete_item(Key={'verification_code': verification_code})

                print("Email verified successfully.")
                return True
            else:
                raise ValueError("User with this email does not exist.")
        except ClientError as e:
            print(f"Error verifying email: {e}")
            raise
        except ValueError as ve:
            print(f"Verification failed: {ve}")
            return False

    def _convert_permission_to_string(self, permission):
        """Convert a Permission enum to a string."""
        return permission.value if isinstance(permission, Permission) else permission

    def _is_email_valid(self, email):
        """Validate email format."""
        email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
        return email_regex.match(email) is not None

    def verify_email_by_admin(self, user_id):
        """Verify a user's email address."""
        try:
            response = self.users_table.update_item(
                Key={'id': user_id},
                UpdateExpression="SET is_email_verified = :verified",
                ExpressionAttributeValues={':verified': True},
                ReturnValues="UPDATED_NEW"
            )
            return response
        except ClientError as e:
            print(f"Error verifying email: {e}")
            raise
    
    def get_user_details_by_id(self, user_id):
        """Retrieve a user's details."""
        try:
            response = self.users_table.get_item(Key={'id': user_id})
            return response.get('Item', {})
        except ClientError as e:
            print(f"Error retrieving user: {e}")
            return {}

    def get_user_details(self, username):
        """Retrieve a user's details by username."""
        try:
            response = self.users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(username)
            )
            return response.get('Items', [{}])[0]  # Return the first item, or an empty dict if not found
        except ClientError as e:
            print(f"Error retrieving user: {e}")
            return {}

    def get_user_details_by_username(self, username):
        """Retrieve user details by username."""
        response = self.users_table.query(
            IndexName='username-index',
            KeyConditionExpression=Key('username').eq(username)
        )
        return response.get('Items', [])[0] if response['Items'] else None

    def get_user_details_by_email(self, email):
        """Retrieve user details by email."""
        response = self.users_table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
        )
        return response.get('Items', [])[0] if response['Items'] else None

    def get_all_users(self):
        """Retrieve all users."""
        response = self.users_table.scan()
        return response.get('Items', [])

    def update_last_login(self, user_id):
        """Update the last login time for the user based on their user ID."""
        last_login = str(datetime.utcnow())

        try:
            # Update the last_login field using the user's ID
            self.users_table.update_item(
                Key={'id': user_id},  # Use 'id' as the primary key
                UpdateExpression="SET last_login = :last_login",
                ExpressionAttributeValues={':last_login': last_login}
            )
            print(f"Updated last_login for user: {user_id}")
        except Exception as e:
            print(f"Failed to update last login: {e}")
            traceback.print_exc()
            raise

    def update_last_login_by_username(self, username):
        # Query to get the user's ID using the username
        response = self.users_table.query(
            IndexName='username-index',
            KeyConditionExpression=Key('username').eq(username)
        )
        user_items = response.get('Items', [])
        if not user_items:
            raise ValueError("User not found.")

        user_id = user_items[0]['id']  # Retrieve the user ID
        last_login = str(datetime.utcnow())

        # Update the last_login using the user's ID
        self.users_table.update_item(
            Key={'id': user_id},  # Use 'id' as the primary key
            UpdateExpression="SET last_login = :last_login",
            ExpressionAttributeValues={':last_login': last_login}
        )

        print(f"Updated last_login for user: {username}")

    def login_user(self, identifier, password):
        """Authenticate a user by username or email and password."""
        try:
            # First, try to find the user by username
            response = self.users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(identifier)
            )
            user = response.get('Items', [])

            if not user:  # If no user found by username, try by email
                response = self.users_table.query(
                    IndexName='email-index',
                    KeyConditionExpression=Key('email').eq(identifier)
                )
                user = response.get('Items', [])

            if not user:
                raise ValueError("Invalid username or email or password.")

            user = user[0]  # Get the first (and only) result

            hashed_password = user['password']
            if not self._check_password(password, hashed_password):
                raise ValueError("Invalid username or email or password.")

            if not user.get('verified', False):
                raise ValueError("Email not verified. Please verify your email before logging in.")

            self.update_last_login(user['id'])

            # Generate a JWT token
            token = self.generate_jwt(user['id'])

            print("User logged in successfully.")
            return token
        except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
            print(f"Error logging in: {e}")
            traceback.print_exc()
            raise ValueError("Failed to authenticate user.")
        except ValueError as ve:
            print(f"Authentication failed: {ve}")
            traceback.print_exc()
            raise

    def login_user_by_username(self, username, password):
        """Authenticate a user by username and password, check email verification, and generate a JWT."""
        try:
            response = self.users_table.query(
                IndexName='username-index',
                KeyConditionExpression=Key('username').eq(username)
            )
            if not response['Items']:
                raise ValueError("User not found.")
            
            user = response['Items'][0]
            hashed_password = user['password']

            # Check if the email is verified
            if not user.get('verified', False):
                raise ValueError("Please verify your email before you will be allowed to log in.")

            # Check if the password matches
            if not self._check_password(password, hashed_password):
                raise ValueError("Invalid password.")

            self.update_last_login(user['id'])
            
            # Generate JWT token
            token = self.generate_jwt(user['id'])

            print("User logged in successfully.")
            return token
        except ValueError as ve:
            print(f"Authentication failed: {ve}")
            utils.handle_exception(ve, 'Authentication error')
            return None
        except (ClientError, NoCredentialsError, PartialCredentialsError) as e:
            print(f"Error logging in: {e}")
            utils.handle_exception(e, 'Error logging in')
            raise

    def generate_jwt(self, user_id):
        """Generate a JWT token for the user."""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(seconds=int(LOGIN_VALIDITY_SECONDS))  # Token expiration time
        }
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        print (f'----user_management: token: {token}')
        print (f'----user_management: secret_key: {self.jwt_secret}')
        return token

    def create_group(self, group_name, creator_user_id):
        if not self.permissions_manager.check_permission(creator_user_id, Permission.CREATE_GROUP):
            return "Permission denied"

        group_id = str(uuid.uuid4())
        try:
            self.groups_table.put_item(
                Item={
                    'id': group_id,
                    'name': group_name,
                    'permissions': []  # Initialize with no permissions
                }
            )
            return group_id
        except ClientError as e:
            print(f"Error creating group: {e}")
            return None

    def get_user_groups(self, user_id):
        """Retrieve the list of groups a user is a member of."""
        try:
            response = self.user_group_membership_table.query(
                KeyConditionExpression=Key('user_id').eq(user_id)
            )
            group_ids = [item['group_id'] for item in response.get('Items', [])]
            return group_ids
        except ClientError as e:
            print(f"Error retrieving user groups: {e}")
            return []

    def add_user_to_group(self, executor_user_id, user_id, group_id):
        """Add a user to a group."""
        if not self.permissions_manager.check_permission(executor_user_id, Permission.ADD_USER_TO_GROUP):
            return "Unauthorized: You don't have permission to add users to groups."

        try:
            self.user_group_membership_table.put_item(
                Item={
                    'user_id': user_id,
                    'group_id': group_id
                }
            )
            return "User added to group"
        except ClientError as e:
            print(f"Error adding user to group: {e}")
            return "Error adding user to group"

    def remove_user_from_group(self, executor_user_id, user_id, group_id):
        """Remove a user from a group."""
        if not self.permissions_manager.check_permission(executor_user_id, Permission.REMOVE_USER_FROM_GROUP):
            return "Unauthorized: You don't have permission to remove users from groups."

        try:
            self.user_group_membership_table.delete_item(
                Key={
                    'user_id': user_id,
                    'group_id': group_id
                }
            )
            return "User removed from group"
        except ClientError as e:
            print(f"Error removing user from group: {e}")
            return "Error removing user from group"

    def check_model_permission(self, user_id, permission):
        """Check if the user can perform a given model operation considering both user and group permissions."""
        permission_str = self._convert_permission_to_string(permission)
        # Check user-specific permissions
        user_permissions = self.permissions_manager.get_user_permissions(user_id)
        print(f"User permissions for {user_id}: {user_permissions}")  # Debugging line
        if permission in user_permissions:
            return True 

        # Check group permissions if user-specific permissions don't include the permission
        group_ids = self.get_user_groups(user_id)
        print(f"Groups for user {user_id}: {group_ids}")  # Debugging line
        for group_id in group_ids:
            group_permissions = self.permissions_manager.get_group_permissions(group_id)
            print(f"Permissions for group {group_id}: {group_permissions}")  # Debugging line
            print (f'permission {permission_str} in group_permissions {group_permissions} {permission_str in group_permissions}')
            if permission_str in group_permissions:
                return True

        # Permission not found
        return False


    def change_password(self, user_id, current_password, new_password, confirm_new_password):
        # Fetch the user's details
        response = self.users_table.get_item(Key={'id': user_id})
        user = response.get('Item')

        if not user:
            raise ValueError("User not found")

        # Check if the current password is correct
        if not bcrypt.checkpw(current_password.encode('utf-8'), user['password'].encode('utf-8')):
            raise ValueError("Current password is incorrect")

        # Check if the new password and confirm password match
        if new_password != confirm_new_password:
            raise ValueError("New password and confirm password do not match")

        # Check if the new password and current password are different
        if new_password == current_password:
            raise ValueError("No password change detected")

        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update the password in the database
        self.users_table.update_item(
            Key={'id': user_id},
            UpdateExpression="set password = :p",
            ExpressionAttributeValues={':p': hashed_password}
        )

        return {"message": "Password changed successfully"}

    def revoke_token(self, token):
        # Add the token to the RevokedTokens table
        self.revoked_tokens_table.put_item(
            Item={
                'token': token,
                'revoked_at': int(time.time())  # Store the time of revocation
            }
        )


# Example usage:
if __name__ == "__main__":
    manager = UserManager()
    
    # Register a new user
    user_id = manager.register_user('john_doe', 'secure_password')
    print(f"Registered user ID: {user_id}")

    # Login a user
    logged_in_user_id = manager.login_user('john_doe', 'secure_password')
    print(f"Logged in user ID: {logged_in_user_id}")

    # Create a group
    group_id = manager.create_group('example_group', logged_in_user_id)
    print(f"Created group ID: {group_id}")

    # Add user to group
    result = manager.add_user_to_group(logged_in_user_id, logged_in_user_id, group_id)
    print(result)

    # Remove user from group
    result = manager.remove_user_from_group(logged_in_user_id, logged_in_user_id, group_id)
    print(result)

    # Check model permissions
    can_upload = manager.check_model_permission(logged_in_user_id, Permission.UPLOAD_MODEL)
    print(f"User can upload model: {can_upload}")
