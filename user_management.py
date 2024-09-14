import bcrypt
import jwt
import hashlib
import logging
import os
import uuid
import time
import re
import traceback
import traceback
import utils

from base_management import BaseManager
from datetime import datetime, timedelta
from email_util import EmailUtil

# Load environment variables
from config_loader import load_environment
load_environment()

PASSWORD_RESET_TOKEN_VALIDITY_SECONDS = os.getenv('PASSWORD_RESET_TOKEN_VALIDITY_SECONDS')
LOGIN_VALIDITY_SECONDS = os.getenv('LOGIN_VALIDITY_SECONDS')

logger = logging.getLogger(__name__)

from functools import wraps

def transactional(func):
    """
    Decorator to handle database transactions.
    It commits the transaction on success or rolls it back on failure.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            result = func(self, *args, **kwargs)
            self.db_connection.commit()  # Commit if everything is successful
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            self.db_connection.rollback()  # Rollback on error
            raise
    return wrapper

class UserManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.jwt_secret = os.getenv('JWT_SECRET')

    def _hash_password(self, password):
        """Hash a password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _check_password(self, password, hashed_password):
        """Check if the provided password matches the hashed password."""
        return bcrypt.checkpw(password.encode(), hashed_password.encode())

    @transactional
    def _username_exists(self, username):
        """Check if a username already exists."""
        user = self.user_dal.get_user_by_username(username)
        return user is not None

    @transactional
    def _email_exists(self, email):
        """Check if an email already exists."""
        user = self.user_dal.get_user_by_email(email)
        return user is not None

    @transactional
    def resend_verification_email(self, identifier):
        """Resend the email verification link, creating a new entry if none exists."""
        # First, try to find the user by username or email
        user = self.user_dal.get_user_by_username(identifier) or self.user_dal.get_user_by_email(identifier)

        if not user:
            logger.error(f"User not found: {identifier}")
            return

        email = user['email']

        # Check if a verification code already exists
        verification_data = self.user_dal.get_verification_by_code(email)

        if not verification_data or int(time.time()) > verification_data['expires_at']:
            # If no entry exists or the code has expired, generate a new code
            verification_code = str(uuid.uuid4())
            expires_at = int(time.time()) + 3600  # Valid for 1 hour
            self.user_dal.insert_verification_code(email, verification_code, expires_at)
            logger.info(f"Generated new verification code for {email}")
        else:
            verification_code = verification_data['verification_code']
            logger.info(f"Existing verification code found for {email}")

        # Resend the verification email
        self._send_verification_email(email, verification_code)

    @transactional
    def _send_reset_email(self, email, reset_token):
        """Send a password reset email with a token using EmailUtil."""
        link = f"{self.email_util.reset_url}?token={reset_token}"
        subject = "Password Reset"
        body = f"Please reset your password by clicking on the following link: {link}"
        self.email_util.send_email(email, subject, body)

    @transactional
    def request_password_reset(self, identifier):
        """Request a password reset by sending a reset token to the user's email."""
        # Try to find the user by username
        user = self.user_dal.get_user_by_username(identifier) or self.user_dal.get_user_by_email(identifier)

        if not user:
            raise ValueError("User not found.")

        reset_token = str(uuid.uuid4())  # Generate a unique reset token

        # Store the reset token with expiration
        self.user_dal.insert_reset_token(user['email'], reset_token, int(time.time()) + int(PASSWORD_RESET_TOKEN_VALIDITY_SECONDS))

        # Send reset email
        self._send_reset_email(user['email'], reset_token)
        logger.info(f"Password reset token sent to: {user['email']}")


    @transactional
    def reset_password(self, token, new_password):
        """Reset the user's password using the provided reset token."""
        logger.info(f"Attempting to reset password with token: {token}")
        # Retrieve the reset token record from PostgreSQL
        token_data = self.user_dal.get_user_reset_token(token)
        
        if not token_data:
            logger.error("No token data found.")
            return False

        if int(time.time()) > token_data['expires_at']:
            logger.error("Reset token has expired.")
            return False

        email = token_data['email']
        user = self.user_dal.get_user_by_email(email)

        if not user:
            logger.error("User not found.")
            return False

        user_id = user['id']

        # Update the user's password
        hashed_password = self._hash_password(new_password)
        self.user_dal.update_password(user_id, hashed_password)
        logger.info(f"Password updated successfully for user ID: {user_id}")

        # Delete the used reset token
        self.user_dal.delete_reset_token(token)
        logger.info(f"Reset token deleted successfully: {token}")

        return True


    @transactional
    def reset_password_with_email(self, email, reset_token, new_password):
        """Reset the user's password using the provided reset token."""
        # Retrieve the reset token from PostgreSQL
        token_data = self.user_dal.get_user_reset_token(email)

        if not token_data or token_data['token'] != reset_token:
            logger.error("Invalid reset token.")
            raise ValueError("Invalid reset token.")

        if int(time.time()) > token_data['expires_at']:
            logger.error("Reset token expired.")
            raise ValueError("Reset token expired.")

        # Update the user's password
        self.user_dal.update_password_by_email(email, self._hash_password(new_password))

        # Delete the reset token
        self.user_dal.delete_reset_token(reset_token)

        logger.info(f"Password successfully reset for email: {email}")

    @transactional
    def register_user(self, username, email, password, confirm_password):
        """Register a new user with username, email, and password."""
        if not utils.is_valid_email(email):
            raise ValueError(f'Email {email} is invalid.')

        if password != confirm_password:
            raise ValueError("Passwords do not match.")

        if self.user_dal.get_user_by_username(username):
            raise ValueError("Username already exists.")

        if self.user_dal.get_user_by_email(email):
            raise ValueError("Email already exists.")

        verification_code = str(uuid.uuid4())  # Generate a unique verification code
        created_at = str(datetime.utcnow())

        # Add user to the PostgreSQL database without specifying user_id, allowing it to be auto-generated
        self.user_dal.insert_user(username, email, self._hash_password(password), created_at)

        # Insert verification code
        self.user_dal.insert_verification_code(email, verification_code, int(time.time()) + 3600)

        # Send verification email
        self._send_verification_email(email, verification_code)

    def _send_verification_email(self, email, verification_code):
        """Send verification email with a code using EmailUtil."""
        link = f"{self.email_util.verification_url}?code={verification_code}"
        subject = "Email Verification"
        body = f"Please verify your email by clicking on the following link: {link}"
        self.email_util.send_email(email, subject, body)

    @transactional
    def verify_email(self, verification_code):
        """Verify a user's email using a verification code."""
        logger.info(f"Attempting to verify email with code: {verification_code}")
        # Retrieve the verification code record from PostgreSQL
        verification_data = self.user_dal.get_verification_by_code(verification_code)
        
        if not verification_data:
            logger.error("Invalid or expired verification code.")
            raise ValueError("Invalid or expired verification code.")

        if int(time.time()) > verification_data['expires_at']:
            logger.error("Verification code has expired.")
            raise ValueError("Verification code has expired.")

        email = verification_data['email']
        user = self.user_dal.get_user_by_email(email)

        if not user:
            logger.error("User not found.")
            raise ValueError("User with this email does not exist.")

        user_id = user['id']

        # Update the user's verification status
        self.user_dal.update_user_verified_status(user_id, True)
        logger.info(f"Email verified successfully for user ID: {user_id}")

        # Delete the verification entry
        self.user_dal.delete_verification_by_code(verification_code)
        logger.info(f"Deleted verification code: {verification_code}")

        return True


    def _convert_permission_to_string(self, permission):
        """Convert a Permission enum to a string."""
        return permission.value if isinstance(permission, Permission) else permission

    def _is_email_valid(self, email):
        """Validate email format."""
        email_regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
        return email_regex.match(email) is not None

    @transactional
    def verify_email_by_admin(self, user_id):
        """Verify a user's email address."""
        self.user_dal.update_user_verified_status(user_id, True)
        logger.info(f"Email verified successfully by admin for user ID: {user_id}")

    @transactional
    def verify_email_by_admin(self, user_id):
        """Verify a user's email address."""
        self.user_dal.update_user_verified_status(user_id, True)
        logger.info(f"Email verified successfully by admin for user ID: {user_id}")

    @transactional
    def get_user_details(self, username):
        """Retrieve a user's details by username."""
        user = self.user_dal.get_user_by_username(username)
        if not user:
            raise ValueError("User not found.")
        return user

    @transactional
    def get_user_details_by_username(self, username):
        """Retrieve user details by username."""
        user = self.user_dal.get_user_by_username(username)
        if not user:
            raise ValueError("User not found.")
        return user

    @transactional
    def get_user_details_by_email(self, email):
        """Retrieve user details by email."""
        user = self.user_dal.get_user_by_email(email)
        if not user:
            raise ValueError("User not found.")
        return user

    @transactional
    def get_all_users(self):
        """Retrieve all users."""
        # Assuming UserDAL has a method for fetching all users
        users = self.user_dal.get_all_users()  # You might need to implement this in UserDAL
        return users

    @transactional
    def update_last_login(self, user_id):
        """Update the last login time for the user based on their user ID."""
        last_login = str(datetime.utcnow())

        # Update the last_login field using the user's ID
        self.user_dal.update_last_login(user_id, last_login)
        logger.info(f"Updated last_login for user: {user_id}")

    @transactional
    def update_last_login_by_username(self, username):
        """Update the last login time using the user's username."""
        user = self.user_dal.get_user_by_username(username)
        if not user:
            raise ValueError("User not found.")

        self.user_dal.update_last_login(user['id'], str(datetime.utcnow()))
        logger.info(f"Updated last_login for user: {username}")

    @transactional
    def login_user(self, identifier, password):
        """Authenticate a user by username or email and password."""
        # Try to find the user by username first, then by email
        user = self.user_dal.get_user_by_username(identifier) or self.user_dal.get_user_by_email(identifier)
        
        if not user:
            raise ValueError("Invalid username or email or password.")

        hashed_password = user['password']
        if not self._check_password(password, hashed_password):
            raise ValueError("Invalid username or email or password.")

        if not user.get('verified', False):
            raise ValueError("Email not verified. Please verify your email before logging in.")

        # Update the last login time
        self.user_dal.update_last_login(user['id'], str(datetime.utcnow()))

        # Generate JWT token
        token = self.generate_jwt(user['id'])

        return token

    @transactional
    def login_user_by_username(self, username, password):
        """Authenticate a user by username and password, check email verification, and generate a JWT."""
        user = self.user_dal.get_user_by_username(username)
        
        if not user:
            raise ValueError("User not found.")

        hashed_password = user['password']

        # Check if the email is verified
        if not user.get('verified', False):
            raise ValueError("Please verify your email before you will be allowed to log in.")

        # Check if the password matches
        if not self._check_password(password, hashed_password):
            raise ValueError("Invalid password.")

        # Update last login time
        self.user_dal.update_last_login(user['id'], str(datetime.utcnow()))

        # Generate JWT token
        token = self.generate_jwt(user['id'])

        return token

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

    @transactional
    def change_password(self, user_id, current_password, new_password, confirm_new_password):
        """Change the user's password after verifying the current password."""
        # Fetch the user's details
        user = self.user_dal.get_user_by_id(user_id)

        if not user:
            logger.error("User not found.")
            raise ValueError("User not found.")

        # Check if the current password is correct
        if not self._check_password(current_password, user['password']):
            logger.error("Current password is incorrect.")
            raise ValueError("Current password is incorrect.")

        # Check if the new password and confirm password match
        if new_password != confirm_new_password:
            logger.error("New password and confirm password do not match.")
            raise ValueError("New password and confirm password do not match.")

        # Check if the new password and current password are different
        if new_password == current_password:
            logger.error("No password change detected.")
            raise ValueError("No password change detected.")

        # Hash the new password
        hashed_password = self._hash_password(new_password)

        # Update the password in the database
        self.user_dal.update_password(user_id, hashed_password)
        logger.info(f"Password changed successfully for user ID: {user_id}")


    @transactional
    def revoke_token(self, token):
        """Add the token to the revoked tokens list."""
        self.user_dal.revoke_token(token)
        logger.info(f"Token revoked successfully: {token}")
