import inspect
import psycopg2
import psycopg2.extras
from psycopg2 import sql
import logging
from functools import wraps
import utils

logger = logging.getLogger(__name__)

def transactional(func):
    """
    Decorator to handle database transactions.
    It commits the transaction on success or rolls it back on failure.
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            result = func(self, *args, **kwargs)
            self.conn.commit()  # Commit if everything is successful
            return result
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {e}")
            self.conn.rollback()  # Rollback on error
            raise
    return wrapper

class UserDAL:
    def __init__(self, db_connection):
        """
        Initialize with a database connection.
        """
        caller_frame = inspect.stack()[1]
        print(f"UserDAL __init__() called by: {caller_frame.function} in {caller_frame.filename} at line {caller_frame.lineno}")

        # Continue with DB info
        self.conn = db_connection
        self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        self.conn.set_session(autocommit=False)  # Ensure autocommit is disabled for consistent transactions
        utils.get_db_info(db_connection)

    @transactional
    def get_user_by_username(self, username):
        """
        Get user details by username.
        """
        query = sql.SQL("SELECT * FROM users WHERE username = %s;")
        logger.debug(f"Executing query to get user by username: {query} with username: {username}")
        self.cursor.execute(query, (username,))
        result = self.cursor.fetchone()
        logger.debug(f"-----------Query result by username: {result}")
        return result

    @transactional
    def get_user_by_email(self, email):
        """
        Get user details by email.
        """
        query = sql.SQL("SELECT * FROM users WHERE email = %s;")
        logger.debug(f"Executing query to get user by username: {query} with email: {email}")
        self.cursor.execute(query, (email,))
        result = self.cursor.fetchone()
        logger.debug(f"-----------Query result: {result}")
        return result

    @transactional
    def insert_user(self, username, email, password_hash, created_at):
        """
        Insert a new user into the database with uniqueness check.
        """
        if self.get_user_by_username(username):
            raise ValueError("Username already exists.")
        if self.get_user_by_email(email):
            raise ValueError("Email already exists.")
        
        query = sql.SQL("""
            INSERT INTO users (username, email, password, created_at) 
            VALUES (%s, %s, %s, %s);
        """)
        self.cursor.execute(query, (username, email, password_hash, created_at))

    @transactional
    def update_user_verified_status(self, user_id, verified):
        """
        Update the verified status of a user by user_id.
        """
        query = sql.SQL("""
            UPDATE users
            SET verified = %s
            WHERE id = %s;
        """)
        self.cursor.execute(query, (verified, user_id))
        self.conn.commit()
        logger.info(f"User {user_id} verified status updated to {verified}")

    @transactional
    def update_last_login(self, user_id, last_login):
        """
        Update the last login time for a user.
        """
        query = sql.SQL("""
            UPDATE users SET last_login = %s WHERE id = %s;
        """)
        self.cursor.execute(query, (last_login, user_id))

    @transactional
    def update_password(self, user_id, new_password_hash):
        """
        Update the user's password.
        """
        query = sql.SQL("""
            UPDATE users SET password = %s WHERE id = %s;
        """)
        self.cursor.execute(query, (new_password_hash, user_id))

    @transactional
    def insert_verification_code(self, email, verification_code, expires_at):
        """
        Insert a new email verification code into the verification table.
        """
        query = sql.SQL("""
            INSERT INTO verification (email, verification_code, expires_at) 
            VALUES (%s, %s, %s);
        """)
        self.cursor.execute(query, (email, verification_code, expires_at))

    @transactional
    def get_verification_by_code(self, verification_code):
        """
        Retrieve the verification entry by code.
        """
        query = sql.SQL("""
            SELECT * FROM verification WHERE verification_code = %s;
        """)
        self.cursor.execute(query, (verification_code,))
        return self.cursor.fetchone()

    @transactional
    def delete_verification_by_code(self, verification_code):
        """
        Delete the verification entry by code.
        """
        query = sql.SQL("""
            DELETE FROM verification WHERE verification_code = %s;
        """)
        self.cursor.execute(query, (verification_code,))

    @transactional
    def get_user_reset_token(self, email):
        """
        Retrieve the password reset token for a user.
        """
        query = sql.SQL("""
            SELECT * FROM reset_tokens WHERE email = %s;
        """)
        self.cursor.execute(query, (email,))
        return self.cursor.fetchone()

    @transactional
    def insert_reset_token(self, email, reset_token, expires_at):
        """
        Insert a password reset token.
        """
        query = sql.SQL("""
            INSERT INTO reset_tokens (email, token, expires_at) 
            VALUES (%s, %s, %s);
        """)
        self.cursor.execute(query, (email, reset_token, expires_at))

    @transactional
    def delete_reset_token(self, token):
        """
        Delete a reset token by token value.
        """
        query = sql.SQL("""
            DELETE FROM reset_tokens WHERE token = %s;
        """)
        self.cursor.execute(query, (token,))

    @transactional
    def revoke_token(self, token):
        """
        Add a token to the revoked tokens list.
        """
        query = sql.SQL("""
            INSERT INTO revoked_tokens (token, revoked_at) VALUES (%s, %s);
        """)
        self.cursor.execute(query, (token, int(time.time())))
