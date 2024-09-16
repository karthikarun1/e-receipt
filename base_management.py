import inspect
import os
import psycopg2
import postgresql_db_utils
from email_util import EmailUtil
from clover_dal import CloverDAL
from user_dal import UserDAL

# Load environment variables
from config_loader import load_environment
load_environment()

class BaseManager:
    def __init__(self):
        caller_frame = inspect.stack()[1]
        print(f"BaseManager __init__() called by: {caller_frame.function} in {caller_frame.filename} at line {caller_frame.lineno}")
        self.email_util= EmailUtil()

        self.db_connection = postgresql_db_utils.get_connection()

        # Ensure autocommit is disabled immediately after connection
        self.db_connection.autocommit = False
        self.user_dal = UserDAL(self.db_connection)
        self.clover_dal = CloverDAL(self.db_connection)
