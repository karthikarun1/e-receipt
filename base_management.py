import inspect
import os
import psycopg2
from email_util import EmailUtil
from user_dal import UserDAL

# Load environment variables
from config_loader import load_environment
load_environment()

class BaseManager:
    def __init__(self):
        caller_frame = inspect.stack()[1]
        print(f"BaseManager __init__() called by: {caller_frame.function} in {caller_frame.filename} at line {caller_frame.lineno}")
        self.email_util= EmailUtil()

        dbname=os.getenv("DB_NAME")
        user=os.getenv("DB_USER")
        password=os.getenv("DB_PASSWORD")
        host=os.getenv("DB_HOST")
        port=os.getenv("DB_PORT")

        self.db_connection = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port
        )

        # Debugging: Print connection details
        print (f'-------------------DB info: dbname: {dbname}, user: {user}, password: {password}, host: {host}, port: {port}')

        # Ensure autocommit is disabled immediately after connection
        self.db_connection.autocommit = False
        self.user_dal = UserDAL(self.db_connection)
