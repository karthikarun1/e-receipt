import psycopg2
import os

# Load environment variables
from config_loader import load_environment
load_environment()

DBNAME=os.getenv("DB_NAME")
USER=os.getenv("DB_USER")
PASSWORD=os.getenv("DB_PASSWORD")
HOST=os.getenv("DB_HOST")
PORT=os.getenv("DB_PORT")

def get_connection():
    connection = psycopg2.connect(
        dbname=DBNAME,
        user=USER,
        password=PASSWORD,
        host=HOST,
        port=PORT
    )
    return connection
