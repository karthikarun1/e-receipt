import os
from dotenv import load_dotenv

def load_environment():
    # Load the base .env file
    load_dotenv()

    # Get the environment from ENV by eading from .env file or default to 'dev'
    env = os.getenv('ENV', 'dev')

    # Load the corresponding .env file based on the environment
    load_dotenv(f'.env.{env}')
