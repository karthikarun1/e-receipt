import os
import re

# Load environment variables
from config_loader import load_environment
load_environment()

# Load limits from .env file
MAX_DESCRIPTION_LENGTH = int(os.getenv('MAX_DESCRIPTION_LENGTH', 500))
MAX_USERNAME_LENGTH = int(os.getenv('MAX_USERNAME_LENGTH', 50))
MAX_EMAIL_LENGTH = int(os.getenv('MAX_EMAIL_LENGTH', 100))
MAX_IDENTIFIER_LENGTH = int(os.getenv('MAX_IDENTIFIER_LENGTH', 100))
MAX_PASSWORD_LENGTH = int(os.getenv('MAX_PASSWORD_LENGTH', 128))
MIN_PASSWORD_LENGTH = int(os.getenv('MIN_PASSWORD_LENGTH', 8))
MAX_FILE_NAME_LENGTH = int(os.getenv('MAX_FILE_NAME_LENGTH', 255))
MAX_ORG_NAME_LENGTH = int(os.getenv('MAX_ORG_NAME_LENGTH', 100))
MAX_GROUP_NAME_LENGTH = int(os.getenv('MAX_GROUP_NAME_LENGTH', 50))
MAX_SEARCH_QUERY_LENGTH = int(os.getenv('MAX_SEARCH_QUERY_LENGTH', 255))
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', 2083))
MAX_COMMENT_LENGTH = int(os.getenv('MAX_COMMENT_LENGTH', 1000))
MAX_BIO_LENGTH = int(os.getenv('MAX_BIO_LENGTH', 500))
MAX_TAG_LENGTH = int(os.getenv('MAX_TAG_LENGTH', 50))
MAX_ADDRESS_LENGTH = int(os.getenv('MAX_ADDRESS_LENGTH', 255))

class InputValidator:

    @staticmethod
    def validate_model_name(model_name):
        if len(model_name) > MAX_FILE_NAME_LENGTH:
            raise ValueError(f"Model name exceeds the maximum length of {MAX_FILE_NAME_LENGTH} characters.")
        return model_name

    @staticmethod
    def validate_model_version(version):
        if len(version) > 20:
            raise ValueError("Model version exceeds the maximum length of 20 characters.")
        return version

    @staticmethod
    def validate_description(description):
        if len(description) > MAX_DESCRIPTION_LENGTH:
            raise ValueError(f"Description exceeds the maximum length of {MAX_DESCRIPTION_LENGTH} characters.")
        return description

    @staticmethod
    def validate_username(username):
        if len(username) > MAX_USERNAME_LENGTH:
            raise ValueError(f"Username exceeds the maximum length of {MAX_USERNAME_LENGTH} characters.")
        return username

    @staticmethod
    def validate_identifier(identifier):
        if len(identifier) > MAX_USERNAME_LENGTH:
            raise ValueError(f"Identifier exceeds the maximum length of {MAX_IDENTIFIER_LENGTH} characters.")
        return identifier

    @staticmethod
    def validate_email(email):
        if len(email) > MAX_EMAIL_LENGTH:
            raise ValueError(f"Email exceeds the maximum length of {MAX_EMAIL_LENGTH} characters.")
        # Basic email format validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email format.")
        return email

    @staticmethod
    def validate_password(password):
        if len(password) < MIN_PASSWORD_LENGTH or len(password) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"Password must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH} characters.")
        return password

    @staticmethod
    def validate_organization_name(org_name):
        if len(org_name) > MAX_ORG_NAME_LENGTH:
            raise ValueError(f"Organization name exceeds the maximum length of {MAX_ORG_NAME_LENGTH} characters.")
        return org_name

    @staticmethod
    def validate_group_name(group_name):
        if len(group_name) > MAX_GROUP_NAME_LENGTH:
            raise ValueError(f"Group name exceeds the maximum length of {MAX_GROUP_NAME_LENGTH} characters.")
        return group_name

    @staticmethod
    def validate_search_query(query):
        if len(query) > MAX_SEARCH_QUERY_LENGTH:
            raise ValueError(f"Search query exceeds the maximum length of {MAX_SEARCH_QUERY_LENGTH} characters.")
        return query

    @staticmethod
    def validate_url(url):
        if len(url) > MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds the maximum length of {MAX_URL_LENGTH} characters.")
        return url

    @staticmethod
    def validate_comment(comment):
        if len(comment) > MAX_COMMENT_LENGTH:
            raise ValueError(f"Comment exceeds the maximum length of {MAX_COMMENT_LENGTH} characters.")
        return comment

    @staticmethod
    def validate_bio(bio):
        if len(bio) > MAX_BIO_LENGTH:
            raise ValueError(f"Bio exceeds the maximum length of {MAX_BIO_LENGTH} characters.")
        return bio

    @staticmethod
    def validate_tag(tag):
        if len(tag) > MAX_TAG_LENGTH:
            raise ValueError(f"Tag exceeds the maximum length of {MAX_TAG_LENGTH} characters.")
        return tag

    @staticmethod
    def validate_address(address):
        if len(address) > MAX_ADDRESS_LENGTH:
            raise ValueError(f"Address exceeds the maximum length of {MAX_ADDRESS_LENGTH} characters.")
        return address

    @staticmethod
    def validate_file_name(file_name):
        if len(file_name) > MAX_FILE_NAME_LENGTH:
            raise ValueError(f"File name exceeds the maximum length of {MAX_FILE_NAME_LENGTH} characters.")
        return file_name

    # Add more validation methods as needed
