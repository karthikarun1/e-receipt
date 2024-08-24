import base64

# Replace these with your actual username and password
username = "your_username"
password = "your_password"

# Combine username and password with a colon
credentials = f"{username}:{password}"

# Encode the credentials in base64
encoded_credentials = base64.b64encode(credentials.encode()).decode()

print(encoded_credentials)
