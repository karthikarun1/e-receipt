import base64
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import urllib.parse
import hmac
import hashlib
import traceback
import utils

from urllib.parse import urlencode

# Load environment variables
from config_loader import load_environment
load_environment()


SEND_EMAIL = os.getenv('SEND_EMAIL')

class EmailUtil:
    def __init__(self):
        self.email_server = os.getenv('EMAIL_SERVER')
        self.email_port = int(os.getenv('EMAIL_PORT', 587))
        self.email_user = os.getenv('EMAIL_USER')
        self.email_password = os.getenv('EMAIL_PASSWORD')
        self.link_secret = os.getenv('LINK_SECRET', 'your-secret-key')
        self.verification_url = f"{os.getenv('BASE_URL')}/verify_email"
        self.reset_url = os.getenv('PASSWORD_RESET_URL')

    def send_email(self, to_email, subject, body):
        print (f'------send_email to: {to_email},\n\n------body: {body}')
        return
        if SEND_EMAIL == 'no':
            return
        msg = MIMEMultipart()
        msg['From'] = self.email_user
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP(self.email_server, self.email_port)
            server.starttls()
            print ('--------email_user ' + repr(self.email_user))
            print ('--------password: ' + repr(self.email_password))
            server.login(self.email_user, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_user, to_email, text)
            server.quit()
            print(f"Email sent to {to_email}")
        except Exception as e:
            print(f"Failed to send email: {e}")
            traceback.print_exc()  # This prints the full stack trace

    def send_sms(self, recipient, message):
        # Placeholder for SMS sending functionality
        print(f"Attempted to send SMS to {recipient} with message '{message}'. SMS functionality is not yet implemented.")

    def _generate_signature(self, data):
        """Generate HMAC signature for the data using the secret key."""
        print(f"10----------generate_signature params {data}")
        hmac_obj = hmac.new(self.link_secret.encode(), data.encode(), hashlib.sha256)
        signature = base64.urlsafe_b64encode(hmac_obj.digest()).decode().strip()  # Remove any possible trailing whitespace
        signature = utils.remove_base64_padding(signature)
        print(f"20-----------Generated signature: {signature}")
        return signature


    def validate_signature(self, params):
        """Validate the signature to ensure the link hasn't been tampered with."""
        signature = params.pop('signature', None)
        if not signature:
            return False

        # Use the utility function to ensure 'expires_at' is properly formatted
        expires_at = utils.format_timestamp(params['expires_at'])

        # Manually build the params string for signature validation
        params_string = f"invitation_id={params['invitation_id']}&expires_at={expires_at}"
        print(f"30---------Validating signature with params: {params_string}")

        # Generate the expected signature based on the parameters
        expected_signature = self._generate_signature(params_string)

        # Ensure the padding is removed from both signatures for comparison
        expected_signature = utils.remove_base64_padding(expected_signature)
        signature = utils.remove_base64_padding(signature)

        # Debugging: Check lengths and exact characters of the signatures
        print(f"40-------------Expected signature length: {len(expected_signature)}")
        print(f"50-------------Received signature length: {len(signature)}")
        print(f"60-------------Expected signature bytes: {expected_signature.encode('utf-8')}")
        print(f"70-------------Received signature bytes: {signature.encode('utf-8')}")

        return hmac.compare_digest(expected_signature, signature)

    def generate_secure_link(self, base_url, params, expiration_minutes=60):
        """Generate a secure link with an expiration timestamp."""
        expires_at = datetime.utcnow() + timedelta(minutes=expiration_minutes)
        params['expires_at'] = expires_at.isoformat()

        # Use the utility function to ensure consistent formatting
        params_string = f"invitation_id={params['invitation_id']}&expires_at={utils.format_timestamp(params['expires_at'])}"
        print(f"--------------Generating signature with params: {params_string}")

        # Generate the signature
        signature = self._generate_signature(params_string)
        params['signature'] = signature

        # Build the full secure link
        secure_link = f"{base_url}?{urlencode(params)}"
        return secure_link

    def send_confirmation_email(self, to_email, subscription_id, base_url='https://example.com/confirm'):
        params = {'subscription_id': subscription_id}
        confirmation_link = self.generate_secure_link(base_url, params)

        subject = "Confirm Your Subscription"
        body = f"Please confirm your subscription by clicking on the following link: {confirmation_link}"
        self.send_email(to_email, subject, body)

    def send_activation_email(self, to_email, subscription_id):
        subject = "Your Subscription is Now Active"
        body = f"Your subscription with ID {subscription_id} is now active. Thank you for subscribing!"
        self.send_email(to_email, subject, body)

    def send_invite_email(self, to_email, org_name, invite_link):
        subject = f"Invitation to Join {org_name}"
        body = f"You have been invited to join the organization {org_name}. Please click the link to accept the invitation: {invite_link}"
        self.send_email(to_email, subject, body)

# Example usage:
if __name__ == "__main__":
    email_util = EmailUtil()
    confirmation_link = email_util.generate_secure_link('https://example.com/confirm', {'subscription_id': 'abc123'})
    print(f'Generated confirmation link: {confirmation_link}')

