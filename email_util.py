import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from dotenv import load_dotenv
import urllib.parse
import hmac
import hashlib
import base64
import traceback

# Load environment variables from .env file
load_dotenv()

SEND_EMAIL = os.getenv('SEND_EMAIL')

class EmailUtil:
    def __init__(self):
        self.email_server = os.getenv('EMAIL_SERVER')
        self.email_port = int(os.getenv('EMAIL_PORT', 587))
        self.email_user = os.getenv('EMAIL_USER')
        self.email_password = os.getenv('EMAIL_PASSWORD')
        self.link_secret = os.getenv('LINK_SECRET', 'your-secret-key')
        self.verification_url = os.getenv('EMAIL_VERIFICATION_URL')
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

    def generate_secure_link(self, base_url, params, expiration_minutes=60):
        """Generate a secure link with an expiration timestamp."""
        expires_at = datetime.utcnow() + timedelta(minutes=expiration_minutes)
        params['expires_at'] = expires_at.isoformat()
        params_string = urllib.parse.urlencode(params)

        # Create a signature using the secret key and the params
        signature = self._generate_signature(params_string)
        params['signature'] = signature

        secure_link = f"{base_url}?{urllib.parse.urlencode(params)}"
        return secure_link

    def _generate_signature(self, data):
        """Generate HMAC signature for the data using the secret key."""
        hmac_obj = hmac.new(self.link_secret.encode(), data.encode(), hashlib.sha256)
        return base64.urlsafe_b64encode(hmac_obj.digest()).decode()

    def validate_signature(self, params):
        """Validate the signature to ensure the link hasn't been tampered with."""
        signature = params.pop('signature', None)
        if not signature:
            return False
        
        params_string = urllib.parse.urlencode(params)
        expected_signature = self._generate_signature(params_string)
        return hmac.compare_digest(expected_signature, signature)

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

