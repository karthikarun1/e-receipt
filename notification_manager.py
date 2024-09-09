import logging
import os
from datetime import datetime, timedelta
from email_util import EmailUtil
from role_management import Role

# Load environment variables
from config_loader import load_environment
load_environment()

# Set up logging
logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self, email_util: EmailUtil):
        self.email_util = email_util()
        self.base_url = os.getenv('BASE_URL', 'http://localhost:5000')
        self.org_invite_email_valid_minutes = int(os.getenv('ORG_INVITE_EMAIL_VALID_MINUTES', 60))

    def send_invitation_sent_notification(self, inviter_email, invited_users, org_name):
        """
        Sends a notification to the inviter once the invitations are successfully sent.
        
        :param inviter_email: str - The email of the inviter (admin).
        :param invited_users: list - List of invited user emails.
        :param org_name: str - The name of the organization.
        """
        subject = f"Invitations sent to join {org_name}"
        invited_users_list = ", ".join(invited_users)
        body = f"""Hi,

You have successfully sent invitations to the following users to join {org_name}:
{invited_users_list}

Best regards,
{org_name} Team"""
        
        try:
            print(f"------Inviter Email: {inviter_email}, Subject: {subject}, Body: {body}")
            self.email_util.send_email(inviter_email, subject, body)
            logger.info(f"Invitation sent notification sent to {inviter_email}")
        except Exception as e:
            logger.error(f"Failed to send invitation sent notification to {inviter_email}: {e}")
            raise

    def send_invitation_accepted_notification(self, inviter_email, invitee_name, org_name):
        """
        Sends a notification email to the inviter when the invitee accepts the invitation.
        
        :param inviter_email: str - The email of the inviter.
        :param invitee_name: str - The name of the invitee who accepted.
        :param org_name: str - The organization name.
        """
        subject = f"{invitee_name} has accepted your invitation to join {org_name}"
        body = f"""Hi,

{invitee_name} has successfully joined {org_name}.

Best regards,
{org_name} Team"""
        
        try:
            self.email_util.send_email(inviter_email, subject, body)
            logger.info(f"Invitation accepted notification sent to {inviter_email}")
        except Exception as e:
            logger.error(f"Failed to send invitation accepted notification to {inviter_email}: {e}")
    
    def send_role_change_notification(self, user_email, new_role, org_name):
        """
        Sends a notification to a user when their role is changed.
        
        :param user_email: str - The email of the user whose role was changed.
        :param new_role: str - The new role assigned to the user.
        :param org_name: str - The organization name.
        """
        subject = f"Your role in {org_name} has been changed"
        body = f"""Hi,

Your role in {org_name} has been updated to {new_role}.

Best regards,
{org_name} Team"""
        
        try:
            self.email_util.send_email(user_email, subject, body)
            logger.info(f"Role change notification sent to {user_email} for role {new_role}")
        except Exception as e:
            logger.error(f"Failed to send role change notification to {user_email}: {e}")
    
    def send_user_removal_notification(self, removed_user_email, org_name):
        """
        Sends a notification to a user when they are removed from an organization.
        
        :param removed_user_email: str - The email of the removed user.
        :param org_name: str - The organization name.
        """
        subject = f"You have been removed from {org_name}"
        body = f"""Hi,

You have been removed from {org_name}. If you believe this is a mistake, please contact the organization admin.

Best regards,
{org_name} Team"""
        
        try:
            self.email_util.send_email(removed_user_email, subject, body)
            logger.info(f"User removal notification sent to {removed_user_email}")
        except Exception as e:
            logger.error(f"Failed to send user removal notification to {removed_user_email}: {e}")
    
    def send_organization_update_notification(self, admin_emails, org_name, update_details):
        """
        Sends a notification to all admins when an organization is updated.
        
        :param admin_emails: list - A list of admin emails.
        :param org_name: str - The organization name.
        :param update_details: str - The details of the update (e.g., plan change, name change).
        """
        subject = f"{org_name} has been updated"
        body = f"""Hi,

{org_name} has been updated with the following changes:
{update_details}

Best regards,
{org_name} Team"""
        
        for admin_email in admin_emails:
            try:
                self.email_util.send_email(admin_email, subject, body)
                logger.info(f"Organization update notification sent to {admin_email}")
            except Exception as e:
                logger.error(f"Failed to send organization update notification to {admin_email}: {e}")
    
    def send_subscription_update_notification(self, admin_emails, org_name, subscription_details):
        """
        Sends a notification to all admins when the subscription plan is updated.
        
        :param admin_emails: list - A list of admin emails.
        :param org_name: str - The organization name.
        :param subscription_details: str - Details about the subscription update.
        """
        subject = f"{org_name}'s subscription has been updated"
        body = f"""Hi,

{org_name}'s subscription plan has been updated:
{subscription_details}

Best regards,
{org_name} Team"""
        
        for admin_email in admin_emails:
            try:
                self.email_util.send_email(admin_email, subject, body)
                logger.info(f"Subscription update notification sent to {admin_email}")
            except Exception as e:
                logger.error(f"Failed to send subscription update notification to {admin_email}: {e}")
    
    def send_organization_deletion_notification(self, user_emails, org_name):
        """
        Sends a notification to all users when an organization is deleted.
        
        :param user_emails: list - A list of user emails.
        :param org_name: str - The organization name.
        """
        subject = f"{org_name} has been deleted"
        body = f"""Hi,

{org_name} has been deleted and you have been removed from the organization.

Best regards,
{org_name} Team"""
        
        for user_email in user_emails:
            try:
                self.email_util.send_email(user_email, subject, body)
                logger.info(f"Organization deletion notification sent to {user_email}")
            except Exception as e:
                logger.error(f"Failed to send organization deletion notification to {user_email}: {e}")
    
    def send_limit_warning_notification(self, admin_emails, org_name, limit_details):
        """
        Sends a warning notification when the organization is nearing or exceeding limits (e.g., user limit).
        
        :param admin_emails: list - A list of admin emails.
        :param org_name: str - The organization name.
        :param limit_details: str - Details about the limit that has been exceeded or is close to being exceeded.
        """
        subject = f"Warning: {org_name} is nearing its limits"
        body = f"""Hi,

{org_name} is nearing the following limits:
{limit_details}

Please take necessary action.

Best regards,
{org_name} Team"""
        
        for admin_email in admin_emails:
            try:
                self.email_util.send_email(admin_email, subject, body)
                logger.info(f"Limit warning notification sent to {admin_email}")
            except Exception as e:
                logger.error(f"Failed to send limit warning notification to {admin_email}: {e}")
