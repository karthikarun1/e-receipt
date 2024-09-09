import logging
import uuid
import os
import utils

from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from urllib.parse import unquote

from base_management import BaseManager
from email_util import EmailUtil
from notification_manager import NotificationManager
from role_management import Role, RoleManager
from user_management import UserManager

# Load environment variables
from config_loader import load_environment
load_environment()

ORG_INVITE_EMAIL_VALID_MINUTES = os.getenv('ORG_INVITE_EMAIL_VALID_MINUTES', 5)

class InvitationManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)
        self.user_manager = UserManager(dynamodb, table_prefix)
        self.role_manager = RoleManager(dynamodb, table_prefix)
        self.notification_manager = NotificationManager(EmailUtil)

    def invite_users(self, org_id, inviter_id, emails, invite_type, role=None):
        """
        Invite users to an organization via email, with checks for existing pending or expired invitations.

        Args:
            org_id (str): The organization ID.
            inviter_id (str): The ID of the user sending the invites.
            emails (list): A list of emails to invite.
            invite_type (Enum): The type of invite (e.g., MEMBER, GUEST).
            role (str): The role to assign to invited users (optional).
        
        Returns:
            dict: Summary of the invitation process.
        """
        # Fetch organization and check if the inviter is authorized
        organization = self._get_organization_and_check_inviter(org_id, inviter_id)

        # Validate role if provided
        if role:
            self._validate_role(role, org_id, inviter_id)

        # Lists to track invited users and those already in the organization
        invited_users = []
        already_in_org = []

        # Iterate through the emails and invite users if they are not already in the organization
        for email in emails:
            # Check if the user is already part of the organization
            user = self.user_manager.get_user_details_by_email(email)
            if user and user['id'] in organization['user_roles']:
                # Track emails already part of the organization
                already_in_org.append(email)
                continue

            # Check if there is an existing invitation for this email
            existing_invite = self._get_existing_invite(email, org_id)

            if existing_invite:
                # If the invite exists but is expired, delete the old invite and create a new one
                if self._is_invite_expired(existing_invite):
                    self._delete_invite(existing_invite['id'])
                    self._create_and_send_invitation(organization, {'email': email}, invite_type, role, inviter_id)
                else:
                    # Resend the existing invite if it's still valid
                    self._resend_existing_invite(existing_invite, organization)
            else:
                # Create a new invite if none exists
                self._create_and_send_invitation(organization, {'email': email}, invite_type, role, inviter_id)

            invited_users.append(email)

        # Notify the inviter if there are invited users
        if invited_users:
            inviter_email = self.user_manager.get_user_details_by_id(inviter_id)['email']
            self.notification_manager.send_invitation_sent_notification(
                inviter_email=inviter_email,
                invited_users=invited_users,
                org_name=organization['org_name']
            )

        # Prepare the response summary
        response_message = {
            "message": "Invitation process completed.",
            "invited_users": invited_users,
            "already_in_organization": already_in_org
        }

        # If no users were invited
        if not invited_users:
            response_message["message"] = "No new users were invited."

        return response_message

    def _get_existing_invite(self, email, org_id):
        """
        Retrieve an existing invite for the given email and organization, if one exists.
        """
        response = self.invites_table.query(
            IndexName='email-org_id-index',  # Assuming you have a composite index on email and org_id
            KeyConditionExpression='email = :email AND org_id = :org_id',
            ExpressionAttributeValues={
                ':email': email,
                ':org_id': org_id
            }
        )
        items = response.get('Items', [])
        return items[0] if items else None

    def _is_invite_expired(self, invite):
        """
        Check if an existing invite has expired.
        """
        expires_at = datetime.fromisoformat(invite['expires_at'])
        return datetime.utcnow() > expires_at

    def _delete_invite(self, invite_id):
        """
        Delete an expired invite from the invites table.
        """
        self.invites_table.delete_item(Key={'id': invite_id})

    def _resend_existing_invite(self, invite, organization):
        """
        Resend an existing invite email without creating a new invite.
        """
        invite_link = self.email_util.generate_secure_link(
            base_url=f"{os.getenv('BASE_URL')}/invite",
            params={"invitation_id": invite['id'], "expires_at": invite['expires_at']},
            expiration_minutes=int(ORG_INVITE_EMAIL_VALID_MINUTES)
        )
        self.email_util.send_invite_email(invite['email'], organization['org_name'], invite_link)

    def _get_organization_and_check_inviter(self, org_id, inviter_id):
        """
        Retrieve the organization and check if the inviter has permissions.

        Args:
            org_id (str): The organization ID.
            inviter_id (str): The ID of the user sending the invites.

        Returns:
            dict: The organization's details.

        Raises:
            LookupError: If the organization does not exist.
            PermissionError: If the inviter does not have permission to invite members.
        """
        # Fetch the organization details
        response = self.org_table.get_item(Key={'id': org_id})
        organization = response.get('Item')

        if not organization:
            raise LookupError("The organization does not exist.")

        print (f'--------organization {organization}')

        # Check if the inviter is part of the organization by looking in the roles
        print (f'-----inviter_id {inviter_id}')
        print (f'-----org roles %s' % organization.get('user_roles', {}))
        if inviter_id not in organization.get('user_roles', {}):
            print (f'-------case 10')
            raise PermissionError("You do not have permission to invite members.")
    
        # Ensure the inviter has the necessary role (superadmin or admin)
        inviter_role = organization['user_roles'].get(inviter_id)
        print (f'-------case 20-----inviter_role {inviter_role}')
        if inviter_role not in [Role.SUPERADMIN.value, Role.ORGANIZATION_ADMIN.value]:
            raise PermissionError("You do not have permission to invite members.")

        return organization

    def _validate_role(self, role, org_id, inviter_id):
        """
        Validates if the inviter has the necessary permissions to assign the provided role.
        Raises an exception if the role is invalid or the inviter is not authorized.
        """
        allowed_roles = [r.value for r in Role]  # Get allowed roles from Role enum
        if role not in allowed_roles:
            raise ValueError(f"Invalid role: {role}")

        # Check if the inviter has the required permissions to assign roles (either ADMIN or SUPERADMIN)
        if not self.role_manager.is_orgadmin_or_superadmin(org_id, inviter_id):
            raise PermissionError("You do not have permission to assign roles.")

    def _process_email_invitations(self, organization, emails, invite_type, role=None):
        invited_users = []
        for email in emails:
            # Send invite regardless of registration or verification status
            user = {'email': email}
            self._create_and_send_invitation(organization, user, invite_type, role)
            invited_users.append(user.get('email'))

        return invited_users

    def _create_and_send_invitation(self, organization, user, invite_type, role=None, inviter_id=None):
        """
        Create and send an invitation email to the user.

        Args:
            organization (dict): The organization to which the user is being invited.
            user (dict): The user's details, primarily their email.
            invite_type (str): The type of invitation.
            role (str): The role to assign to the user (optional).
            inviter_id (str): The ID of the user sending the invite (admin or user with permission).

        Returns:
            None
        """
        invitation_id = str(uuid.uuid4())
        expires_at = (datetime.utcnow() + timedelta(minutes=int(ORG_INVITE_EMAIL_VALID_MINUTES))).isoformat()

        # Create the invite entry in the database
        invite_data = {
            'id': invitation_id,
            'org_id': organization['id'],
            'email': user['email'],
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at,
            'invite_type': invite_type.value,
            'inviter_id': inviter_id  # Store inviter_id
        }

        if role:
            invite_data['role'] = role

        self.invites_table.put_item(Item=invite_data)

        # Generate the invite link
        invite_link = self.email_util.generate_secure_link(
            base_url=f"{os.getenv('BASE_URL')}/invite",
            params={"invitation_id": invitation_id, "expires_at": expires_at},
            expiration_minutes=int(ORG_INVITE_EMAIL_VALID_MINUTES)
        )

        # Send the invite email
        self.email_util.send_invite_email(user['email'], organization['org_name'], invite_link)

    def process_invitation(self, invitation_id, expires_at, signature):
        """
        Process an invitation after a user accepts it.

        Args:
            invitation_id (str): The unique ID of the invitation.
            expires_at (str): The expiration time of the invitation.
            signature (str): A security signature to validate the invitation.

        Returns:
            dict: A message indicating the result of the invitation processing.

        Raises:
            ValueError: If the invitation is invalid or has expired.
            LookupError: If the invitation does not exist or has already been processed.
        """
        # Decode and validate the invitation parameters
        invitation_id = unquote(invitation_id)
        expires_at = unquote(expires_at)

        params = {'invitation_id': invitation_id, 'expires_at': utils.format_timestamp(expires_at), 'signature': signature}
        if not self.email_util.validate_signature(params):
            raise ValueError("Invalid or tampered invitation link.")

        # Check if the invitation has expired
        expires_at_dt = datetime.fromisoformat(expires_at)
        if datetime.utcnow() > expires_at_dt:
            raise ValueError("The invitation link has expired.")

        # Retrieve the invitation from the database
        invite_response = self.invites_table.get_item(Key={'id': invitation_id})
        invite = invite_response.get('Item')

        if not invite or invite['status'] != 'pending':
            raise LookupError(f"Invitation not found or already processed.")

        # Check if the user is registered
        user = self.user_manager.get_user_details_by_email(invite['email'])
        if user:
            # If the user is not verified, prompt them to verify their email first
            if not user.get('verified', False):
                return {"error": "Please verify your email before joining the organization."}

            # Add the user to the organization and assign the role from the invitation
            self.org_table.update_item(
                Key={'id': invite['org_id']},
                UpdateExpression="SET #roles_field.#user_id = :user_data",
                ExpressionAttributeNames={
                    '#roles_field': 'user_roles', 
                    '#user_id': user['id']
                },
                ExpressionAttributeValues={
                    ':user_data': invite.get('role', Role.VIEWER.value)  # Assign the role (default to 'viewer' if not provided)
                }
            )

        else:
            # If the email is not registered, prompt to register
            return {"message": f"Please register with {invite['email']} to join the organization."}

        # Mark the invitation as accepted
        self.invites_table.update_item(
            Key={'id': invitation_id},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'accepted'}
        )

        # Notify the inviter when the invitee accepts the invitation
        print (f'--------------invite is {invite}')
        inviter_email = self.user_manager.get_user_details_by_id(invite['inviter_id'])['email']
        invitee_name = user['username']  # Assuming 'user' is the invitee
        self.notification_manager.send_invitation_accepted_notification(
            inviter_email=inviter_email,
            invitee_name=invitee_name,
            org_name=self.org_table.get_item(Key={'id': invite['org_id']})['Item']['org_name']
        )

        return {"message": "The invitation has been successfully accepted."}
