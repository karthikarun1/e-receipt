import logging
import uuid
import os
import utils

from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from urllib.parse import unquote

# Load environment variables
from config_loader import load_environment
load_environment()

ORG_INVITE_EMAIL_VALID_DAYS = os.getenv('ORG_INVITE_EMAIL_VALID_DAYS', 1)

class InvitationManager:
    def __init__(self, org_table, users_table, invites_table, email_util):
        self.org_table = org_table
        self.users_table = users_table
        self.invites_table = invites_table
        self.email_util = email_util

    def invite_users(self, org_id, inviter_id, user_ids, invite_type):
        # Fetch organization and check if the inviter is authorized
        organization = self._get_organization_and_check_inviter(org_id, inviter_id)

        # Process invitations and collect invited users
        invited_users = self._process_invitations(organization, user_ids, invite_type)

        # Return appropriate response
        if not invited_users:
            return {"message": "No users met the criteria to be invited."}

        return {
            "message": "Invitations sent successfully.",
            "invited_users": invited_users
        }

    def _get_organization_and_check_inviter(self, org_id, inviter_id):
        response = self.org_table.get_item(Key={'id': org_id})
        organization = response.get('Item')

        if not organization:
            raise LookupError("The organization you are trying to invite users to does not exist.")

        if inviter_id not in organization.get('admins', []):
            raise PermissionError("You do not have permission to invite members to this organization.")

        return organization

    def _process_invitations(self, organization, user_ids, invite_type):
        invited_users = []
        for user_id in user_ids:
            # Get user if verified
            user = self._get_user_if_verified(user_id)

            # Check if user is verified and exists
            if user is None:
                logging.info(
                    f"User {user_id} is not verified or does not exist."
                )
                continue

            # Check if the user is already a member of the organization
            if user_id in organization.get('users', []):
                logging.info(
                    f"User {user_id} is already a member of the organization."
                )
                continue

            # Create and send the invitation
            self._create_and_send_invitation(organization, user, invite_type)
            invited_users.append(user_id)

        return invited_users

    def _get_user_if_verified(self, user_id):
        user_response = self.users_table.get_item(Key={'id': user_id})
        user = user_response.get('Item')

        if not user:
            raise LookupError(f"User with ID {user_id} does not exist.")

        if not user.get('verified', False):
            logging.info(f"User {user_id} is not verified and cannot be invited.")
            return None

        return user

    def _create_and_send_invitation(self, organization, user, invite_type):
        invitation_id = str(uuid.uuid4())
        self.invites_table.put_item(
            Item={
                'id': invitation_id,
                'org_id': organization['id'],
                'user_id': user['id'],
                'status': 'pending',
                'invite_type': invite_type.value,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': (datetime.utcnow() + timedelta(days=int(ORG_INVITE_EMAIL_VALID_DAYS))).isoformat()
            }
        )

        # Generate invite link and send email
        invite_link = self.email_util.generate_secure_link(
            base_url=f"{os.getenv('BASE_URL')}/invite",
            params={"invitation_id": invitation_id},
            expiration_minutes=int(ORG_INVITE_EMAIL_VALID_DAYS) * 24 * 60
        )

        self.email_util.send_invite_email(user['email'], organization['org_name'], invite_link)

    def accept_invite(self, invite_id):
        # Fetch the invite from the database
        invite_response = self.invites_table.get_item(Key={'id': invite_id})
        invite = invite_response.get('Item')

        if not invite or invite['status'] != 'pending':
            raise LookupError(f"Invite {invite_id} not found or already processed.")

        # Add the user to the organization
        self.org_table.update_item(
            Key={'id': invite['org_id']},
            UpdateExpression="ADD users :user_id",
            ExpressionAttributeValues={':user_id': invite['user_id']}
        )

        # Mark the invite as accepted
        self.invites_table.update_item(
            Key={'id': invite_id},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'accepted'}
        )

        return {"message": "Invitation accepted."}

    def reject_invite(self, invite_id):
        # Fetch the invite from the database
        invite_response = self.invites_table.get_item(Key={'id': invite_id})
        invite = invite_response.get('Item')

        if not invite or invite['status'] != 'pending':
            raise LookupError(f"Invite {invite_id} not found or already processed.")

        # Mark the invite as rejected
        self.invites_table.update_item(
            Key={'id': invite_id},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'rejected'}
        )

        return {"message": "Invitation rejected."}

    def process_invitation(self, invitation_id, expires_at, signature):
        # Validate the signature
        # Decode the URL-encoded parameters
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
            raise LookupError(f"Invitation {invitation_id} not found or already processed.")

        # Get the org_id from the invite object
        org_id = invite.get('org_id')
        if not org_id:
            raise LookupError(f"Organization ID not found in invitation {invitation_id}.")

        new_user_id = invite.get('user_id')
        if not new_user_id:
            raise LookupError(f"User ID not found in invitation {invitation_id}.")

        self.org_table.update_item(
            Key={'id': org_id},
            UpdateExpression="ADD #users_field :user_id_set",
            ExpressionAttributeNames={'#users_field': 'users'},  # Alias for 'users'
            ExpressionAttributeValues={':user_id_set': set([new_user_id])}  # Add user to the set
        )

        # Update the invitation status to 'accepted'
        self.invites_table.update_item(
            Key={'id': invitation_id},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': 'accepted'}
        )

        return {"message": "The invitation has been successfully accepted."}
