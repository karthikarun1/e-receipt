from email_util import EmailUtil

class BaseManager:
    def __init__(self, dynamodb, table_prefix):

        self.dynamodb = dynamodb

        self.users_table_name = f'{table_prefix}_Users'
        self.groups_table_name = f'{table_prefix}_Groups'
        self.org_table_name = f'{table_prefix}_Organizations'
        self.permissions_table_name = f'{table_prefix}_Permissions'
        self.subscriptions_table_name = f'{table_prefix}_Subscriptions'
        self.invites_table_name = f'{table_prefix}_Invites'
        self.user_group_membership_table_name = f'{table_prefix}_UserGroupMembership'

        self.users_table = dynamodb.Table(self.users_table_name)
        self.groups_table = dynamodb.Table(self.groups_table_name)
        self.org_table = dynamodb.Table(self.org_table_name)
        self.subscriptions_table = dynamodb.Table(self.subscriptions_table_name)
        self.invites_table = dynamodb.Table(self.invites_table_name)
        self.permissions_table = dynamodb.Table(self.permissions_table_name)
        self.user_group_membership_table = dynamodb.Table(self.user_group_membership_table_name)
        self.verification_table = dynamodb.Table(f'{table_prefix}_EmailVerification')
        self.reset_tokens_table = dynamodb.Table(f'{table_prefix}_ResetTokens')
        self.revoked_tokens_table = dynamodb.Table(f'{table_prefix}_RevokedTokens')

        self.email_util= EmailUtil()
