import boto3
import logging
import os

from botocore.exceptions import ClientError
from uuid import uuid4
from datetime import datetime, timedelta
import smtplib

from base_management import BaseManager
from enum import Enum
from email_util import EmailUtil

# Load environment variables
from config_loader import load_environment
load_environment()


class SubscriptionPlanType(Enum):
    FREE = "free"
    PAID = "paid"


class UserNotFoundException(Exception):
    pass


class SubscriptionManager(BaseManager):
    def __init__(self, dynamodb, table_prefix):
        super().__init__(dynamodb, table_prefix)

    def get_user_subscription(self, user_id):
        """Retrieve the subscription details for a given user."""
        try:
            table = self.dynamodb.Table(self.subscription_table_name)
            response = table.get_item(Key={'user_id': user_id})
            subscription = response.get('Item')
            
            if not subscription:
                # If no subscription is found, return a default free plan
                return {
                    'user_id': user_id,
                    'plan_type': 'free',
                    'status': 'active'
                }
            return subscription
        except Exception as e:
            logging.error(f"Error retrieving subscription for user {user_id}: {e}")
            raise

    def get_user_plan_type(self, user_id):
        """Automatically detect the plan type for the given user."""
        subscription = self.get_user_subscription(user_id)
        # Default to 'free' if no subscription found
        plan_type_str = subscription.get('plan_type', SubscriptionPlanType.FREE.value)
        return SubscriptionPlanType(plan_type_str)  # Convert string to PlanType enum
        
    def _initialize_tables(self):
        existing_tables = [table.name for table in self.dynamodb.tables.all()]

        if self.subscriptions_table_name not in existing_tables:
            self.dynamodb.create_table(
                TableName=self.subscriptions_table_name,
                KeySchema=[
                    {'AttributeName': 'subscription_id', 'KeyType': 'HASH'},  # Partition key
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'subscription_id', 'AttributeType': 'S'},
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5,
                }
            )

    def create_subscription(self, user_id, plan_type='individual', start_date=None, end_date=None):
        # Check if the user exists first
        user = self.get_user_details(user_id)
        
        if not user:
            print(f"Cannot create subscription. User '{user_id}' does not exist.")
            if not user:
                raise UserNotFoundException(f"Cannot create subscription. User '{user_id}' does not exist.")

        subscription_id = str(uuid4())
        start_date = start_date or datetime.utcnow()
        end_date = end_date or start_date + timedelta(days=30)  # Default to a 30-day subscription

        print(f"Creating subscription with ID {subscription_id} for user {user_id}")

        table = self.dynamodb.Table(self.subscriptions_table_name)
        try:
            item = {
                'id': subscription_id,  # Updated key name to match table schema
                'user_id': user_id,
                'plan_type': plan_type,
                'start_date': str(start_date),
                'end_date': str(end_date),
                'status': 'pending',  # Initial status is pending
                'created_at': str(datetime.utcnow()),
                'updated_at': str(datetime.utcnow())
            }
            print(f"Subscription Item: {item}")  # Debugging output

            table.put_item(Item=item)
            print("Subscription item created successfully.")  # Debugging output after successful put_item

            # Send confirmation email
            if 'email' in user:
                print(f"Sending confirmation email to {user['email']} for subscription {subscription_id}")
                self.email_util.send_confirmation_email(user['email'], subscription_id)
                print("Confirmation email sent successfully.")
            else:
                print(f"User '{user_id}' is missing an email address. Cannot send confirmation.")

        except ClientError as e:
            print(f"A ClientError occurred: {e.response['Error']['Message']}")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")

        return subscription_id

    def get_subscription(self, subscription_id):
        table = self.dynamodb.Table(self.subscriptions_table_name)
        try:
            response = table.get_item(Key={'subscription_id': subscription_id})
            return response.get('Item')
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def get_organization_subscription(self, org_id):
        """Retrieve the subscription details for a given organization."""
        try:
            table = self.dynamodb.Table(self.subscription_table_name)
            response = table.get_item(Key={'org_id': org_id})
            subscription = response.get('Item')
            
            if not subscription:
                # If no subscription is found, return a default free plan
                return {
                    'org_id': org_id,
                    'plan_type': 'free',
                    'status': 'active'
                }
            
            return subscription
        except Exception as e:
            logging.error(f"Error retrieving subscription for organization {org_id}: {e}")
            raise

    def get_user_subscription(self, user_id):
        """Retrieve the user's organization subscription or their individual subscription."""
        try:
            # Get the organization ID the user belongs to
            user = self.get_user_details(user_id)
            org_id = user.get('org_id')
            
            if org_id:
                # Check the organization's subscription
                return self.get_organization_subscription(org_id)
            else:
                # Fall back to individual user subscription if no org_id is found
                return self.get_individual_user_subscription(user_id)
        except Exception as e:
            logging.error(f"Error retrieving subscription for user {user_id}: {e}")
            raise

    def get_individual_user_subscription(self, user_id):
        """Retrieve the individual subscription details for a user."""
        try:
            response = self.subscriptions_table.get_item(Key={'id': user_id})
            subscription = response.get('Item')
            
            if not subscription:
                # If no subscription is found, return a default free plan
                return {
                    'user_id': user_id,
                    'plan_type': 'free',
                    'status': 'active'
                }
            
            return subscription
        except Exception as e:
            logging.error(f"Error retrieving individual subscription for user {user_id}: {e}")
            raise

    def update_subscription(self, subscription_id, plan_type=None, status=None, end_date=None):
        table = self.dynamodb.Table(self.subscriptions_table_name)
        update_expression = "SET updated_at = :updated_at"
        expression_attribute_values = {':updated_at': str(datetime.utcnow())}

        if plan_type:
            update_expression += ", plan_type = :plan_type"
            expression_attribute_values[':plan_type'] = plan_type

        if status:
            update_expression += ", status = :status"
            expression_attribute_values[':status'] = status

        if end_date:
            update_expression += ", end_date = :end_date"
            expression_attribute_values[':end_date'] = str(end_date)

        try:
            table.update_item(
                Key={'subscription_id': subscription_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_attribute_values,
                ReturnValues="UPDATED_NEW"
            )
        except ClientError as e:
            print(e.response['Error']['Message'])

    def delete_subscription(self, subscription_id):
        table = self.dynamodb.Table(self.subscriptions_table_name)
        try:
            table.delete_item(Key={'subscription_id': subscription_id})
        except ClientError as e:
            print(e.response['Error']['Message'])

    def list_subscriptions(self, user_id=None):
        table = self.dynamodb.Table(self.subscriptions_table_name)
        try:
            if user_id:
                response = table.scan(
                    FilterExpression="user_id = :user_id",
                    ExpressionAttributeValues={":user_id": user_id}
                )
            else:
                response = table.scan()
            return response.get('Items', [])
        except ClientError as e:
            print(e.response['Error']['Message'])
            return []

    def confirm_subscription(self, subscription_id):
        subscription = self.get_subscription(subscription_id)
        if not subscription:
            raise ValueError("Subscription not found.")

        if subscription['status'] != 'pending':
            raise ValueError("Subscription is not in a pending state.")

        # Activate the subscription
        self.update_subscription(subscription_id, status='active')
        user = self.get_user_details(subscription['user_id'])
        self.email_util.send_activation_email(user['email'], subscription_id)

    def cancel_subscription(self, subscription_id):
        subscription = self.get_subscription(subscription_id)
        if not subscription:
            raise ValueError("Subscription not found.")

        if subscription['status'] == 'cancelled':
            raise ValueError("Subscription is already cancelled.")

        # Mark the subscription as cancelled
        self.update_subscription(subscription_id, status='cancelled')

    def renew_subscription(self, subscription_id, additional_days=30):
        subscription = self.get_subscription(subscription_id)
        if not subscription:
            raise ValueError("Subscription not found.")

        if subscription['status'] != 'active':
            raise ValueError("Only active subscriptions can be renewed.")

        # Extend the subscription end date
        new_end_date = datetime.strptime(subscription['end_date'], "%Y-%m-%d %H:%M:%S.%f") + timedelta(days=additional_days)
        self.update_subscription(subscription_id, end_date=new_end_date)

    def send_confirmation_email(self, user_id, subscription_id):
        user = self.get_user_details(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} does not exist.")

        subject = "Confirm Your Subscription"
        body = f"Please confirm your subscription by clicking on the following link: https://example.com/confirm?subscription_id={subscription_id}"

        self._send_email(user['email'], subject, body)

    def send_activation_email(self, user_id, subscription_id):
        user = self.get_user_details(user_id)
        if not user:
            raise ValueError(f"User with ID {user_id} does not exist.")

        subject = "Your Subscription is Now Active"
        body = f"Your subscription with ID {subscription_id} is now active. Thank you for subscribing!"

        self._send_email(user['email'], subject, body)

    def get_user_details(self, user_id):
        table = self.dynamodb.Table(self.users_table_name)
        try:
            response = table.get_item(Key={'id': user_id})
            return response.get('Item')
        except ClientError as e:
            print(e.response['Error']['Message'])
            return None

    def is_team_plan(self, user_id):
        subscriptions = self.list_subscriptions(user_id)
        for subscription in subscriptions:
            if subscription['plan_type'] == 'team' and subscription['status'] == 'active':
                return True
        return False

# Example usage:
if __name__ == "__main__":
    sub_mgmt = SubscriptionManagement()
    subscription_id = sub_mgmt.create_subscription(user_id='user_123', plan_type='team')
    print(f'Created subscription with ID: {subscription_id}')

    subscription = sub_mgmt.get_subscription(subscription_id)
    print(f'Subscription details: {subscription}')

