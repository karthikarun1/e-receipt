from datetime import datetime
from enum import Enum

class OrganizationUpdater:
    def __init__(self, org_manager, user_manager, permissions_manager, dynamodb, table_name):
        self.org_manager = org_manager
        self.user_manager = user_manager
        self.permissions_manager = permissions_manager
        self.dynamodb = dynamodb
        self.table_name = table_name

    def update_organization(self, org_id, user_id, updates):
        """
        Main function to update organization details with provided key-value pairs.
        """
        self._check_permissions(org_id, user_id)
        org = self._get_organization(org_id)
        update_expression, expression_values = self._prepare_updates(org, user_id, updates)
        return self._apply_updates(org_id, update_expression, expression_values)

    def _check_permissions(self, org_id, user_id):
        if not self.permissions_manager.is_user_admin_of_organization(org_id, user_id):
            raise PermissionError("You do not have permission to update this organization.")

    def _get_organization(self, org_id):
        return self.org_manager.get_organization_by_id(org_id)

    def _prepare_updates(self, org, user_id, updates):
        allowed_keys = {"org_name", "plan_type", "admins", "description"}
        update_expression_parts = []
        expression_attribute_values = {':updated_at': str(datetime.utcnow())}

        for key, value in updates.items():
            if key not in allowed_keys:
                raise ValueError(f"Invalid key provided: {key}")

            if key == "org_name":
                self._validate_org_name(value)
                update_expression_parts.append(f"{key} = :{key}")
                expression_attribute_values[f":{key}"] = value

            elif key == "admins":
                self._validate_admins(value, org, user_id)
                update_expression_parts.append(f"{key} = :{key}")
                expression_attribute_values[f":{key}"] = value

            elif key == "plan_type":
                self._validate_plan_type(value)
                update_expression_parts.append(f"{key} = :{key}")
                expression_attribute_values[f":{key}"] = value.value

            elif key == "description":
                update_expression_parts.append(f"{key} = :{key}")
                expression_attribute_values[f":{key}"] = value

        if not update_expression_parts:
            raise ValueError("No valid updates provided.")

        update_expression = "SET updated_at = :updated_at"
        update_expression += ", " + ", ".join(update_expression_parts)

        return update_expression, expression_attribute_values

    def _apply_updates(self, org_id, update_expression, expression_attribute_values):
        table = self.dynamodb.Table(self.table_name)
        response = table.update_item(
            Key={'id': org_id},
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="ALL_NEW"
        )
        return response.get('Attributes', {})

    def _validate_org_name(self, org_name):
        if self.org_manager.is_org_name_taken(org_name):
            raise ValueError(f"An organization with the name '{org_name}' already exists.")

    def _validate_admins(self, new_admins, org, user_id):
        if not isinstance(new_admins, list):
            raise ValueError("Admins must be provided as a list of user IDs.")

        current_admins = set(org.get('admins', []))
        new_admins_set = set(new_admins)

        if user_id not in new_admins_set and len(new_admins_set) < len(current_admins):
            raise ValueError("You cannot remove yourself as an admin unless there is at least one other admin.")

        for admin_id in new_admins_set:
            if not self.user_manager.user_exists(admin_id):
                raise ValueError(f"Invalid admin ID: {admin_id}")

    def _validate_plan_type(self, plan_type):
        if not isinstance(plan_type, SubscriptionPlanType):
            raise ValueError(f"Invalid plan type: {plan_type}")
