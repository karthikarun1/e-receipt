from datetime import datetime
from enum import Enum
from subscription_management import SubscriptionPlanType
from role_management import Role, Permission


_ALLOWED_KEYS  = {"org_name", "plan_type", "description"}

class OrganizationUpdater:
    def __init__(self, org_manager, user_manager, role_manager, dynamodb, table_name):
        self.org_manager = org_manager
        self.user_manager = user_manager
        self.role_manager = role_manager
        self.dynamodb = dynamodb
        self.table_name = table_name

    def update_organization(self, org_id, user_id, updates):
        self._check_permissions(org_id, user_id)
        org = self._get_organization(org_id)
        self._validate_plan_type_change(org, updates)  # Validate plan_type before updating
        update_expression, expression_values = self._prepare_updates(org, user_id, updates)
        return self._apply_updates(org_id, update_expression, expression_values)

    def _check_permissions(self, org_id, user_id):
        """Check if the user has the OrganizationAdmin or SuperAdmin role."""
        if not self.role_manager.is_orgadmin_or_superadmin(org_id, user_id):
            raise PermissionError("You do not have permission to update this organization.")

    def _get_organization(self, org_id):
        return self.org_manager.get_organization_by_id(org_id)

    def _prepare_updates(self, org, user_id, updates):
        update_expression_parts = []
        expression_attribute_values = {':updated_at': str(datetime.utcnow())}

        for key, value in updates.items():
            if key not in _ALLOWED_KEYS:
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
        """Validate and assign new admins using RoleManager."""
        if not isinstance(new_admins, list):
            raise ValueError("Admins must be provided as a list of user IDs.")

        current_admins = set(org.get('admins', []))
        new_admins_set = set(new_admins)

        if user_id not in new_admins_set and len(new_admins_set) < len(current_admins):
            raise ValueError("You cannot remove yourself as an admin unless there is at least one other admin.")

        # Use RoleManager to assign the OrganizationAdmin role to new admins
        for admin_id in new_admins_set:
            if not self.user_manager.user_exists(admin_id):
                raise ValueError(f"Invalid admin ID: {admin_id}")
            if admin_id not in current_admins:
                self.role_manager.change_user_role(org['id'], admin_id, user_id, Role.ORGANIZATION_ADMIN)

    def _validate_plan_type_change(self, org, updates):
        """
        Validate the transition of plan_type, ensuring that any change to a PAID plan is valid.
        """
        if "plan_type" in updates:
            new_plan_type = updates["plan_type"]
            if isinstance(new_plan_type, str):
                try:
                    new_plan_type = SubscriptionPlanType(new_plan_type.lower())
                except ValueError:
                    raise ValueError(f"Invalid plan type: {new_plan_type}")

            if new_plan_type == SubscriptionPlanType.PAID:
                self._check_paid_plan_eligibility(org)
            elif new_plan_type == SubscriptionPlanType.FREE:
                # Additional logic can be added here if there are restrictions on switching back to free
                pass
    
    def _validate_plan_type(self, plan_type):
        if not isinstance(plan_type, SubscriptionPlanType):
            raise ValueError(f"Invalid plan type: {plan_type}")

    def _check_paid_plan_eligibility(self, org):
        """
        Check if the organization is eligible to switch to a PAID plan.
        """
        if not org.get('payment_status') == 'active':
            raise ValueError("Organization does not have an active payment method.")
        if org.get('on_free_trial'):
            raise ValueError("Organization is currently on a free trial and cannot upgrade to a paid plan.")
        if not self._is_approved_for_paid_plan(org['id']):
            raise ValueError("Organization has not been approved for a paid plan by an admin.")
    
    def _is_approved_for_paid_plan(self, org_id):
        """
        Check if the organization has been approved for a paid plan.
        This is a placeholder method; implement actual logic as needed.
        """
        return True  # Implement actual logic to check if the org is approved for a paid plan
