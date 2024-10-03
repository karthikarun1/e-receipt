import uuid
from datetime import datetime
from models import Provider, Order, Payment, Customer, Merchant  # Import the ORM models
from extensions import db

class BasePOSMapper:
    """
    Base class for mapping provider-specific data to a common data structure
    used by the ORM.
    """
    def map_order(self, order_data):
        raise NotImplementedError("This method should be overridden by subclasses.")

    def map_payment(self, payment_data):
        raise NotImplementedError("This method should be overridden by subclasses.")

    def map_customer(self, customer_data):
        raise NotImplementedError("This method should be overridden by subclasses.")

    def map_merchant(self, merchant_data):
        raise NotImplementedError("This method should be overridden by subclasses.")


class SquarePOSMapper(BasePOSMapper):
    """
    Square-specific implementation of the BasePOSMapper.
    Maps Square order, payment, customer, and merchant data to ORM models.
    """

    def map_order(self, order_data):
        """
        Map Square order data to the Order ORM model.
        """
        order_id = order_data.get('id', str(uuid.uuid4()))  # Generate UUID if missing

        # Create an Order ORM object with all the relevant fields mapped
        order = Order(
            id=order_id,
            customer_id=order_data.get('customer_id'),  # Ensure the customer ID is provided
            provider_id=order_data.get('provider_id', None),  # Provider ID from the POS system, default None
            merchant_id=order_data.get('merchant_id', None),  # Map merchant_id
            total_amount=order_data.get('amount', 0.00),  # Default to 0 if missing
            order_status=order_data.get('status', 'pending'),  # Default to 'pending'
            order_date=order_data.get('created_at', datetime.utcnow()),  # Default to current time if missing
            currency=order_data.get('currency', 'USD'),  # Default to 'USD'
            created_at=order_data.get('created_at', datetime.utcnow()),  # Default to current time
            updated_at=order_data.get('updated_at', datetime.utcnow())  # Default to current time
        )

        # Add order to the session
        db.session.add(order)
        return order

    def map_payment(self, payment_data):
        """
        Map Square payment data to the Payment ORM model.
        """
        payment_id = payment_data.get('id') or payment_data.get('payment_id', str(uuid.uuid4()))  # Generate UUID if missing

        # Create a Payment ORM object
        payment = Payment(
            id=payment_id,
            order_id=payment_data.get('order_id'),
            customer_id=payment_data.get('customer_id'),
            merchant_id=payment_data.get('merchant_id', None),  # Map merchant_id
            amount=payment_data.get('amount_money', {}).get('amount', 0.00),  # Default to 0 if missing
            currency=payment_data.get('amount_money', {}).get('currency', 'USD'),  # Default to 'USD'
            payment_method=payment_data.get('card_details', {}).get('card', {}).get('card_brand', 'unknown'),  # Default if missing
            payment_status=payment_data.get('status', 'pending'),  # Default to 'pending'
            transaction_id=payment_data.get('transaction_id', 'unknown'),  # Default to 'unknown'
            payment_date=payment_data.get('created_at', datetime.utcnow()),  # Default to current time
            provider_id=None,  # Set provider_id if needed
        )

        # Add payment to the session
        db.session.add(payment)
        return payment

    def map_customer(self, customer_data):
        """
        Map Square customer data to the Customer ORM model.
        """
        # Use email or phone, if both are missing, generate a UUID-based email
        contact_info = customer_data.get('email_address') or customer_data.get('phone_number') or f'no-email-{uuid.uuid4()}@example.com'
        
        customer = Customer(
            email=customer_data.get('email_address', f'no-email-{uuid.uuid4()}@example.com'),  # Default if missing
            mobile_number=customer_data.get('phone_number', '000-000-0000'),  # Default if missing
        )

        # Add customer to the session
        db.session.add(customer)
        return customer

    def map_merchant(self, merchant_data):
        """
        Map Square merchant (location) data to the Merchant ORM model.
        """
        merchant_id = merchant_data.get('location_id', str(uuid.uuid4()))  # Use location_id as merchant_id

        merchant = Merchant(
            id=merchant_id,
            name=merchant_data.get('name', 'Unknown Merchant'),
            address=merchant_data.get('address', 'Unknown Address'),
            contact_info=merchant_data.get('contact_info', 'No Contact Info'),
        )

        # Add merchant to the session
        db.session.add(merchant)
        return merchant
