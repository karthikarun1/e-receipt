class BasePOSMapper:
    """
    Base class for mapping provider-specific data to a common data structure
    used by the DAL.
    """
    def map_order(self, order_data):
        raise NotImplementedError("This method should be overridden by subclasses.")

    def map_payment(self, payment_data):
        raise NotImplementedError("This method should be overridden by subclasses.")

    def map_customer(self, customer_data):
        raise NotImplementedError("This method should be overridden by subclasses.")


class SquarePOSMapper(BasePOSMapper):
    """
    Square-specific implementation of the BasePOSMapper.
    Maps Square order, payment, and customer data to the common format.
    """
    def map_order(self, order_data):
        """
        Map the order data from the POS system to your internal format.
        Handles both 'id' and 'order_id' as potential identifiers.
        """
        # Check for 'order_id' if 'id' doesn't exist
        order_id = order_data.get('id') or order_data.get('order_id')
        if not order_id:
            logger.error(f"Order data does not contain 'id' or 'order_id': {order_data}")
            raise KeyError("Order ID is missing in the provided data")

        return {
            'order_id': order_id,  # Now handles both 'id' and 'order_id'
            'amount': order_data.get('amount', None),
            'currency': order_data.get('currency', None),
            'created_at': order_data.get('created_at', None),
            'status': order_data.get('status', None),
            # Add other fields you need from order_data
        }

    def map_payment(self, payment_data):
        # Check for 'order_id' if 'id' doesn't exist
        payment_id = payment_data.get('id') or payment_data.get('payment_id')
        if not payment_id:
            logger.error(f"Payment data does not contain 'id' or 'payment_id': {payment_data}")
            raise KeyError("Payment ID is missing in the provided data")
        return {
            'payment_id': payment_id,
            'order_id': payment_data['order_id'],
            'customer_id': payment_data['customer_id'],
            'amount': payment_data['amount_money']['amount'],
            'currency': payment_data['amount_money']['currency'],
            'payment_method': payment_data['card_details']['card']['card_brand'] if 'card_details' in payment_data else 'unknown',
            'payment_status': payment_data['status'],
            'transaction_id': payment_data['transaction_id'],
            'payment_date': payment_data['created_at'],
            'provider_name': 'square',
            'extra_data': payment_data  # Additional data from Square API
        }

    def map_customer(self, customer_data):
        return {
            'customer_identifier': customer_data.get('card_fingerprint', ''),
            'contact_info': customer_data.get('email_address', customer_data.get('phone_number', '')),
            'provider_name': 'square',
            'extra_data': customer_data  # Additional data from Square API
        }


class CloverPOSMapper(BasePOSMapper):
    """
    Clover-specific implementation of the BasePOSMapper.
    Maps Clover order, payment, and customer data to the common format.
    """
    def map_order(self, order_data):
        return {
            'order_id': order_data['id'],
            'merchant_id': order_data['merchant']['id'],
            'total_amount': order_data['amount'],
            'currency': order_data['currency'],
            'order_status': order_data['status'],
            'order_date': order_data['created_time'],
            'provider_name': 'clover',
            'extra_data': order_data  # Additional data from Clover API
        }

    def map_payment(self, payment_data):
        return {
            'payment_id': payment_data['id'],
            'order_id': payment_data['order_id'],
            'customer_id': payment_data['customer_id'],
            'amount': payment_data['amount'],
            'currency': payment_data['currency'],
            'payment_method': payment_data['payment_method'],  # Clover-specific field
            'payment_status': payment_data['status'],
            'transaction_id': payment_data['transaction_id'],
            'payment_date': payment_data['created_time'],
            'provider_name': 'clover',
            'extra_data': payment_data  # Additional data from Clover API
        }

    def map_customer(self, customer_data):
        return {
            'customer_identifier': customer_data['phone_number'] if 'phone_number' in customer_data else customer_data['sms'],
            'contact_info': customer_data['email'] if 'email' in customer_data else customer_data['phone_number'],
            'provider_name': 'clover',
            'extra_data': customer_data  # Additional data from Clover API
        }
