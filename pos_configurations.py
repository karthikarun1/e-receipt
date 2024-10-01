import os

# load environment variables
from config_loader import load_environment
load_environment()


class POSConfig:
    """
    Base configuration class for POS providers.
    """

    def __init__(self, order_env, payment_env, customer_env, merchant_env, api_key_env):
        self.order_url = os.getenv(order_env)
        self.payment_url = os.getenv(payment_env)
        self.customer_url = os.getenv(customer_env)
        self.merchant_url = os.getenv(merchant_env)
        self.api_key = os.getenv(api_key_env)  # Load the API key from the environment

        # Validate URLs and API key
        self.validate_urls()

    def validate_urls(self):
        """
        Validates that all necessary URLs and the API key are loaded from environment variables.
        Raises an exception if any URL or the API key is missing.
        """
        missing_urls = [attr for attr in dir(self) if attr.endswith('_url') and not getattr(self, attr)]
        if not self.api_key:
            missing_urls.append('api_key')
        if missing_urls:
            raise ValueError(f"Missing one or more required URLs or API key: {', '.join(missing_urls)}")


class SquarePOSConfig(POSConfig):
    """
    Configuration and data parsing class for Square POS provider.
    """

    def __init__(self):
        super().__init__(
            order_env='SQUARE_ORDER_URL',
            payment_env='SQUARE_PAYMENT_URL',
            customer_env='SQUARE_CUSTOMER_URL',
            merchant_env='SQUARE_MERCHANT_URL',
            api_key_env='SQUARE_ACCESS_TOKEN'  # Load the API key specific to Square
        )

    # Parsing methods specific to Square
    def parse_order_data(self, raw_data):
        order = raw_data.get('order', {})
        return {
            'order_id': order.get('id'),
            'location_id': order.get('location_id'),
            'total_amount': order.get('total_money', {}).get('amount'),
            'currency': order.get('total_money', {}).get('currency'),
            'created_at': order.get('created_at'),
            'updated_at': order.get('updated_at'),
            'line_items': order.get('line_items', []),
            'state': order.get('state'),
            'net_amount': order.get('net_amounts', {}).get('total_money', {}).get('amount')
        }

    def parse_payment_data(self, raw_data):
        payment = raw_data.get('payment', {})
        return {
            'payment_id': payment.get('id'),
            'order_id': payment.get('order_id'),
            'location_id': payment.get('location_id'),
            'status': payment.get('status'),
            'amount': payment.get('amount_money', {}).get('amount'),
            'currency': payment.get('amount_money', {}).get('currency'),
            'created_at': payment.get('created_at'),
            'updated_at': payment.get('updated_at'),
            'card_details': {
                'card_brand': payment.get('card_details', {}).get('card', {}).get('card_brand'),
                'last_4': payment.get('card_details', {}).get('card', {}).get('last_4'),
                'fingerprint': payment.get('card_details', {}).get('card', {}).get('fingerprint'),
                'exp_month': payment.get('card_details', {}).get('card', {}).get('exp_month'),
                'exp_year': payment.get('card_details', {}).get('card', {}).get('exp_year')
            },
            'receipt_url': payment.get('receipt_url'),
            'receipt_number': payment.get('receipt_number')
        }

    def parse_customer_data(self, raw_data):
        # Assuming customer data is fetched separately and provided here
        return {
            'customer_id': raw_data.get('id'),
            'name': raw_data.get('given_name', 'Unknown') + ' ' + raw_data.get('family_name', 'Unknown'),
            'email': raw_data.get('email_address'),
        }

    def get_merchant_id(self, raw_order_data, raw_payment_data):
        """
        Extract the merchant ID dynamically from the order or payment data.
        For Square POS, we'll use the location_id, which corresponds to the merchant.
        """
        merchant_id = raw_order_data.get('location_id') or raw_payment_data.get('location_id')
        
        if not merchant_id:
            raise ValueError("Merchant ID (location_id) not found in order or payment data")
        
        return merchant_id

    def fetch_merchant_data(self, merchant_id):
        """
        Fetch merchant details from Square using the location_id (merchant_id).
        """
        url = f"{self.api_base_url}/locations/{merchant_id}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code != 200:
            raise ValueError(f"Failed to fetch merchant data for merchant_id: {merchant_id}")
        
        return response.json()  # Return merchant details

    def parse_merchant_data(self, raw_data):
        return {
            'merchant_id': raw_data.get('id'),
            'name': raw_data.get('business_name'),
        }


'''
class CloverPOSConfig(POSConfig):
    """
    Configuration class for Clover POS provider.
    """

    def __init__(self):
        super().__init__(
            order_env='CLOVER_ORDER_URL',
            payment_env='CLOVER_PAYMENT_URL',
            customer_env='CLOVER_CUSTOMER_URL',
            merchant_env='CLOVER_MERCHANT_URL',
            api_key_env='CLOVER_API_KEY'  # Load the API key specific to Clover
        )

# Add more classes here for additional POS providers as needed.
'''
