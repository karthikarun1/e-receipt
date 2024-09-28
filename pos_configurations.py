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
    Configuration class for Square POS provider.
    """

    def __init__(self):
        super().__init__(
            order_env='SQUARE_ORDER_URL',
            payment_env='SQUARE_PAYMENT_URL',
            customer_env='SQUARE_CUSTOMER_URL',
            merchant_env='SQUARE_MERCHANT_URL',
            api_key_env='SQUARE_ACCESS_TOKEN'  # Load the API key specific to Square
        )

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
