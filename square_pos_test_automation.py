import logging
import requests
import uuid

from functools import wraps

def handle_request_errors(func):
    """
    Decorator to handle request-related errors and log them consistently.

    Args:
        func (function): The function to wrap with error handling.

    Returns:
        function: The wrapped function with error handling.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.RequestException as e:
            # Handling any request-related errors and logging them
            logging.error(f"Error in {func.__name__}: {e}")
            return {"error": str(e)}
    return wrapper

class SquareTestAutomation:
    def __init__(self, access_token, location_id):
        """
        Initializes the SquareTestAutomation class with access token and location details.

        Args:
            access_token (str): The Square access token for API authentication.
            location_id (str): The location ID for creating orders and processing payments.
        """
        self.access_token = access_token
        self.location_id = location_id
        self.base_url = "https://connect.squareupsandbox.com"
        self.headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }

    @handle_request_errors
    def create_order(self, order_details):
        """
        Creates an order using the Square API.

        Args:
            order_details (dict): Details of the order, including items, quantities, and pricing.

        Returns:
            dict: The response from Square API containing order details or an error message.
        """
        url = f"{self.base_url}/v2/orders"

        # Constructing the payload for the order
        payload = {
            "order": {
                "location_id": self.location_id,
                "line_items": order_details["line_items"]
            },
            "idempotency_key": order_details["idempotency_key"]  # Ensures the request is unique
        }

        # Sending the request to create the order
        response = requests.post(url, json=payload, headers=self.headers)
        response.raise_for_status()  # Raises an exception for HTTP errors

        # Logging the successful order creation
        logging.info(f"Order created successfully: {response.json()}")
        return response.json()

    @handle_request_errors
    def make_payment(self, order_id, source_id="cnon:card-nonce-ok", amount=1000, currency="USD"):
        """
        Makes a payment using the Square API for the specified order.

        Args:
            order_id (str): The ID of the order to be paid.
            source_id (str): The payment source (e.g., card nonce). Default is a sandbox card nonce.
            amount (int): The amount to be charged in the smallest currency unit (e.g., cents).
            currency (str): The currency code (default is USD).

        Returns:
            dict: The response from Square API containing payment details or an error message.
        """
        url = f"{self.base_url}/v2/payments"

        # Construct the payload for the payment
        payload = {
            "source_id": source_id,  # Sandbox nonce for a successful payment
            "amount_money": {
                "amount": amount,  # Amount in cents
                "currency": currency
            },
            "idempotency_key": str(uuid.uuid4()),  # Unique key to prevent duplicate payments
            "order_id": order_id,
            "location_id": self.location_id
        }

        # Sending the request to process the payment
        response = requests.post(url, json=payload, headers=self.headers)
        response.raise_for_status()  # Raises an exception for HTTP errors

        # Logging the successful payment
        logging.info(f"Payment made successfully: {response.json()}")
        return response.json()
