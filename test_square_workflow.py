import os
import uuid
import logging
import requests
from square_pos_test_automation import SquareTestAutomation  # Ensure this module is correctly imported

# Setup logging for detailed output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# load environment variables
from config_loader import load_environment
load_environment()

# Square API configuration - replace with your actual sandbox access token
ACCESS_TOKEN = os.getenv('SQUARE_ACCESS_TOKEN')
LOCATION_ID = os.getenv('SQUARE_LOCATION_ID')
BASE_URL = os.getenv('BASE_URL')

# Initialize the SquareTestAutomation class
square_test_automation = SquareTestAutomation(access_token=ACCESS_TOKEN, location_id=LOCATION_ID)

def generate_unique_order_details():
    """
    Generates unique order details for testing, ensuring no conflicts between test runs.
    """
    return {
        "line_items": [
            {
                "name": f"Test Item {uuid.uuid4()}",  # Unique item name for each test
                "quantity": "1",
                "base_price_money": {
                    "amount": 1000,  # Amount in cents (e.g., 1000 = $10.00)
                    "currency": "USD"
                }
            }
        ],
        "idempotency_key": str(uuid.uuid4())  # Unique idempotency key to prevent duplicate orders
    }


def test_create_order_and_make_payment():
    """
    Tests the creation of an order and makes a payment using the Square API, validating the response.
    """
    # Generate unique order details
    order_details = generate_unique_order_details()

    # Log the test initiation
    logging.info("Starting test: Create Order and Make Payment")

    # Step 1: Create the order
    response = square_test_automation.create_order(order_details)

    # Validate the order creation response
    if "order" in response and "id" in response["order"]:
        order_id = response["order"]["id"]
        logging.info(f"Order created successfully with Order ID: {order_id}")

        # Step 2: Make a payment for the created order
        payment_response = square_test_automation.make_payment(order_id=order_id)

        # Validate the payment response
        if "payment" in payment_response and "id" in payment_response["payment"]:
            payment_id = payment_response["payment"]["id"]
            card_fingerprint = payment_response["payment"]["card_details"]["card"]["fingerprint"]
            logging.info(f"Payment made successfully with Payment ID: {payment_id}")

            # Step 3: Simulate the notify payment with obtained IDs
            simulate_notify_payment(order_id, payment_id, card_fingerprint)

            # Step 4: Simulate form submission by the customer
            simulate_form_submission(payment_id, order_id, card_fingerprint)
        else:
            logging.error(f"Failed to make payment: {payment_response.get('error')}")
    else:
        logging.error(f"Failed to create order: {response.get('error')}")


def simulate_notify_payment(order_id, payment_id, card_fingerprint):
    """
    Sends a request to the /notify_square_payment endpoint using the data obtained from the test.
    """
    notify_payment_url = "https://c676-2603-8081-16f0-da30-7d51-6f45-c448-b657.ngrok-free.app/notify_square_payment"

    payload = {
        "order_id": order_id,
        "payment_id": payment_id,
        "card_fingerprint": card_fingerprint,
        "customer_info": {
            "email": "testuser@example.com"
        }
    }

    try:
        logging.info("Sending request to /notify_square_payment with obtained data.")
        response = requests.post(notify_payment_url, json=payload)
        response.raise_for_status()  # Raises an exception for HTTP errors

        # Try to parse the response as JSON
        try:
            response_json = response.json()
            logging.info(f"Response from /notify_square_payment (JSON): {response_json}")
            print(response_json)
        except requests.exceptions.JSONDecodeError:
            # If response is not JSON, log and print the raw text
            logging.info("Received non-JSON response, printing raw HTML content.")
            logging.info(f"Response content: {response.text}")
            print(response.text)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending request to /notify_square_payment: {e}")


def simulate_form_submission(payment_id, order_id, card_fingerprint):
    """
    Sends a request to the /square_submit_customer_contact_info endpoint to simulate form submission.
    """
    submit_contact_info_url = "https://c676-2603-8081-16f0-da30-7d51-6f45-c448-b657.ngrok-free.app/square_submit_customer_contact_info"

    # Payload simulating the form submission data
    payload = {
        "payment_id": payment_id,
        "order_id": order_id,
        "card_fingerprint": card_fingerprint,
        "contact_info": {
            "email": os.getenv('SQUARE_CUSTOMER_EMAIL')  # Simulating customer's email entered in the form
        }
    }

    try:
        logging.info("Sending request to /square_submit_customer_contact_info with form data.")
        response = requests.post(submit_contact_info_url, json=payload)
        response.raise_for_status()  # Raises an exception for HTTP errors

        # Log and print the response
        logging.info(f"Response from /square_submit_customer_contact_info: {response.json()}")
        print(response.json())

    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending request to /square_submit_customer_contact_info: {e}")


if __name__ == "__main__":
    # Run the system test
    test_create_order_and_make_payment()
