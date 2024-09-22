import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

from square_dal import SquareDAL
from datetime import datetime

square_dal = SquareDAL(db_session=postgresql_db_utils.get_connection())

# load environment variables
from config_loader import load_environment
load_environment()


# Define constants for Square API
SQUARE_API_BASE_URL = os.getenv('SQUARE_API_BASE_URL')
SQUARE_API_RETRIES = 3  # Number of retry attempts
SQUARE_API_TIMEOUT = 5  # Timeout for Square API requests in seconds
SQUARE_API_HEADERS = {
    "Authorization": f"Bearer {os.getenv('SQUARE_ACCESS_TOKEN')}",
    "Content-Type": "application/json"
}


# payment_handler.py
def handle_payment_event(data):
    try:
        # Log the raw input data
        logging.info(f"---------------- sqp 10: Received data: {data}")

        # Extract the payment data from the payload
        payment_data = data.get('data', {}).get('object', {}).get('payment', {})
        logging.debug(f"---------------- sqp 20: Extracted payment data: {payment_data}")

        payment_id = payment_data.get('id')
        card_details = payment_data.get('card_details', {})
        # DEBUG:root:---------------- sqp 40: Card Details: {'avs_status': 'AVS_ACCEPTED', 'card': {'bin': '453275', 'card_brand': 'VISA', 'card_type': 'CREDIT', 'exp_month': 9, 'exp_year': 2026, 'fingerprint': 'sq-1-HN56mMfCAgC4gMYZsumutzAY9p0jbDxAx5d9w9Aw746T0rlOahhYWLG3eSh4Qb9bog', 'last_4': '5858', 'prepaid_type': 'NOT_PREPAID'}, 'card_payment_timeline': {'authorized_at': '2024-09-19T021328.560Z', 'captured_at': '2024-09-19T021328.718Z'}, 'cvv_status': 'CVV_ACCEPTED', 'entry_method': 'KEYED', 'statement_description': 'SQ DEFAULT TEST ACCOUNT', 'status': 'CAPTURED'}

        card_fingerprint = card_details.get('card', {}).get('fingerprint')
        
        logging.debug(f"---------------- sqp 30: Payment ID: {payment_id}")
        logging.debug(f"---------------- sqp 40: Card Details: {card_details}")
        logging.debug(f"---------------- sqp 50: Card Fingerprint: {card_fingerprint}")

        # Basic validation
        if not payment_id or not card_fingerprint:
            logging.error("--------------- sqp 60: Missing payment ID or card fingerprint.")
            raise ValueError("Missing payment ID or card fingerprint.")

        # Simulate finding a customer by fingerprint
        logging.info(f"---------------- sqp 70: Looking for customer with card fingerprint: {card_fingerprint}")
        customer = find_customer_by_fingerprint(card_fingerprint)
        logging.debug(f"---------------- sqp 80: Customer found: {customer}")

        if customer:
            # Simulate sending the receipt to the customer
            logging.info(f"---------------- sqp 90: Customer found. Sending receipt for payment {payment_id} to customer {customer}")
            send_receipt_to_customer(customer, payment_id)
            return {"status": "receipt_sent", "payment_id": payment_id}, 200
        else:
            # New customer or no match found
            logging.info(f"---------------- sqp 100: No customer found with card fingerprint {card_fingerprint}. Ignoring for now.")
            return {"status": "new_customer_ignored", "payment_id": payment_id}, 200

    except Exception as e:
        # Handle any unexpected errors and log the error message
        logging.exception("--------------- sqp 110: An error occurred while handling the payment event.")
        return {"error": str(e)}, 400

def find_customer_by_fingerprint(card_fingerprint):
    # Placeholder function to simulate finding a customer by fingerprint
    # This should interact with your database in a real-world scenario
    logging.info(f"---------------- sqp 120: Searching for customer in the database using fingerprint: {card_fingerprint}")
    return None  # Simulating a new customer for now

def send_receipt_to_customer(customer, payment_id):
    # Placeholder function to simulate sending a receipt
    logging.info(f"---------------- sqp 130: Sending receipt for payment {payment_id} to customer {customer}")
    print(f"Sending receipt for payment {payment_id} to customer {customer}")
    return



def validate_contact_info(contact_info):
    """
    Validate the contact information provided by the customer.
    :param contact_info: The contact information (email or mobile number) from the customer.
    :return: Boolean indicating whether the contact information is valid.
    """
    if not contact_info or ('@' not in contact_info and not contact_info.isdigit()):
        logger.error(f"Invalid contact information provided: {contact_info}")
        return False
    return True

def extract_order_data(order_details):
    """
    Extract relevant order data from Square's API response.
    :param order_details: The order details retrieved from Square.
    :return: Extracted order data fields.
    """
    merchant_id = order_details.get('merchant_id', 'unknown')
    total_amount = order_details.get('total_money', {}).get('amount', 0)
    currency = order_details.get('total_money', {}).get('currency', 'USD')
    order_status = order_details.get('state', 'unknown')
    order_date = order_details.get('created_at', datetime.utcnow())
    return merchant_id, total_amount, currency, order_status, order_date

def extract_payment_data(payment_details):
    """
    Extract relevant payment data from Square's API response.
    :param payment_details: The payment details retrieved from Square.
    :return: Extracted payment data fields.
    """
    customer_id = payment_details.get('customer_id', 'unknown')
    amount = payment_details.get('amount_money', {}).get('amount', 0)
    payment_method = payment_details.get('card_details', {}).get('card', {}).get('type', 'unknown')
    payment_status = payment_details.get('status', 'unknown')
    transaction_id = payment_details.get('id')
    payment_date = payment_details.get('created_at', datetime.utcnow())
    return customer_id, amount, payment_method, payment_status, transaction_id, payment_date

def insert_square_data(order_data, payment_data, customer_id, contact_info, card_fingerprint):
    """
    Insert the extracted data into the appropriate database tables using SquareDAL.
    :param order_data: The extracted order data.
    :param payment_data: The extracted payment data.
    :param customer_id: The customer ID associated with the payment.
    :param contact_info: The contact information provided by the customer.
    :param card_fingerprint: The credit card fingerprint for identifying the customer.
    """
    order_id, merchant_id, total_amount, currency, order_status, order_date = order_data
    payment_id, amount, payment_method, payment_status, transaction_id, payment_date = payment_data

    # Insert order data
    square_dal.insert_order(order_id, merchant_id, total_amount, currency, order_status, order_date)

    # Insert payment data
    square_dal.insert_payment(payment_id, order_id, customer_id, amount, currency, payment_method, payment_status, transaction_id, payment_date)

    # Insert customer data
    square_dal.insert_customer(customer_id, contact_info, card_fingerprint)

    # Insert merchant data (if needed, otherwise ensure it's fetched from your internal database)
    square_dal.insert_merchant(merchant_id, "Merchant Name", "Merchant Location", "Merchant Contact")


def fetch_square_data(url, retries=SQUARE_API_RETRIES):
    """
    Fetch data from Square API with retry logic.

    :param url: The API endpoint URL to fetch data from.
    :param retries: The number of times to retry in case of failure.
    :return: JSON response from the API if successful, None otherwise.
    """
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=SQUARE_API_HEADERS, timeout=SQUARE_API_TIMEOUT)
            if response.status_code == 200:
                app.logger.info(f"---------------- sqp 40: Successfully retrieved data from Square: {url}")
                return response.json()
            else:
                app.logger.error(f"---------------- sqp 50: Failed to retrieve data from Square. Status Code: {response.status_code}, Attempt: {attempt + 1}")
        except requests.RequestException as e:
            app.logger.error(f"---------------- sqp 60: Error occurred while fetching data from Square: {str(e)}, Attempt: {attempt + 1}")
    
    app.logger.error(f"---------------- sqp 70: Exceeded retry limit for fetching data from Square: {url}")
    return None
