import logging
from pos_dal import POSDAL
from pos_dal_mappers import SquarePOSMapper

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def handle_payment_event(data, receipt_manager, db_session):
    """
    Handles payment.updated event for Square POS.
    Replaces SquareDAL with POSDAL and SquarePOSMapper for generic handling.
    """
    # Log the raw input data
    logging.info(f"---------------- sqp 10: Received data: {data}")

    # Extract the payment data from the payload
    payment_data = data.get('data', {}).get('object', {}).get('payment', {})
    logging.debug(f"---------------- sqp 20: Extracted payment data: {payment_data}")

    payment_id = payment_data.get('id')
    card_details = payment_data.get('card_details', {})
    card_fingerprint = card_details.get('card', {}).get('fingerprint')

    logging.debug(f"---------------- sqp 30: Payment ID: {payment_id}")
    logging.debug(f"---------------- sqp 40: Card Details: {card_details}")
    logging.debug(f"---------------- sqp 50: Card Fingerprint: {card_fingerprint}")

    # Basic validation
    if not payment_id or not card_fingerprint:
        logging.error("--------------- sqp 60: Missing payment ID or card fingerprint.")
        raise ValueError("Missing payment ID or card fingerprint.")

    # Initialize POSDAL and Mapper
    pos_dal = POSDAL(db_session)
    square_mapper = SquarePOSMapper()

    # Use the mapper to structure data for querying the DAL
    customer_identifier = square_mapper.map_customer({
        'card_fingerprint': card_fingerprint
    })['customer_identifier']

    logging.info(f"---------------- sqp 70: Looking for customer with card fingerprint: {card_fingerprint}")
    customer = pos_dal.get_customer_by_identifier(customer_identifier)
    logging.debug(f"---------------- sqp 80: Customer found: {customer}")

    if customer:
        # Fetch necessary data
        order_id = payment_data.get('order_id')
        order_data = pos_dal.get_order_by_order_id(order_id)
        payment_data = pos_dal.get_payment_by_payment_id(payment_id)
        merchant_data = pos_dal.get_merchant_by_merchant_id(order_data['merchant_id'])

        # Generate and send receipt
        receipt = receipt_manager.generate_receipt(order_data, payment_data, customer, merchant_data)
        logging.info(f"---------------- sqp 90: Customer found. Sending receipt for payment {payment_id} to customer {customer}")
        receipt_manager.send_receipt(receipt, customer['contact_info'])
        return {"status": "receipt_sent", "payment_id": payment_id}, 200
    else:
        # New customer or no match found
        logging.info(f"---------------- sqp 100: No customer found with card fingerprint {card_fingerprint}. Ignoring for now.")
        return {"status": "new_customer_ignored", "payment_id": payment_id}, 200
