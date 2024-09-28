import logging
import os
import postgresql_db_utils

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

from datetime import datetime

# from square_dal import SquareDAL
# square_dal = SquareDAL(db_session=postgresql_db_utils.get_connection())


def handle_payment_event(data, receipt_manager, square_dal):
    # DEBUG:root:---------------- sqp 40: Card Details: {'avs_status': 'AVS_ACCEPTED', 'card': {'bin': '453275', 'card_brand': 'VISA', 'card_type': 'CREDIT', 'exp_month': 9, 'exp_year': 2026, 'fingerprint': 'sq-1-HN56mMfCAgC4gMYZsumutzAY9p0jbDxAx5d9w9Aw746T0rlOahhYWLG3eSh4Qb9bog', 'last_4': '5858', 'prepaid_type': 'NOT_PREPAID'}, 'card_payment_timeline': {'authorized_at': '2024-09-19T021328.560Z', 'captured_at': '2024-09-19T021328.718Z'}, 'cvv_status': 'CVV_ACCEPTED', 'entry_method': 'KEYED', 'statement_description': 'SQ DEFAULT TEST ACCOUNT', 'status': 'CAPTURED'}
    try:
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

        # Find customer by fingerprint using SquareDAL
        logging.info(f"---------------- sqp 70: Looking for customer with card fingerprint: {card_fingerprint}")
        customer = square_dal.get_customer_by_fingerprint(card_fingerprint)
        logging.debug(f"---------------- sqp 80: Customer found: {customer}")

        if customer:
            # Fetch necessary data
            order_data = square_dal.get_order_by_order_id(payment_data.get('order_id'))
            payment_data = square_dal.get_payment_by_payment_id(payment_id)
            merchant_data = square_dal.get_merchant_by_merchant_id(order_data['merchant_id'])

            receipt = receipt_manager.generate_receipt(order_data, payment_data, customer, merchant_data)
            logging.info(f"---------------- sqp 90: Customer found. Sending receipt for payment {payment_id} to customer {customer}")
            receipt_manager.send_receipt(receipt, customer['contact_info'])
            return {"status": "receipt_sent", "payment_id": payment_id}, 200
        else:
            # New customer or no match found
            logging.info(f"---------------- sqp 100: No customer found with card fingerprint {card_fingerprint}. Ignoring for now.")
            return {"status": "new_customer_ignored", "payment_id": payment_id}, 200

    except Exception as e:
        # Handle any unexpected errors and log the error message
        logging.exception("--------------- sqp 110: An error occurred while handling the payment event.")
        return {"error": str(e)}, 400
