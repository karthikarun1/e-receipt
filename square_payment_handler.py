import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

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
