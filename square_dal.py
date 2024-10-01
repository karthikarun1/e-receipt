import uuid
from datetime import datetime
from sqlalchemy import text
from transactional import transactional
import logging

logger = logging.getLogger(__name__)

class SquareDAL:
    def __init__(self, db_session):
        self.db_session = db_session

    @transactional
    def insert_order(self, order_id, merchant_id, total_amount, currency, order_status, order_date):
        """
        Insert a new order into the square_orders table with uniqueness check.
        """
        if self.get_order_by_order_id(order_id):
            logger.warning(f"Order with order_id {order_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO square_orders (id, order_id, merchant_id, total_amount, currency, order_status, order_date, created_at, updated_at)
            VALUES (%(id)s, %(order_id)s, %(merchant_id)s, %(total_amount)s, %(currency)s, %(order_status)s, %(order_date)s, %(now)s, %(now)s);
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),
                'order_id': order_id,
                'merchant_id': merchant_id,
                'total_amount': total_amount,
                'currency': currency,
                'order_status': order_status,
                'order_date': order_date,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted order with order_id {order_id}.")

    @transactional
    def insert_payment(self, payment_id, order_id, customer_id, amount, currency, payment_method, payment_status, transaction_id, payment_date):
        """
        Insert a new payment into the square_payments table with uniqueness check.
        """
        if self.get_payment_by_payment_id(payment_id):
            logger.warning(f"Payment with payment_id {payment_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO square_payments (id, payment_id, order_id, customer_id, amount, currency, payment_method, payment_status, transaction_id, payment_date, created_at, updated_at)
            VALUES (%(id)s, %(payment_id)s, %(order_id)s, %(customer_id)s, %(amount)s, %(currency)s, %(payment_method)s, %(payment_status)s, %(transaction_id)s, %(payment_date)s, %(now)s, %(now)s);
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),
                'payment_id': payment_id,
                'order_id': order_id,
                'customer_id': customer_id,
                'amount': amount,
                'currency': currency,
                'payment_method': payment_method,
                'payment_status': payment_status,
                'transaction_id': transaction_id,
                'payment_date': payment_date,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted payment with payment_id {payment_id}.")

    @transactional
    def insert_customer(self, contact_info, card_fingerprint):
        """
        Insert a new customer into the square_customers table.
        Generates a new customer_id and returns it.
        """
        # Generate a new customer_id using UUID
        customer_id = str(uuid.uuid4())

        query = """
            INSERT INTO square_customers (id, customer_id, contact_info, card_fingerprint, created_at, updated_at)
            VALUES (%(id)s, %(customer_id)s, %(contact_info)s, %(card_fingerprint)s, %(now)s, %(now)s);
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),  # Unique ID for this entry
                'customer_id': customer_id,  # Generated customer ID
                'contact_info': contact_info,
                'card_fingerprint': card_fingerprint,
                'now': datetime.utcnow()
            })
            self.db_session.commit()

        logger.info(f"Successfully inserted customer with customer_id {customer_id}.")
        return customer_id  # Return the newly generated customer_id


    @transactional
    def insert_merchant(self, merchant_id, name, location, contact_info):
        """
        Insert a new merchant into the square_merchants table with uniqueness check.
        """
        if self.get_merchant_by_merchant_id(merchant_id):
            logger.warning(f"Merchant with merchant_id {merchant_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO square_merchants (id, merchant_id, name, location, contact_info, created_at, updated_at)
            VALUES (%(id)s, %(merchant_id)s, %(name)s, %(location)s, %(contact_info)s, %(now)s, %(now)s);
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),
                'merchant_id': merchant_id,
                'name': name,
                'location': location,
                'contact_info': contact_info,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted merchant with merchant_id {merchant_id}.")

    @transactional
    def get_order_by_order_id(self, order_id):
        """
        Retrieve order details by order_id.
        """
        query = """
            SELECT * FROM square_orders WHERE order_id = %(order_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'order_id': order_id})
            result = cursor.fetchone()
            logger.debug(f"Query result for order_id {order_id}: {result}")
        return result

    @transactional
    def get_payment_by_payment_id(self, payment_id):
        """
        Retrieve payment details by payment_id.
        """
        query = """
            SELECT * FROM square_payments WHERE payment_id = %(payment_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'payment_id': payment_id})
            result = cursor.fetchone()
            logger.debug(f"Query result for payment_id {payment_id}: {result}")
        return result

    @transactional
    def get_customer_by_customer_id(self, customer_id):
        """
        Retrieve customer details by customer_id.
        """
        query = """
            SELECT * FROM square_customers WHERE customer_id = %(customer_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'customer_id': customer_id})
            result = cursor.fetchone()
            logger.debug(f"Query result for customer_id {customer_id}: {result}")
        return result

    @transactional
    def get_merchant_by_merchant_id(self, merchant_id):
        """
        Retrieve merchant details by merchant_id.
        """
        query = """
            SELECT * FROM square_merchants WHERE merchant_id = %(merchant_id)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'merchant_id': merchant_id})
            result = cursor.fetchone()
            logger.debug(f"Query result for merchant_id {merchant_id}: {result}")
        return result

    @transactional
    def get_customer_by_fingerprint(self, card_fingerprint):
        """
        Retrieve customer details by card fingerprint.

        Args:
            card_fingerprint (str): The fingerprint of the card used by the customer.

        Returns:
            dict or None: The customer details if found, otherwise None.
        """
        query = """
            SELECT * FROM square_customers WHERE card_fingerprint = %(card_fingerprint)s;
        """

        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'card_fingerprint': card_fingerprint})
            result = cursor.fetchone()
            logger.debug(f"Query result for card_fingerprint {card_fingerprint}: {result}")
        return result
