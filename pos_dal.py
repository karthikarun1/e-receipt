import uuid
from datetime import datetime
from sqlalchemy import text
from transactional import transactional
import logging

logger = logging.getLogger(__name__)

class POSDAL:
    def __init__(self, db_session):
        self.db_session = db_session

    @transactional
    def get_customer_by_fingerprint_or_contact(self, card_fingerprint, contact_info):
        """
        Query the database to check if a customer exists using the card_fingerprint or contact info (email/SMS).
        """
        query = """
        SELECT customer_id FROM customers
        WHERE card_fingerprint = %s OR email = %s OR phone_number = %s
        LIMIT 1
        """
        cursor = self.db_session.cursor()
        cursor.execute(query, (card_fingerprint, contact_info, contact_info))
        result = cursor.fetchone()
        cursor.close()

        if result:
            logger.info(f"Found existing customer with id {result[0]}")
            return result[0]
        else:
            logger.info("No existing customer found.")
            return None


    # Insert a new order
    @transactional
    def insert_order(self, order_id, merchant_id, total_amount, currency, order_status, order_date, provider_name, extra_data=None):
        if self.get_order_by_order_id(order_id):
            logger.warning(f"Order with order_id {order_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO orders (id, order_id, merchant_id, total_amount, currency, order_status, order_date, provider_name, extra_data, created_at, updated_at)
            VALUES (%(id)s, %(order_id)s, %(merchant_id)s, %(total_amount)s, %(currency)s, %(order_status)s, %(order_date)s, %(provider_name)s, %(extra_data)s, %(now)s, %(now)s);
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
                'provider_name': provider_name,
                'extra_data': extra_data,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted order with order_id {order_id}.")

    # Insert a new payment
    @transactional
    def insert_payment(self, payment_id, order_id, customer_id, amount, currency, payment_method, payment_status, transaction_id, payment_date, provider_name, extra_data=None):
        if self.get_payment_by_payment_id(payment_id):
            logger.warning(f"Payment with payment_id {payment_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO payments (id, payment_id, order_id, customer_id, amount, currency, payment_method, payment_status, transaction_id, payment_date, provider_name, extra_data, created_at, updated_at)
            VALUES (%(id)s, %(payment_id)s, %(order_id)s, %(customer_id)s, %(amount)s, %(currency)s, %(payment_method)s, %(payment_status)s, %(transaction_id)s, %(payment_date)s, %(provider_name)s, %(extra_data)s, %(now)s, %(now)s);
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
                'provider_name': provider_name,
                'extra_data': extra_data,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted payment with payment_id {payment_id}.")

    # Insert a new customer, supporting flexible mappings (email, SMS, or card token)
    @transactional
    def insert_customer(self, pos_customer_identifier, contact_info, provider_name, card_fingerprint=None):
        """
        Insert a new customer into the database. Generates a UUID for the 'id' column.
        """
        query = """
        INSERT INTO customers (id, customer_id, pos_customer_identifier, email, phone_number, card_fingerprint, provider_name, created_at, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, now(), now())
        RETURNING customer_id
        """
        cursor = self.db_session.cursor()

        # Check if contact_info is an email or phone number and assign accordingly
        email = contact_info if '@' in contact_info else None
        phone_number = contact_info if '@' not in contact_info else None

        # Generate a UUID for the 'id' column
        new_id = str(uuid.uuid4())  # Ensure the UUID is generated for 'id'

        # Ensure all arguments are passed in the correct order matching the placeholders
        cursor.execute(query, (
            new_id,  # UUID for 'id' column
            str(uuid.uuid4()),  # Generate a new UUID for customer_id
            pos_customer_identifier,  # POS identifier (card_fingerprint or other)
            email,  # Email if present
            phone_number,  # Phone number if present
            card_fingerprint,  # Card fingerprint if available
            provider_name  # POS provider (Square, Clover, etc.)
        ))

        result = cursor.fetchone()
        cursor.close()

        if result:
            logger.info(f"Inserted new customer with id {result[0]}")
            return result[0]
        else:
            logger.error("Failed to insert new customer.")
            return None

    # Insert a new merchant
    @transactional
    def insert_merchant(self, merchant_id, name, location, contact_info, provider_name, extra_data=None):
        if self.get_merchant_by_merchant_id(merchant_id):
            logger.warning(f"Merchant with merchant_id {merchant_id} already exists. Skipping insertion.")
            return
        
        query = """
            INSERT INTO merchants (id, merchant_id, name, location, contact_info, provider_name, extra_data, created_at, updated_at)
            VALUES (%(id)s, %(merchant_id)s, %(name)s, %(location)s, %(contact_info)s, %(provider_name)s, %(extra_data)s, %(now)s, %(now)s);
        """
        with self.db_session.cursor() as cursor:
            cursor.execute(query, {
                'id': str(uuid.uuid4()),
                'merchant_id': merchant_id,
                'name': name,
                'location': location,
                'contact_info': contact_info,
                'provider_name': provider_name,
                'extra_data': extra_data,
                'now': datetime.utcnow()
            })
            self.db_session.commit()
            logger.info(f"Successfully inserted merchant with merchant_id {merchant_id}.")

    # Get order by order_id
    @transactional
    def get_order_by_order_id(self, order_id):
        query = "SELECT * FROM orders WHERE order_id = %(order_id)s;"
        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'order_id': order_id})
            result = cursor.fetchone()
            return result

    # Get payment by payment_id
    @transactional
    def get_payment_by_payment_id(self, payment_id):
        query = "SELECT * FROM payments WHERE payment_id = %(payment_id)s;"
        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'payment_id': payment_id})
            result = cursor.fetchone()
            return result

    # Get customer by flexible identifier (card token, phone number, or email)
    @transactional
    def get_customer_by_identifier(self, pos_customer_identifier):
        query = "SELECT * FROM customers WHERE pos_customer_identifier = %(pos_customer_identifier)s;"
        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'pos_customer_identifier': pos_customer_identifier})
            result = cursor.fetchone()
            return result

    # Get merchant by merchant_id
    @transactional
    def get_merchant_by_merchant_id(self, merchant_id):
        query = "SELECT * FROM merchants WHERE merchant_id = %(merchant_id)s;"
        with self.db_session.cursor() as cursor:
            cursor.execute(query, {'merchant_id': merchant_id})
            result = cursor.fetchone()
            return result
