import logging
import datetime
import requests  # Assuming we're using requests to make API calls
from receipt_dal import ReceiptDAL
from email_util import EmailUtil
from pos_dal import POSDAL

logger = logging.getLogger(__name__)

email_util = EmailUtil()  # Create an instance of EmailUtil

class ReceiptManager:
    def __init__(self, db_session, pos_config):
        self.db_session = db_session
        self.receipt_dal = ReceiptDAL(db_session)
        self.pos_dal = POSDAL(db_session)
        self.pos_config = pos_config
        self.headers = {
            'Authorization': f'Bearer {self.pos_config.api_key}',
            'Content-Type': 'application/json'
        }

    def validate_receipt_data(self, raw_order_data, raw_payment_data, raw_customer_data):
        """
        Validate the provided raw data by using pos_config to parse the data.
        The data is expected to be parsed and standardized by the pos_config.
        """
        # Use parse_pos_data to get standardized data
        order_data, payment_data, customer_data, _ = self.parse_pos_data(raw_order_data, raw_payment_data, raw_customer_data)

        # Validate order data
        required_order_fields = ['order_id', 'total_amount', 'currency']
        for field in required_order_fields:
            if field not in order_data or not order_data[field]:
                logger.error(f"Missing required field {field} in order data: {order_data}")
                return False

        # Validate payment data
        required_payment_fields = ['payment_id', 'amount', 'currency']
        for field in required_payment_fields:
            if field not in payment_data or not payment_data[field]:
                logger.error(f"Missing required field {field} in payment data: {payment_data}")
                return False

        # Validate customer data
        required_customer_fields = ['customer_id', 'email']
        for field in required_customer_fields:
            if field not in customer_data or not customer_data[field]:
                logger.error(f"Missing required field {field} in customer data: {customer_data}")
                return False

        return True

    def parse_pos_data(self, raw_order_data, raw_payment_data, raw_customer_data):
        """
        Parses the raw data using the configured POS-specific parsing logic.
        Returns the standardized order, payment, customer, and merchant data.
        """
        order_data = self.pos_config.parse_order_data(raw_order_data)
        payment_data = self.pos_config.parse_payment_data(raw_payment_data)
        customer_data = self.pos_config.parse_customer_data(raw_customer_data)

        # Extract and parse merchant data
        try:
            merchant_id = self.pos_config.get_merchant_id(raw_order_data, raw_payment_data)
            raw_merchant_data = self.pos_config.fetch_merchant_data(merchant_id)
            merchant_data = self.pos_config.parse_merchant_data(raw_merchant_data)
        except (ValueError, KeyError) as e:
            self.logger.error(f"Failed to fetch or parse merchant data: {str(e)}. Proceeding without merchant data.")
            merchant_data = {
                'name': 'Unknown Merchant',  # Fallback value
                'location': 'Unknown Location'  # Fallback value
            }

        return order_data, payment_data, customer_data, merchant_data

    def generate_receipt(self, order_data, payment_data, customer_data, merchant_data):
        """ 
        Generate the receipt content using the already parsed data from the POS provider.
        """
        # Generate the receipt content based on the parsed data
        receipt_content = {
            'order_id': order_data['order_id'],
            'payment_id': payment_data['payment_id'],
            'customer_name': customer_data.get('name', 'Unknown Customer'),
            'total_amount': order_data['total_amount'],
            'currency': order_data['currency'],
            'merchant_name': merchant_data.get('name', 'Unknown Merchant'),
            'date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        }
        logger.info(f"Receipt generated for order {order_data['order_id']}: {receipt_content}")
        return receipt_content

    def send_receipt(self, receipt, contact_info):
        """
        Send the generated receipt to the customer via email or SMS.
        """
        if '@' in contact_info:
            email_util.send_email(contact_info, "Your Receipt", receipt)
            logger.info(f"Receipt sent via email to {contact_info}")
        elif contact_info.isdigit():
            email_util.send_sms(contact_info, receipt)
            logger.info(f"Receipt sent via SMS to {contact_info}")
        else:
            logger.error(f"Invalid contact information provided: {contact_info}")
            raise ValueError("Invalid contact information format.")

    def check_and_process_receipt(self, order_id, payment_id, customer_id):
        """
        Check if a receipt exists for the provided IDs and process it if not.
        """
        # Step 1: Check if the receipt already exists using the provided IDs
        if self.receipt_dal.check_receipt_exists(order_id, payment_id, customer_id):
            logger.info(f"Receipt already exists for order_id {order_id}, payment_id {payment_id}, customer_id {customer_id}.")
            return

        # Step 2: Fetch necessary raw data using POSDAL
        raw_order_data = self.pos_dal.get_order_by_order_id(order_id)
        raw_payment_data = self.pos_dal.get_payment_by_payment_id(payment_id)
        raw_customer_data = self.pos_dal.get_customer_by_identifier(customer_id)

        # Step 3: Parse the data for order, payment, customer, and merchant using the POS-specific configuration
        order_data, payment_data, customer_data, merchant_data = self.parse_pos_data(
            raw_order_data, raw_payment_data, raw_customer_data
        )

        # Step 4: Validate the parsed data
        if not self.validate_receipt_data(order_data, payment_data, customer_data):
            logger.error(f"Invalid data for receipt processing for order_id {order_id}")
            return

        # Step 5: Generate and send the receipt
        receipt = self.generate_receipt(order_data, payment_data, customer_data, merchant_data)
        self.send_receipt(receipt, customer_data['contact_info'])

        # Step 6: Insert the receipt into the database
        self.receipt_dal.insert_receipt(
            order_id, payment_id, customer_id, customer_data['contact_info'],
            'GenericPOS', 'email', 'success'
        )

    def fetch_order_data(self, order_id):
        """
        Fetch order data from the POS system or the local PostgreSQL database using POSDAL.
        """
        logger.info(f"Fetching order data for order_id {order_id}")
        order_data = self.pos_dal.get_order_by_order_id(order_id)
        
        if order_data is None:
            logger.error(f"***************No order data found for order_id {order_id}")
        else:
            logger.info(f"***************Fetched order data: {order_data}")
        
        return order_data


    def fetch_payment_data(self, payment_id):
        """
        Fetch payment data from the POS system or the local PostgreSQL database using POSDAL.
        """
        # Fetch payment data from the POS system using POSDAL
        payment_data = self.pos_dal.get_payment_by_payment_id(payment_id)
        logger.info(f"Fetched payment data for payment_id {payment_id}: {payment_data}")
        return payment_data

    def fetch_customer_data(self, customer_id):
        """
        Fetch customer data from the POS provider. If the customer doesn't exist in the POS system,
        fallback to fetching the customer data from the PostgreSQL database.
        """
        # Attempt to fetch customer data from the POS provider using POSDAL
        customer_data = self.pos_dal.get_customer_by_identifier(customer_id)

        # If customer_data is None (customer not found in POS), fallback to local DB
        if not customer_data:
            logger.warning(f"Customer not found in POS, falling back to local database for customer_id {customer_id}.")
            customer_data = self._fetch_from_db(customer_id)

        logger.info(f"Fetched customer data for customer_id {customer_id}: {customer_data}")
        return customer_data

    def _fetch_from_pos(self, customer_id):
        """
        Fetch customer data from the POS provider using the customer_id.
        """
        url = self.pos_config.customer_url.format(customer_id=customer_id)
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        customer_data = response.json()
        logger.info(f"Fetched customer data for customer_id {customer_id} from POS: {customer_data}")
        return customer_data

    def _fetch_from_db(self, customer_id):
        """
        Fetch customer data from the local PostgreSQL database if not found in the POS system.
        """
        customer_data = self.pos_dal.get_customer_by_identifier(customer_id)
        if not customer_data:
            logger.error(f"No customer data found for customer_id {customer_id} in local database.")
            raise ValueError(f"No customer found for customer_id {customer_id} in POS or local database.")
        return customer_data

    def fetch_merchant_data(self, merchant_id):
        """
        Fetch merchant data from the POS provider using the merchant_id.
        """
        url = self.pos_config.merchant_url.format(merchant_id=merchant_id)
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        merchant_data = response.json()
        logger.info(f"Fetched merchant data for merchant_id {merchant_id}: {merchant_data}")
        return merchant_data

    # Placeholder Definitions for Future Functions
    def retry_failed_receipts(self):
        pass

    def handle_bulk_receipt_processing(self):
        pass

    def log_receipt_processing_activity(self, receipt_id, status):
        pass

    def archive_old_receipts(self, days_old):
        pass

    def notify_admin_of_critical_failures(self):
        pass

    def sync_receipts_with_reporting_system(self):
        pass

    def reprocess_stale_receipts(self):
        pass

    def flag_suspicious_receipt_activity(self):
        pass

    def export_receipts_for_audit(self):
        pass

    def fetch_additional_order_details(self, order_id):
        pass

    def manage_receipt_locks(self, receipt_id, action):
        pass

    def queue_receipt_for_manual_review(self, receipt_id):
        pass

    def adjust_retry_strategy(self, receipt_id, strategy):
        pass

    def get_last_receipt_status(self, receipt_id):
        pass

    def filter_receipts_by_date_range(self, start_date, end_date):
        pass

    def resolve_receipt_conflicts(self, receipt_id):
        pass

