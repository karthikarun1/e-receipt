import datetime
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from unittest.mock import MagicMock, patch
from receipt_management import ReceiptManager

# Sample constants for testing
API_BASE_URL = "https://api.testpos.com"
API_KEY = "test_api_key"

# Fixture for setting up the ReceiptManager with mocked dependencies
@pytest.fixture
def setup_receipt_manager():
    # Mock the database session
    mock_db_session = MagicMock()

    # Initialize ReceiptManager with mocked db session and API details
    receipt_manager = ReceiptManager(
        db_session=mock_db_session,
        api_base_url=API_BASE_URL,
        api_key=API_KEY
    )
    return receipt_manager, mock_db_session

def test_receipt_manager_initialization(setup_receipt_manager):
    """
    Test the initialization of the ReceiptManager class.
    """
    receipt_manager, mock_db_session = setup_receipt_manager

    # Verify that ReceiptManager is initialized correctly with mocked session
    assert receipt_manager.db_session == mock_db_session
    assert receipt_manager.api_base_url == API_BASE_URL
    assert receipt_manager.api_key == API_KEY
    assert receipt_manager.receipt_dal is not None


def test_validate_receipt_data_valid(setup_receipt_manager):
    """
    Test validate_receipt_data with valid data.
    """
    receipt_manager, _ = setup_receipt_manager
    valid_order_data = {
        'order_id': 'order123',
        'payment_id': 'payment123',
        'customer_id': 'customer123',
        'total_amount': 100,
        'currency': 'USD'
    }
    result = receipt_manager.validate_receipt_data(valid_order_data, {}, {})
    assert result is True

def test_validate_receipt_data_missing_field(setup_receipt_manager):
    """
    Test validate_receipt_data with missing fields.
    """
    receipt_manager, _ = setup_receipt_manager
    invalid_order_data = {
        'order_id': 'order123',
        # 'payment_id' is missing
        'customer_id': 'customer123',
        'total_amount': 100,
        'currency': 'USD'
    }
    result = receipt_manager.validate_receipt_data(invalid_order_data, {}, {})
    assert result is False

@patch('receipt_management.EmailUtil.send_email')
@patch('receipt_management.EmailUtil.send_sms')
def test_send_receipt_email(mock_send_sms, mock_send_email, setup_receipt_manager):
    """
    Test send_receipt sends an email when contact_info is an email address.
    """
    receipt_manager, _ = setup_receipt_manager
    receipt = {"order_id": "order123", "total_amount": 100}
    contact_info = "test@example.com"

    receipt_manager.send_receipt(receipt, contact_info)

    mock_send_email.assert_called_once_with(contact_info, "Your Receipt", receipt)
    mock_send_sms.assert_not_called()

@patch('receipt_management.EmailUtil.send_email')
@patch('receipt_management.EmailUtil.send_sms')
def test_send_receipt_sms(mock_send_sms, mock_send_email, setup_receipt_manager):
    """
    Test send_receipt sends an SMS when contact_info is a phone number.
    """
    receipt_manager, _ = setup_receipt_manager
    receipt = {"order_id": "order123", "total_amount": 100}
    contact_info = "1234567890"

    receipt_manager.send_receipt(receipt, contact_info)

    mock_send_sms.assert_called_once_with(contact_info, receipt)
    mock_send_email.assert_not_called()

@patch('receipt_management.ReceiptManager.fetch_order_data')
@patch('receipt_management.ReceiptManager.fetch_payment_data')
@patch('receipt_management.ReceiptManager.fetch_customer_data')
@patch('receipt_management.ReceiptManager.fetch_merchant_data')
@patch('receipt_management.ReceiptDAL.check_receipt_exists', return_value=False)
@patch('receipt_management.ReceiptDAL.insert_receipt')
@patch('receipt_management.ReceiptDAL.mark_receipt_as_failed')
def test_check_and_process_receipt(
        mock_mark_receipt_as_failed, 
        mock_insert_receipt, 
        mock_check_receipt_exists, 
        mock_fetch_merchant_data, 
        mock_fetch_customer_data, 
        mock_fetch_payment_data, 
        mock_fetch_order_data, 
        setup_receipt_manager):
    """
    Test check_and_process_receipt for complete workflow including receipt creation and sending.
    """
    receipt_manager, _ = setup_receipt_manager
    mock_fetch_order_data.return_value = {
        'order_id': 'order123',
        'payment_id': 'payment123',
        'customer_id': 'customer123',
        'total_amount': 100,
        'currency': 'USD',
        'merchant_id': 'merchant123'
    }
    mock_fetch_payment_data.return_value = {'payment_id': 'payment123'}
    mock_fetch_customer_data.return_value = {'customer_id': 'customer123', 'contact_info': 'test@example.com'}
    mock_fetch_merchant_data.return_value = {'merchant_id': 'merchant123'}

    receipt_manager.check_and_process_receipt('order123', 'payment123', 'customer123')

    mock_insert_receipt.assert_called_once()
    mock_mark_receipt_as_failed.assert_not_called()

@patch('receipt_management.ReceiptManager.fetch_order_data')
@patch('receipt_management.ReceiptManager.fetch_payment_data')
@patch('receipt_management.ReceiptManager.fetch_customer_data')
@patch('receipt_management.ReceiptManager.fetch_merchant_data')
@patch('receipt_management.ReceiptDAL.check_receipt_exists', return_value=True)
@patch('receipt_management.ReceiptDAL.insert_receipt')
@patch('receipt_management.ReceiptDAL.mark_receipt_as_failed')
def test_check_and_process_receipt_already_exists(
        mock_mark_receipt_as_failed, 
        mock_insert_receipt, 
        mock_check_receipt_exists, 
        mock_fetch_merchant_data, 
        mock_fetch_customer_data, 
        mock_fetch_payment_data, 
        mock_fetch_order_data, 
        setup_receipt_manager):
    """
    Test check_and_process_receipt when a receipt already exists.
    """
    receipt_manager, _ = setup_receipt_manager

    receipt_manager.check_and_process_receipt('order123', 'payment123', 'customer123')

    mock_check_receipt_exists.assert_called_once()
    mock_insert_receipt.assert_not_called()
    mock_mark_receipt_as_failed.assert_not_called()


def test_datetime_handling():
    # Setup
    manager = ReceiptManager(None, "https://api.example.com", "test_api_key")

    # Sample input data
    order_data = {
        'order_id': 'order123',
        'total_amount': 100,
        'currency': 'USD',
        'merchant_id': 'merchant456'
    }
    payment_data = {'payment_id': 'payment123'}
    customer_data = {'name': 'John Doe', 'contact_info': 'john.doe@example.com'}
    merchant_data = {'name': 'Example Merchant'}

    # Generate receipt to test date handling
    receipt = manager.generate_receipt(order_data, payment_data, customer_data, merchant_data)
    
    # Test the 'date' field is properly formatted
    assert 'date' in receipt
    # Parse the date string into a datetime object
    date_obj = datetime.datetime.strptime(receipt['date'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
    # Check if the datetime object is within a reasonable time frame of now (e.g., within 60 seconds)
    utc_now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((utc_now - date_obj).total_seconds()) < 60  # Ensure within 60 seconds window

