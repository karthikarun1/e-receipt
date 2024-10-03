from datetime import datetime
from extensions import db  # Import db from extensions
from uuid import uuid4

# Providers Table
class Provider(db.Model):
    __tablename__ = 'providers'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    provider_name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Customers Table
class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    mobile_number = db.Column(db.String(20), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship with orders and customer_cards
    orders = db.relationship('Order', backref='customer', lazy=True)
    cards = db.relationship('CustomerCard', backref='customer', lazy=True)

# Customer Cards Table
class CustomerCard(db.Model):
    __tablename__ = 'customer_cards'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    customer_id = db.Column(db.String(36), db.ForeignKey('customers.id'), nullable=False)
    card_fingerprint = db.Column(db.String(255), unique=True, nullable=False)
    last_4_digits = db.Column(db.String(4))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Orders Table
class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    customer_id = db.Column(db.String(36), db.ForeignKey('customers.id'), nullable=False)
    provider_id = db.Column(db.String(36), db.ForeignKey('providers.id'))
    merchant_id = db.Column(db.String(36), db.ForeignKey('merchants.id'))  # Link to Merchant
    total_amount = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    order_date = db.Column(db.DateTime, default=datetime.utcnow)
    order_status = db.Column(db.String(50), nullable=False, default='pending')
    currency = db.Column(db.String(10), default='USD')  # Add the new currency field here
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship with payments and order_items
    payments = db.relationship('Payment', backref='order', lazy=True)
    items = db.relationship('OrderItem', backref='order', lazy=True)

# Order Items Table
class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = db.Column(db.String(36), db.ForeignKey('orders.id'), nullable=False)
    item_name = db.Column(db.String(255), nullable=False)
    item_quantity = db.Column(db.Numeric(10, 2), nullable=False, default=1)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    pricing_type = db.Column(db.String(20), nullable=False, default='per_each')
    weight_unit = db.Column(db.String(20))
    item_price = db.Column(db.Numeric(10, 2), nullable=False)  # Calculated externally
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Payments Table
class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = db.Column(db.String(36), db.ForeignKey('orders.id'), nullable=False)
    customer_id = db.Column(db.String(36), db.ForeignKey('customers.id'), nullable=False)
    merchant_id = db.Column(db.String(36), db.ForeignKey('merchants.id'))  # Link to Merchant
    amount = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    payment_method = db.Column(db.String(50), nullable=False, default='card')
    payment_status = db.Column(db.String(50), nullable=False, default='pending')
    transaction_id = db.Column(db.String(255))
    payment_date = db.Column(db.DateTime, default=datetime.utcnow)
    provider_id = db.Column(db.String(36), db.ForeignKey('providers.id'))
    card_fingerprint = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Receipts Table
class Receipt(db.Model):
    __tablename__ = 'receipts'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    order_id = db.Column(db.String(36), db.ForeignKey('orders.id'), nullable=False)
    customer_id = db.Column(db.String(36), db.ForeignKey('customers.id'), nullable=False)
    merchant_id = db.Column(db.String(36), db.ForeignKey('merchants.id'), nullable=False)  # Link to Merchant
    receipt_data = db.Column(db.JSON)
    emailed = db.Column(db.Boolean, default=False)
    sms_sent = db.Column(db.Boolean, default=False)
    email_sent_at = db.Column(db.DateTime)
    sms_sent_at = db.Column(db.DateTime)
    subtotal = db.Column(db.Numeric(10, 2), default=0.00)
    tax = db.Column(db.Numeric(10, 2), default=0.00)
    total = db.Column(db.Numeric(10, 2), default=0.00)
    last_4_digits = db.Column(db.String(4))
    barcode = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Merchant Table
class Merchant(db.Model):
    __tablename__ = 'merchants'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    name = db.Column(db.String(255), nullable=False)
    address = db.Column(db.Text)
    contact_info = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
