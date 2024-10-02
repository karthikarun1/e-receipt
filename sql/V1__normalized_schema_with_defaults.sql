-- V1__normalized_schema_with_defaults.sql

-- UUID generation extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Providers Table (stores information about POS providers like Square, Clover, etc.)
CREATE TABLE providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider_name VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

-- Customers Table (one email and one phone per customer, updateable without breaking history)
CREATE TABLE customers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    mobile_number VARCHAR(20) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Index for faster lookups on customers by email or phone
CREATE INDEX idx_customers_email ON customers(email);
CREATE INDEX idx_customers_mobile_number ON customers(mobile_number);

-- Customer Cards Table (multiple cards per customer)
CREATE TABLE customer_cards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    card_fingerprint VARCHAR(255) UNIQUE NOT NULL,
    last_4_digits VARCHAR(4), -- Last 4 digits of the credit card
    created_at TIMESTAMP DEFAULT now()
);

-- Orders Table (multiple orders per customer)
CREATE TABLE orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    provider_id UUID REFERENCES providers(id) ON DELETE SET NULL, -- Link to the POS provider
    total_amount DECIMAL(10, 2) NOT NULL DEFAULT 0.00, -- Default total amount
    order_date TIMESTAMP DEFAULT now(),
    order_status VARCHAR(50) NOT NULL DEFAULT 'pending', -- Default order status
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Index for faster lookups on orders by customer
CREATE INDEX idx_orders_customer_id ON orders(customer_id);

-- Order Items Table (each order can have multiple items)
CREATE TABLE order_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
    item_name VARCHAR(255) NOT NULL,
    item_quantity DECIMAL(10, 2) NOT NULL DEFAULT 1, -- Default quantity is 1
    unit_price DECIMAL(10, 2) NOT NULL, -- No default, price varies
    pricing_type VARCHAR(20) NOT NULL DEFAULT 'per_each', -- Default pricing type is per_each
    weight_unit VARCHAR(20) CHECK (weight_unit IN ('pound', 'kilogram', 'gram', 'ounce')), -- Unit for weight-based pricing
    item_price DECIMAL(10, 2) GENERATED ALWAYS AS (item_quantity * unit_price) STORED, -- Automatically calculated
    created_at TIMESTAMP DEFAULT now()
);

-- Index for faster lookups on items by order
CREATE INDEX idx_order_items_order_id ON order_items(order_id);

-- Payments Table (each order can have multiple payments)
CREATE TABLE payments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL DEFAULT 0.00, -- Default amount is 0
    payment_method VARCHAR(50) NOT NULL DEFAULT 'card', -- Default payment method is card
    payment_status VARCHAR(50) NOT NULL DEFAULT 'pending', -- Default status is pending
    transaction_id VARCHAR(255),
    payment_date TIMESTAMP DEFAULT now(),
    provider_id UUID REFERENCES providers(id) ON DELETE SET NULL, -- Link to the POS provider
    card_fingerprint VARCHAR(255),
    created_at TIMESTAMP DEFAULT now()
);

-- Receipts Table (each payment generates a receipt)
CREATE TABLE receipts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id UUID REFERENCES orders(id) ON DELETE CASCADE,
    customer_id UUID REFERENCES customers(id) ON DELETE CASCADE,
    receipt_data JSONB, -- Store detailed order data (items, payment, etc.)
    emailed BOOLEAN DEFAULT FALSE, -- Default is not emailed
    sms_sent BOOLEAN DEFAULT FALSE, -- Default is no SMS
    email_sent_at TIMESTAMP,
    sms_sent_at TIMESTAMP,
    subtotal DECIMAL(10, 2) DEFAULT 0.00, -- Default subtotal is 0
    tax DECIMAL(10, 2) DEFAULT 0.00, -- Default tax is 0
    total DECIMAL(10, 2) DEFAULT 0.00, -- Default total is 0
    merchant_name VARCHAR(255),
    merchant_address TEXT,
    merchant_contact_info VARCHAR(255),
    last_4_digits VARCHAR(4), -- Last 4 digits of the credit card used
    barcode VARCHAR(255), -- Barcode to scan the receipt
    created_at TIMESTAMP DEFAULT now()
);

-- Index for faster lookups on receipts by customer and order
CREATE INDEX idx_receipts_customer_id ON receipts(customer_id);
CREATE INDEX idx_receipts_order_id ON receipts(order_id);

-- Triggers
-- Example Trigger: Auto-update updated_at in orders whenever a row is updated
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_order_timestamp
BEFORE UPDATE ON orders
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Example Trigger: Auto-update updated_at in customers whenever a row is updated
CREATE TRIGGER update_customer_timestamp
BEFORE UPDATE ON customers
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- Example Trigger: Auto-update updated_at in order_items whenever a row is updated
CREATE TRIGGER update_order_item_timestamp
BEFORE UPDATE ON order_items
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();
