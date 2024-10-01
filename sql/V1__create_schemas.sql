-- Create Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone_number VARCHAR(20),
    password_hash TEXT NOT NULL,
    last_login TIMESTAMP,
    email_verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on email for faster lookup
CREATE INDEX idx_users_email ON users(email);

-- Create Verification Table for Email Verification Codes
CREATE TABLE verification_codes (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT now()
);

-- Unified Orders Table (covers Square, Clover, and other POS providers)
CREATE TABLE orders (
    id UUID PRIMARY KEY,
    order_id VARCHAR(255) NOT NULL UNIQUE,  -- Add UNIQUE constraint to allow foreign key references
    merchant_id VARCHAR(255),
    total_amount DECIMAL(10, 2),
    currency VARCHAR(10),
    order_status VARCHAR(50),
    order_date TIMESTAMP,
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on order_id for faster lookups
CREATE INDEX idx_orders_order_id ON orders(order_id);

-- Unified Payments Table (covers Square, Clover, and other POS providers)
CREATE TABLE payments (
    id UUID PRIMARY KEY,
    payment_id VARCHAR(255) NOT NULL UNIQUE,  -- Add UNIQUE constraint for payment_id
    order_id VARCHAR(255) REFERENCES orders(order_id) ON DELETE CASCADE,  -- Foreign key references orders(order_id)
    customer_id VARCHAR(255),
    amount DECIMAL(10, 2),
    currency VARCHAR(10),
    payment_method VARCHAR(50),
    payment_status VARCHAR(50),
    transaction_id VARCHAR(255),
    payment_date TIMESTAMP,
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on payment_id for faster lookups
CREATE INDEX idx_payments_payment_id ON payments(payment_id);

-- Unified Customers Table (covers Square, Clover, and other POS providers)
CREATE TABLE customers (
    id UUID PRIMARY KEY,
    customer_id VARCHAR(255) NOT NULL,  -- Unique customer ID in your system
    pos_customer_identifier VARCHAR(255),  -- Identifier from POS (card fingerprint, phone, or email)
    email VARCHAR(255),  -- To store the customer email
    phone_number VARCHAR(20),  -- To store the customer phone number
    card_fingerprint VARCHAR(255),  -- Unique card fingerprint or token
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on pos_customer_identifier for faster lookups
CREATE INDEX idx_customers_identifier ON customers(pos_customer_identifier);

-- Unified Merchants Table (covers Square, Clover, and other POS providers)
CREATE TABLE merchants (
    id UUID PRIMARY KEY,
    merchant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    location VARCHAR(255),
    contact_info VARCHAR(255),
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on merchant_id for faster lookups
CREATE INDEX idx_merchants_merchant_id ON merchants(merchant_id);

-- Unified Tokens Table (covers tokens for any POS provider, e.g., Clover, Square, etc.)
CREATE TABLE tokens (
    id UUID PRIMARY KEY,
    merchant_id VARCHAR(255) NOT NULL,  -- Merchant associated with this token
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on merchant_id for faster lookups in tokens
CREATE INDEX idx_tokens_merchant_id ON tokens(merchant_id);

-- Create Receipts Table for tracking receipts across providers
CREATE TABLE receipts (
    id UUID PRIMARY KEY,
    payment_id VARCHAR(255) REFERENCES payments(payment_id) ON DELETE CASCADE,  -- Foreign key references UNIQUE payment_id
    receipt_url TEXT,
    receipt_number VARCHAR(255),
    provider_name VARCHAR(50),  -- Square, Clover, etc.
    extra_data JSONB,  -- Store any provider-specific fields here
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Create index on payment_id for faster lookups in receipts
CREATE INDEX idx_receipts_payment_id ON receipts(payment_id);

-- Triggers to automatically update the updated_at column on every update
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply the trigger to update `updated_at` on changes in orders
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON orders
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();

-- Apply the trigger to update `updated_at` on changes in payments
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON payments
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();

-- Apply the trigger to update `updated_at` on changes in customers
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON customers
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();

-- Apply the trigger to update `updated_at` on changes in merchants
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON merchants
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();

-- Apply the trigger to update `updated_at` on changes in tokens
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON tokens
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();

-- Apply the trigger to update `updated_at` on changes in receipts
CREATE TRIGGER set_timestamp
BEFORE UPDATE ON receipts
FOR EACH ROW
EXECUTE PROCEDURE update_timestamp();
