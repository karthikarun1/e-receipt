-- V8__create_receipts_table.sql

-- Create the generic receipts table
CREATE TABLE IF NOT EXISTS receipts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id VARCHAR(255) NOT NULL,
    payment_id VARCHAR(255) NOT NULL,
    customer_id VARCHAR(255) NOT NULL,
    contact_info VARCHAR(255) NOT NULL, -- Stores email or mobile number
    provider VARCHAR(50) NOT NULL,      -- Identifies the POS provider (e.g., Square, Clover)
    sent_status VARCHAR(50) NOT NULL,   -- Status of the receipt sent (e.g., 'success', 'failed')
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Timestamp when the receipt was sent
    retries INTEGER DEFAULT 0,          -- Count of retry attempts
    error_message TEXT,                 -- Logs any errors during sending
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (order_id, payment_id, customer_id) -- Unique constraint to prevent duplicate entries
);

-- Create an index on order_id, payment_id, and customer_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_receipts_unique ON receipts (order_id, payment_id, customer_id);

