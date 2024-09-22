-- V6__create_clover_tokens_table.sql

-- V6__create_clover_tokens_table.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the clover_tokens table
CREATE TABLE clover_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    merchant_id VARCHAR(255) NOT NULL UNIQUE,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create a function to automatically update the 'updated_at' timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = NOW();
   RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

-- Create a trigger to execute the function before updating the table
CREATE TRIGGER update_clover_tokens_updated_at
BEFORE UPDATE ON clover_tokens
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_column();
