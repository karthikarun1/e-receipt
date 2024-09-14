-- V4__Add_phone_number_to_users_table.sql

-- Add phone number and phone verified fields
ALTER TABLE users
ADD COLUMN phone_number VARCHAR(15);

ALTER TABLE users
ADD COLUMN phone_verified BOOLEAN DEFAULT FALSE;

-- Ensure phone number is unique
CREATE UNIQUE INDEX idx_phone_number ON users(phone_number);
