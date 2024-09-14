-- V5__Rename_verified_to_email_verified.sql

-- Rename the verified column to email_verified
ALTER TABLE users
RENAME COLUMN verified TO email_verified;
