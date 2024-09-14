-- Alter the users table to add the last_login column
ALTER TABLE public.users
ADD COLUMN last_login TIMESTAMPTZ DEFAULT NULL;
