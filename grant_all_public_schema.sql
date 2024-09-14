-- Option 1: Grant SUPERUSER privileges (if you are okay with this)
ALTER ROLE myuser WITH SUPERUSER;

-- Option 2: Grant specific privileges (if you prefer not to use SUPERUSER)

-- Allow myuser to create databases and roles
ALTER ROLE myuser WITH CREATEDB CREATEROLE;

-- Change the owner of the public schema to myuser
ALTER SCHEMA public OWNER TO myuser;

-- Grant all privileges on the mydb database to myuser
GRANT ALL PRIVILEGES ON DATABASE mydb TO myuser;

-- Grant usage, create, and all privileges on the public schema
GRANT USAGE, CREATE ON SCHEMA public TO myuser;
GRANT ALL PRIVILEGES ON SCHEMA public TO myuser;

-- Ensure myuser can create objects within the public schema
GRANT CREATE ON SCHEMA public TO myuser;
