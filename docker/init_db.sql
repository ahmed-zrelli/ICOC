-- ICOC-Lite PostgreSQL Init Script
-- Runs automatically on first container start via docker-entrypoint-initdb.d

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Set timezone
SET timezone = 'UTC';

-- Grant all to icoc user (already created via env vars)
GRANT ALL PRIVILEGES ON DATABASE icoc TO icoc;
GRANT ALL ON SCHEMA public TO icoc;

-- Note: tables are created by database.py create_schema() on API startup
-- This file just ensures the DB and user exist with correct permissions.

SELECT 'ICOC-Lite database initialized' as status;
