ALTER TABLE secrets
    DROP CONSTRAINT secrets_type_check,
    ALTER COLUMN name TYPE TEXT;

ALTER TABLE users
    ALTER COLUMN login TYPE TEXT,
    ALTER COLUMN password_hash TYPE TEXT;
