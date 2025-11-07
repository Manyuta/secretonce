-- Add salt column with a temporary default
ALTER TABLE secrets ADD COLUMN salt TEXT DEFAULT 'legacy'::TEXT;

-- Backfill or update existing rows as needed
UPDATE secrets SET salt = 'legacy' WHERE salt IS NULL;

-- Enforce NOT NULL constraint
ALTER TABLE secrets ALTER COLUMN salt SET NOT NULL;

