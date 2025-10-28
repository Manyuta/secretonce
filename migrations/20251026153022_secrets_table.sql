CREATE TABLE IF NOT EXISTS secrets (
  id UUID PRIMARY KEY,
  ciphertext TEXT NOT NULL,
  passphrase TEXT,
  recipient TEXT,
  passphrase_required BOOLEAN NOT NULL DEFAULT false,
  burn_after_reading BOOLEAN NOT NULL DEFAULT false,
  access_count INTEGER NOT NULL DEFAULT 0,
  max_views INTEGER NOT NULL DEFAULT 1,
  ttl_minutes INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

