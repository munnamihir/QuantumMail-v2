-- server/migrations/002_recovery_quorum.sql

CREATE TABLE IF NOT EXISTS qm_recovery_vault (
  user_id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL,
  token_verifier_hash TEXT NOT NULL,
  enc_wk_b64 TEXT NOT NULL,
  iv_b64 TEXT NOT NULL,
  wk_version INT NOT NULL DEFAULT 1,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS qm_devices (
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  pub_jwk JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (user_id, device_id)
);

CREATE TABLE IF NOT EXISTS qm_recovery_requests (
  request_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_id TEXT NOT NULL,
  requester_device_id TEXT NOT NULL,
  nonce_b64 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING | APPROVED | DENIED | EXPIRED
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  approved_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS qm_recovery_approvals (
  request_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  sig_b64 TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (request_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_qm_recovery_requests_user ON qm_recovery_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_qm_devices_user ON qm_devices(user_id);
