CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  member_no INTEGER NOT NULL UNIQUE,
  name TEXT NOT NULL,
  position TEXT DEFAULT '',
  phone TEXT DEFAULT '',
  shares INTEGER NOT NULL CHECK (shares IN (5,6,10)),
  join_date TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  month TEXT NOT NULL,
  amount INTEGER NOT NULL,
  payment_date TEXT NOT NULL,
  notes TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS fund_transactions (
  id TEXT PRIMARY KEY,
  tx_date TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('income','investment','expense')),
  amount INTEGER NOT NULL,
  category TEXT DEFAULT '',
  description TEXT DEFAULT '',
  member_id TEXT,
  month TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS admins (
  email TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  action TEXT NOT NULL,
  entity TEXT DEFAULT '',
  entity_id TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_payments_member_month ON payments(member_id, month);
CREATE INDEX IF NOT EXISTS idx_fund_date ON fund_transactions(tx_date);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
