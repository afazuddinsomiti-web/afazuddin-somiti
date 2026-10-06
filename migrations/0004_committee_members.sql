-- Add a dedicated, fully editable committee directory without touching existing member/payment/fund data.
CREATE TABLE IF NOT EXISTS committee_members (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  designation TEXT NOT NULL DEFAULT '',
  section TEXT NOT NULL CHECK(section IN ('board','executive','advisory')),
  photo TEXT DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_committee_section_order
  ON committee_members(section, sort_order, created_at);
