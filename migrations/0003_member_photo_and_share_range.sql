-- Preserve all existing member data while allowing 0-10 shares and storing a profile photo.
CREATE TABLE IF NOT EXISTS members_new (
  id TEXT PRIMARY KEY, member_no INTEGER NOT NULL UNIQUE, name TEXT NOT NULL, position TEXT DEFAULT '', phone TEXT DEFAULT '',
  shares INTEGER NOT NULL CHECK (shares >= 0 AND shares <= 10), profile_photo TEXT DEFAULT '', join_date TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR REPLACE INTO members_new (id,member_no,name,position,phone,shares,profile_photo,join_date,active,created_at,updated_at)
SELECT id,member_no,name,position,phone,CASE WHEN shares < 0 THEN 0 WHEN shares > 10 THEN 10 ELSE shares END,'',join_date,active,created_at,updated_at FROM members;
DROP TABLE members;
ALTER TABLE members_new RENAME TO members;
CREATE INDEX IF NOT EXISTS idx_members_no ON members(member_no);
