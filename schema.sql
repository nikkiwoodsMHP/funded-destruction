PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS companies (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  sector TEXT,
  legal_entity_name TEXT,
  jurisdiction TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  publisher TEXT NOT NULL,
  url TEXT NOT NULL UNIQUE,
  publication_date TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','rejected')),
  reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS financial_records (
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  source_id INTEGER NOT NULL REFERENCES sources(id),
  category TEXT NOT NULL,
  record_type TEXT NOT NULL,
  description TEXT NOT NULL,
  recipient_name TEXT,
  amount REAL,
  currency TEXT DEFAULT 'USD',
  period_start TEXT,
  period_end TEXT,
  evidence_level TEXT NOT NULL DEFAULT 'reported',
  review_status TEXT NOT NULL DEFAULT 'draft' CHECK(review_status IN ('draft','approved','rejected')),
  reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS relationships (
  id INTEGER PRIMARY KEY,
  company_id INTEGER NOT NULL REFERENCES companies(id),
  source_id INTEGER NOT NULL REFERENCES sources(id),
  target_name TEXT NOT NULL,
  relationship_type TEXT NOT NULL,
  description TEXT,
  review_status TEXT NOT NULL DEFAULT 'draft' CHECK(review_status IN ('draft','approved','rejected'))
);
CREATE TABLE IF NOT EXISTS evidence_reports (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  general_location TEXT NOT NULL,
  incident_period TEXT,
  description TEXT NOT NULL,
  public_source_url TEXT,
  submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','screening','verifying','investigating','closed')),
  review_notes TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS editorial_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL REFERENCES evidence_reports(id),
  editor_email TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_status TEXT,
  new_status TEXT,
  occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_financial_company ON financial_records(company_id,review_status);
CREATE INDEX IF NOT EXISTS idx_relationship_company ON relationships(company_id,review_status);
CREATE INDEX IF NOT EXISTS idx_reports_status ON evidence_reports(status,submitted_at);