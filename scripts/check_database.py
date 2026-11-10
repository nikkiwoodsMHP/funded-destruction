#!/usr/bin/env python3
"""Run local SQLite validation of the Cloudflare D1 schema and seed.
No Cloudflare credentials or remote database access required.
"""
from pathlib import Path
import sqlite3

root = Path(__file__).resolve().parents[1]
db = sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys=ON")
db.executescript((root / "schema.sql").read_text())
seed = (root / "seed-companies.sql").read_text()
db.executescript(seed)
db.executescript(seed)  # Must be safe to rerun.
companies = db.execute("SELECT slug FROM companies ORDER BY slug").fetchall()
assert len(companies) == 6, companies
for name in ("financial_records", "sources", "relationships", "evidence_reports", "editorial_audit"):
    assert db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone(), name

# A financial claim must never appear without a reviewed record and reviewed source.
company_id = db.execute("SELECT id FROM companies WHERE slug='mcdonalds'").fetchone()[0]
db.execute("INSERT INTO sources(title,publisher,url) VALUES(?,?,?)",
           ("Fixture source", "Testing only", "https://example.org/test"))
source_id = db.execute("SELECT id FROM sources WHERE url=?", ("https://example.org/test",)).fetchone()[0]
db.execute("INSERT INTO financial_records(company_id,source_id,category,record_type,description) VALUES(?,?,?,?,?)",
           (company_id, source_id, "test", "test", "Synthetic unpublished record"))
query = """SELECT f.id FROM financial_records f JOIN sources s ON s.id=f.source_id
           WHERE f.company_id=? AND f.review_status='approved' AND s.status='approved'"""
assert db.execute(query, (company_id,)).fetchall() == []
db.execute("UPDATE financial_records SET review_status='approved'")
assert db.execute(query, (company_id,)).fetchall() == []
db.execute("UPDATE sources SET status='approved'")
assert len(db.execute(query, (company_id,)).fetchall()) == 1

# A report does not grant permission for public exposure.
db.execute("""INSERT INTO evidence_reports(id,category,general_location,description)
           VALUES('test-id','Other environmental concern','Test region',?)""",
           ("Testing report description; no real identity or allegations.",))
assert db.execute("SELECT status FROM evidence_reports WHERE id='test-id'").fetchone()[0] == "new"

print("PASS: schema, six idempotent company seeds, publication gate, private report status")
