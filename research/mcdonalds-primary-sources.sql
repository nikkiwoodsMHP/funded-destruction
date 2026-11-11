-- McDonald's pilot: two primary-source research records.
-- Sources: FEC committee profile (2025-2026), McDonald's Feb 11, 2026 results release.
-- Committee receipts are NOT corporate campaign contributions.
INSERT INTO sources(title,publisher,url,publication_date,status,reviewed_at) VALUES
('McDonalds Corporation Political Action Committee: 2025-2026 financial summary','Federal Election Commission','https://www.fec.gov/data/committee/C00063164/',NULL,'approved',CURRENT_TIMESTAMP),
('McDonalds Reports Fourth Quarter and Full Year 2025 Results','McDonald''s Corporation','https://corporate.mcdonalds.com/corpmcd/our-stories/article/Q4-full-year-2025-results.html','2026-02-11','approved',CURRENT_TIMESTAMP)
ON CONFLICT(url) DO UPDATE SET title=excluded.title,publisher=excluded.publisher,publication_date=excluded.publication_date,status='approved',reviewed_at=CURRENT_TIMESTAMP;
INSERT INTO financial_records(company_id,source_id,category,record_type,description,recipient_name,amount,currency,period_start,period_end,evidence_level,review_status,reviewed_at)
SELECT c.id,s.id,'Political finance','PAC receipts',
'FEC-reported total receipts for the separately registered McDonald''s Corporation Political Action Committee, Jan. 1, 2025 through Oct. 14, 2026. This is PAC fundraising, NOT direct political contributions made by McDonald''s Corporation.',
'McDonalds Corporation Political Action Committee',735666.46,'USD','2025-01-01','2026-10-14','Federal Election Commission summary','approved',CURRENT_TIMESTAMP
FROM companies c JOIN sources s ON s.url='https://www.fec.gov/data/committee/C00063164/' WHERE c.slug='mcdonalds'
AND NOT EXISTS(SELECT 1 FROM financial_records f WHERE f.company_id=c.id AND f.source_id=s.id AND f.record_type='PAC receipts' AND f.period_start='2025-01-01');
INSERT INTO financial_records(company_id,source_id,category,record_type,description,recipient_name,amount,currency,period_start,period_end,evidence_level,review_status,reviewed_at)
SELECT c.id,s.id,'Company financial context','Systemwide sales',
'McDonald''s reported more than $139 billion in worldwide systemwide sales for 2025, including franchised restaurant sales. Systemwide sales are NOT consolidated corporate revenue, political contributions, or evidence of environmental wrongdoing.',
NULL,NULL,'USD','2025-01-01','2025-12-31','Company earnings release','approved',CURRENT_TIMESTAMP
FROM companies c JOIN sources s ON s.url='https://corporate.mcdonalds.com/corpmcd/our-stories/article/Q4-full-year-2025-results.html' WHERE c.slug='mcdonalds'
AND NOT EXISTS(SELECT 1 FROM financial_records f WHERE f.company_id=c.id AND f.source_id=s.id AND f.record_type='Systemwide sales' AND f.period_start='2025-01-01');