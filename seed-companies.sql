-- Starter directory only: being listed is not an allegation or endorsement.
-- Financial records remain empty until individual disclosures are reviewed and approved.
INSERT INTO companies (slug, name, sector, legal_entity_name, jurisdiction) VALUES
('mcdonalds', 'McDonald''s', 'Restaurants', 'McDonald''s Corporation', 'United States'),
('walmart', 'Walmart', 'Retail', 'Walmart Inc.', 'United States'),
('coca-cola', 'Coca-Cola', 'Beverages', 'The Coca-Cola Company', 'United States'),
('amazon', 'Amazon', 'Technology and retail', 'Amazon.com, Inc.', 'United States'),
('nike', 'Nike', 'Apparel', 'NIKE, Inc.', 'United States'),
('apple', 'Apple', 'Technology', 'Apple Inc.', 'United States')
ON CONFLICT(slug) DO UPDATE SET name=excluded.name, sector=excluded.sector,
legal_entity_name=excluded.legal_entity_name, jurisdiction=excluded.jurisdiction;
