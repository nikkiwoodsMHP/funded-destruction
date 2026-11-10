# Funded Destruction — Cloudflare D1 connection

This repository deploys to **holy-resonance-a508**, the **preview**, not the public FundedDestruction.com website. The existing `wrangler.jsonc` intentionally does **not** reference a nonexistent database.

## Already committed
- `schema.sql`: company records, sources, financial disclosures, report submissions and editorial audit history.
- `src/worker.js`: GET `/api/health`, GET `/api/companies`, GET `/api/companies/:slug`, gated POST `/api/reports`, editor-only GET and PATCH review routes.
- `wrangler.d1.example.jsonc`: a safe configuration template; **not** the active config.

## Finish the Cloudflare connection
1. Cloudflare Dashboard → Storage & databases → D1 → Create database; name it `funded-destruction-preview`.
2. Copy the database ID. In the actual `wrangler.jsonc`, add the `d1_databases` entry from `wrangler.d1.example.jsonc` with the **real** database ID. Do not replace the rest of the configuration.
3. Apply the schema from a machine or CI session authenticated to this Cloudflare account: `npx wrangler d1 execute funded-destruction-preview --remote --file=./schema.sql`.\n4. Seed the **six neutral company names only** with `npx wrangler d1 execute funded-destruction-preview --remote --file=./seed-companies.sql`. This is safe to rerun; no transactions or allegations are seeded.
5. Deploy through the existing Git integration. Check `/api/health`: `database_connected` must be `true`. Check `/api/companies`: it should return a valid, initially empty list.
6. Do **not** switch `INTAKE_ENABLED` to `true` until Cloudflare Turnstile, rate limiting, consent/privacy information and the Cloudflare Access editor policy have been verified.

## Editorial safety
- The public company API only returns records AND sources explicitly marked `approved`.
- Reports do not have a public listing route. Intake remains closed by default.
- Editor routes require a signed, validated Cloudflare Access JWT and an allowlisted editor email.
- Do not commit access tokens, Turnstile secrets, reporter identities, or sensitive evidence.
- D1 is not a confidential whistleblower intake system by itself; plan a separate high-security channel before inviting sensitive reports.

## Verification
- `GET /api/health` — shows binding/feature readiness (does not write).
- `GET /api/config` — shows whether reporting is enabled.
- `GET /api/companies` — returns only company names and sectors.
- `GET /api/companies/mcdonalds` — returns an empty approved-record profile after the neutral directory seed is applied. Financial records will remain empty until reviewed.
- `POST /api/reports` — returns 503 until intake is intentionally enabled.
- `GET /api/editor/reports` without a valid Cloudflare Access identity — must return 401.

**Remaining blocker:** This chat has GitHub access, but no Cloudflare D1 creation/binding authorization. The database ID must be created or supplied from Cloudflare before we can commit the live binding.

## Automated integrity checks
`python3 scripts/check_database.py` is run by GitHub Actions on every commit. It checks idempotent seeding, schema creation, and that both the claim and source must be approved before publication.
