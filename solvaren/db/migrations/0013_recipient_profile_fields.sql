-- SOLVAREN migration 0013 — Recipient profile fields (role, team territory/region, sales).
--
-- The organisation's preferred payroll export carries more than name/phone/amount: a
-- role, an ID number (already covered by recipients.external_reference), a team (already
-- covered by department_id — a "team" and a "department" are the same concept here), a
-- territory, a region, and a per-run sales figure. Territory/region/role describe the
-- recipient and are worth keeping on the master record; sales is a per-payout-run figure
-- and belongs on the instruction, snapshotted like every other financial-adjacent field.
--
-- Nothing here changes what gets signed into the release manifest (packages/core/src/
-- manifest.ts hashes instructionId/recipientId/msisdn/amountCents only) — these are
-- descriptive/reporting fields, not money-movement fields.

ALTER TABLE recipients
  ADD COLUMN role      TEXT CHECK (role IS NULL OR char_length(role) BETWEEN 1 AND 80),
  ADD COLUMN territory  TEXT CHECK (territory IS NULL OR char_length(territory) BETWEEN 1 AND 80),
  ADD COLUMN region     TEXT CHECK (region IS NULL OR char_length(region) BETWEEN 1 AND 80);

ALTER TABLE payment_instructions
  ADD COLUMN role_snapshot      TEXT CHECK (role_snapshot IS NULL OR char_length(role_snapshot) BETWEEN 1 AND 80),
  ADD COLUMN territory_snapshot TEXT CHECK (territory_snapshot IS NULL OR char_length(territory_snapshot) BETWEEN 1 AND 80),
  ADD COLUMN region_snapshot    TEXT CHECK (region_snapshot IS NULL OR char_length(region_snapshot) BETWEEN 1 AND 80),
  ADD COLUMN sales_count        NUMERIC CHECK (sales_count IS NULL OR sales_count >= 0);

CREATE INDEX recipients_territory_idx ON recipients (organization_id, territory) WHERE territory IS NOT NULL;
CREATE INDEX recipients_region_idx    ON recipients (organization_id, region) WHERE region IS NOT NULL;
