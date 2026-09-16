-- SOLVAREN migration 0015 — add the missing 404.001.01 platform-default failure reason.
--
-- 0005's seed (generated from packages/core/src/failure-reasons.ts) was missing
-- 404.001.01 ("Resource not found — wrong endpoint"), documented in the platform-wide
-- gateway error table alongside 404.001.03/404.001.04/404.003.01, which were present.
-- 0005 is already applied and its checksum is locked, so this ships as a new forward
-- migration rather than an edit to that file. The compiled dictionary
-- (packages/core/src/failure-reasons.ts) is the runtime fallback and already carries
-- this code; this migration brings the database-backed platform default in line with it.

INSERT INTO failure_reason_map (provider_code, organization_id, reason, failure_class, operator_action, transient)
VALUES
  ('404.001.01', NULL, 'Daraja reports the endpoint does not exist', 'REQUEST', 'Raise an engineering incident — the API path is wrong for this Daraja product', false)
ON CONFLICT (organization_id, provider_code) DO UPDATE SET
  reason = EXCLUDED.reason,
  failure_class = EXCLUDED.failure_class,
  operator_action = EXCLUDED.operator_action,
  transient = EXCLUDED.transient;
