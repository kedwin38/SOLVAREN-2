-- SOLVAREN migration 0014 — extend instruction-freeze guard and reporting views to cover
-- the new recipient profile fields added in 0013 (role, territory, region, sales).
--
-- Migrations are append-only: 0010's guard_instruction_update() and 0006's
-- transaction_explorer view are replaced here in place (CREATE OR REPLACE) rather than
-- editing the historical files, per docs/deployment.md's rollback policy.

CREATE OR REPLACE FUNCTION guard_instruction_update() RETURNS trigger AS $$
DECLARE
  batch_state TEXT;
BEGIN
  IF NEW.amount_cents IS DISTINCT FROM OLD.amount_cents
     OR NEW.recipient_id IS DISTINCT FROM OLD.recipient_id
     OR NEW.recipient_name_snapshot IS DISTINCT FROM OLD.recipient_name_snapshot
     OR NEW.msisdn_snapshot IS DISTINCT FROM OLD.msisdn_snapshot
     OR NEW.department_id IS DISTINCT FROM OLD.department_id
     OR NEW.currency IS DISTINCT FROM OLD.currency
     OR NEW.remarks IS DISTINCT FROM OLD.remarks
     OR NEW.occasion IS DISTINCT FROM OLD.occasion
     OR NEW.batch_id IS DISTINCT FROM OLD.batch_id
     OR NEW.source_line_number IS DISTINCT FROM OLD.source_line_number
     OR NEW.retry_of_instruction_id IS DISTINCT FROM OLD.retry_of_instruction_id
     OR NEW.role_snapshot IS DISTINCT FROM OLD.role_snapshot
     OR NEW.territory_snapshot IS DISTINCT FROM OLD.territory_snapshot
     OR NEW.region_snapshot IS DISTINCT FROM OLD.region_snapshot
     OR NEW.sales_count IS DISTINCT FROM OLD.sales_count THEN
    SELECT state INTO batch_state FROM payment_batches WHERE id = NEW.batch_id;
    IF batch_state NOT IN ('DRAFT', 'VALIDATED', 'RETURNED_FOR_CORRECTION') THEN
      RAISE EXCEPTION
        'SOLVAREN immutability: batch % is in state %; its instructions can no longer be edited',
        NEW.batch_id, batch_state;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE VIEW transaction_explorer AS
SELECT t.id AS transaction_id,
       pi.id AS instruction_id,
       b.id AS batch_id,
       b.batch_reference,
       r.id AS recipient_id,
       pi.recipient_name_snapshot AS recipient_name,
       pi.msisdn_snapshot AS msisdn,
       d.id AS department_id,
       d.name AS department_name,
       pi.role_snapshot AS role,
       pi.territory_snapshot AS territory,
       pi.region_snapshot AS region,
       pi.sales_count AS sales_count,
       pi.amount_cents,
       t.status,
       t.failure_code,
       t.failure_reason,
       t.failure_class,
       t.provider_result_description,
       t.mpesa_receipt_number,
       t.conversation_id,
       t.originator_conversation_id,
       t.status_source,
       t.last_status_check_at,
       t.created_at,
       t.submitted_at,
       t.completed_at,
       t.updated_at
  FROM transactions t
  JOIN payment_instructions pi ON pi.id = t.instruction_id
  JOIN payment_batches b       ON b.id = t.batch_id
  JOIN recipients r            ON r.id = pi.recipient_id
  LEFT JOIN departments d      ON d.id = pi.department_id;
