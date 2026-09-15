-- 0010: instruction status is the lifecycle, not the financial record.
--
-- guard_instruction_update (0003) refused ALL updates to instructions once their batch
-- left DRAFT/VALIDATED/RETURNED_FOR_CORRECTION — including the status transitions the
-- payment pipeline itself must make (SUBMITTED → AWAITING_CALLBACK → SUCCESS/FAILED and
-- the reconciliation states). Every submitted payment would have deadlocked on its first
-- status update. The financial columns of an instruction are the record; those stay
-- frozen once the batch is beyond editing. Status, and only status, keeps moving.

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
     OR NEW.retry_of_instruction_id IS DISTINCT FROM OLD.retry_of_instruction_id THEN
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
