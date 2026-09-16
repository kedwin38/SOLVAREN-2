-- SOLVAREN migration 0016 — L3 exemption from schema-level separation of duties.
--
-- By organizational decision, L3 (the chief/executive authority) is the overall
-- superior of the system and may prepare, review, approve and authorize a batch alone,
-- start to finish. This was already implemented at the application layer
-- (packages/core/src/sod.ts: assertNotSelfApproval / assertNotSelfAuthorization both
-- return immediately for actorLevel === 'L3'). The application layer can be bypassed;
-- the schema cannot — so 0002's unconditional `batches_no_self_approval` and
-- `batches_no_self_authorization` CHECK constraints must be replaced with a trigger
-- that can look up the acting user's authority level (a plain CHECK constraint cannot
-- reference another table). L1 and L2 remain fully, unconditionally bound: only an
-- approver or authorizer whose own authority_level is 'L3' is exempt.
--
-- 0002 is already applied and its checksum is locked, so this ships as a new forward
-- migration rather than an edit to that file.

ALTER TABLE payment_batches
  DROP CONSTRAINT batches_no_self_approval,
  DROP CONSTRAINT batches_no_self_authorization;

CREATE OR REPLACE FUNCTION enforce_batch_separation_of_duties() RETURNS TRIGGER AS $$
DECLARE
  approver_level TEXT;
  authorizer_level TEXT;
BEGIN
  IF NEW.approved_by_user_id IS NOT NULL THEN
    SELECT authority_level INTO approver_level FROM users WHERE id = NEW.approved_by_user_id;
    IF approver_level IS DISTINCT FROM 'L3' AND NEW.approved_by_user_id = NEW.created_by_user_id THEN
      RAISE EXCEPTION 'Separation of duties: the batch creator may not approve their own batch unless they hold L3 authority'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NEW.authorized_by_user_id IS NOT NULL THEN
    SELECT authority_level INTO authorizer_level FROM users WHERE id = NEW.authorized_by_user_id;
    IF authorizer_level IS DISTINCT FROM 'L3' THEN
      IF NEW.authorized_by_user_id = NEW.created_by_user_id OR NEW.authorized_by_user_id = NEW.approved_by_user_id THEN
        RAISE EXCEPTION 'Separation of duties: the batch creator/approver may not also authorize it unless they hold L3 authority'
          USING ERRCODE = '23514';
      END IF;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER batches_separation_of_duties
  BEFORE INSERT OR UPDATE ON payment_batches
  FOR EACH ROW EXECUTE FUNCTION enforce_batch_separation_of_duties();
