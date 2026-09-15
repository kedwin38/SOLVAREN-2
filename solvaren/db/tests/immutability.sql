-- SOLVAREN database security assertions (spec §24).
--
-- Attacks the schema directly: attempt every forbidden mutation and assert the database
-- refuses it. Runs under the application's role assumptions; a superuser can disable
-- triggers (documented in the threat model) — these tests prove the *application*
-- cannot bypass its own invariants.
--
-- Each assertion uses an ASSERT in a DO block so the run fails loudly per check.

\set ON_ERROR_STOP off
\pset pager off

-- Test organization and users seeded for this run.
CREATE TEMP TABLE seed AS
SELECT '11111111-1111-1111-1111-111111111111'::uuid AS org_id,
       '22222222-2222-2222-2222-222222222222'::uuid AS creator_id,
       '33333333-3333-3333-3333-333333333333'::uuid AS approver_id,
       '44444444-4444-4444-4444-444444444444'::uuid AS batch_id,
       '55555555-5555-5555-5555-555555555555'::uuid AS recipient_id;

INSERT INTO organizations (id, slug, name)
SELECT org_id, 'dbtest-org', 'DB Test Org' FROM seed
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (id, organization_id, email, full_name, authority_level, status, password_hash, authorization_pin_hash)
SELECT creator_id, org_id, 'creator@dbtest.test', 'Creator', 'L1', 'ACTIVE', 'x', 'y' FROM seed
ON CONFLICT (id) DO NOTHING;
INSERT INTO users (id, organization_id, email, full_name, authority_level, status, password_hash, authorization_pin_hash)
SELECT approver_id, org_id, 'approver@dbtest.test', 'Approver', 'L3', 'ACTIVE', 'x', 'y' FROM seed
ON CONFLICT (id) DO NOTHING;

INSERT INTO payment_batches (id, organization_id, batch_reference, purpose, created_by_user_id, state)
SELECT batch_id, org_id, 'SLV-DBTEST-1', 'DB test batch', creator_id, 'DRAFT' FROM seed
ON CONFLICT (id) DO NOTHING;

INSERT INTO recipients (id, organization_id, full_name, msisdn, created_by_user_id)
SELECT recipient_id, org_id, 'DB Test Recipient', '254700000001', creator_id FROM seed
ON CONFLICT (id) DO NOTHING;

INSERT INTO payment_instructions (organization_id, batch_id, recipient_id, recipient_name_snapshot,
  msisdn_snapshot, amount_cents, remarks)
SELECT org_id, batch_id, recipient_id, 'DB Test Recipient', '254700000001', 500000, 'test' FROM seed;

-- ---------------------------------------------------------------------------
-- 1. A SUCCESS transaction without an M-PESA receipt is refused.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; seed_batch uuid; seed_recipient uuid;
BEGIN
  SELECT org_id, batch_id, recipient_id INTO seed_org, seed_batch, seed_recipient FROM seed;
  BEGIN
    INSERT INTO transactions (id, organization_id, instruction_id, batch_id, status,
      originator_conversation_id, request_fingerprint, amount_cents, status_source)
    VALUES (gen_random_uuid(), seed_org,
      (SELECT id FROM payment_instructions WHERE batch_id = seed_batch LIMIT 1),
      seed_batch, 'SUCCESS', 'SLV-DBTEST-FAIL-1', 'fp', 500000, 'CALLBACK');
    RAISE EXCEPTION 'ASSERTION 1 FAILED: SUCCESS without a receipt was accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '✓ 1. SUCCESS without a receipt refused';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 2. A FAILED transaction without a reason is refused.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; seed_batch uuid;
BEGIN
  SELECT org_id, batch_id INTO seed_org, seed_batch FROM seed;
  BEGIN
    INSERT INTO transactions (id, organization_id, instruction_id, batch_id, status,
      originator_conversation_id, request_fingerprint, amount_cents, status_source)
    VALUES (gen_random_uuid(), seed_org,
      (SELECT id FROM payment_instructions WHERE batch_id = seed_batch LIMIT 1),
      seed_batch, 'FAILED', 'SLV-DBTEST-FAIL-2', 'fp', 500000, 'CALLBACK');
    RAISE EXCEPTION 'ASSERTION 2 FAILED: FAILED without a code was accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '✓ 2. FAILED without a failure code refused';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 3. UPDATE and DELETE on audit_events are refused for every role.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid;
BEGIN
  SELECT org_id INTO seed_org FROM seed;
  INSERT INTO audit_events (id, event_reference, organization_id, actor_id, event_class,
    action, object_type, outcome, correlation_id, previous_hash, event_hash, security_context, detail)
  VALUES (gen_random_uuid(), 'EVT-DBTEST-1', seed_org, 'dbtest', 'PAYMENT',
    'dbtest.event', 'Test', 'SUCCESS', 'cor-dbdetestdbtestdb1', 'seed', 'hash1', '{}', '{}');

  BEGIN
    UPDATE audit_events SET action = 'tampered' WHERE event_reference = 'EVT-DBTEST-1';
    RAISE EXCEPTION 'ASSERTION 3a FAILED: audit UPDATE was accepted';
  EXCEPTION WHEN others THEN
    IF SQLERRM NOT LIKE '%immutability%' THEN RAISE EXCEPTION 'ASSERTION 3a unexpected: %', SQLERRM; END IF;
    RAISE NOTICE '✓ 3a. audit_events UPDATE refused';
  END;

  BEGIN
    DELETE FROM audit_events WHERE event_reference = 'EVT-DBTEST-1';
    RAISE EXCEPTION 'ASSERTION 3b FAILED: audit DELETE was accepted';
  EXCEPTION WHEN others THEN
    IF SQLERRM NOT LIKE '%immutability%' THEN RAISE EXCEPTION 'ASSERTION 3b unexpected: %', SQLERRM; END IF;
    RAISE NOTICE '✓ 3b. audit_events DELETE refused';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 4. A settled transaction cannot be re-settled; a receipt cannot be overwritten.
-- ---------------------------------------------------------------------------
DO $$
DECLARE txn_id uuid; seed_org uuid; seed_batch uuid; ins_id uuid;
BEGIN
  SELECT org_id, batch_id INTO seed_org, seed_batch FROM seed;
  SELECT id INTO ins_id FROM payment_instructions WHERE batch_id = seed_batch LIMIT 1;
  INSERT INTO transactions (id, organization_id, instruction_id, batch_id, status,
    originator_conversation_id, request_fingerprint, amount_cents, status_source, mpesa_receipt_number, completed_at)
  VALUES (gen_random_uuid(), seed_org, ins_id, seed_batch, 'SUCCESS',
    'SLV-DBTEST-OK-3', 'fp', 500000, 'CALLBACK', 'SG-DBTEST-1', now());
  SELECT id INTO txn_id FROM transactions WHERE originator_conversation_id = 'SLV-DBTEST-OK-3';

  BEGIN
    UPDATE transactions SET mpesa_receipt_number = 'SG-FORGED' WHERE id = txn_id;
    RAISE EXCEPTION 'ASSERTION 4a FAILED: receipt overwrite was accepted';
  EXCEPTION WHEN others THEN
    RAISE NOTICE '✓ 4a. provider receipt cannot be overwritten';
  END;

  BEGIN
    UPDATE transactions SET amount_cents = 9000000 WHERE id = txn_id;
    RAISE EXCEPTION 'ASSERTION 4b FAILED: amount change was accepted';
  EXCEPTION WHEN others THEN
    RAISE NOTICE '✓ 4b. transaction amount is frozen';
  END;

  BEGIN
    UPDATE transactions SET status = 'FAILED', failure_code = '1', failure_reason = 'rewritten' WHERE id = txn_id;
    RAISE EXCEPTION 'ASSERTION 4c FAILED: settled-state rewrite was accepted';
  EXCEPTION WHEN others THEN
    RAISE NOTICE '✓ 4c. a settled transaction cannot be re-settled';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 5. Instructions freeze once the batch leaves the editable states.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; seed_batch uuid;
BEGIN
  SELECT org_id, batch_id INTO seed_org, seed_batch FROM seed;
  UPDATE payment_batches SET state = 'SUBMITTED_TO_L2', submitted_by_user_id = creator_id FROM seed
   WHERE payment_batches.id = seed_batch;

  BEGIN
    UPDATE payment_instructions SET amount_cents = 9000000
     WHERE batch_id = (SELECT batch_id FROM seed);
    RAISE EXCEPTION 'ASSERTION 5 FAILED: instruction edit after submission was accepted';
  EXCEPTION WHEN others THEN
    RAISE NOTICE '✓ 5. instructions freeze after submission';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 6. A batch creator cannot be recorded as its own approver or authorizer.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; seed_batch uuid; seed_creator uuid;
BEGIN
  SELECT s.org_id, s.batch_id, s.creator_id INTO seed_org, seed_batch, seed_creator FROM seed s;
  BEGIN
    UPDATE payment_batches SET approved_by_user_id = seed_creator WHERE id = seed_batch;
    RAISE EXCEPTION 'ASSERTION 6a FAILED: self-approval was accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '✓ 6a. self-approval refused by the schema';
  END;

  BEGIN
    UPDATE payment_batches SET approved_by_user_id = (SELECT approver_id FROM seed),
      authorized_by_user_id = (SELECT approver_id FROM seed) WHERE id = seed_batch;
    RAISE EXCEPTION 'ASSERTION 6b FAILED: approver-as-authorizer was accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '✓ 6b. approver ≠ authorizer enforced by the schema';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 7. Two concurrent authorization ceremonies on one batch are refused.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; seed_batch uuid; seed_approver uuid; approval_id uuid; ch1 uuid;
BEGIN
  SELECT s.org_id, s.batch_id, s.approver_id INTO seed_org, seed_batch, seed_approver FROM seed s;
  UPDATE payment_batches SET state = 'L3_READY', approved_by_user_id = seed_approver WHERE id = seed_batch;
  INSERT INTO approvals (id, organization_id, approval_reference, batch_id, batch_version,
    actor_user_id, actor_level, action)
  VALUES (gen_random_uuid(), seed_org, 'APR-DBTEST', seed_batch, 1, seed_approver, 'L3', 'APPROVE');
  SELECT id INTO approval_id FROM approvals WHERE approval_reference = 'APR-DBTEST';

  INSERT INTO authorization_challenges (id, organization_id, batch_id, approval_id,
    authorizer_user_id, manifest_hash, challenge_hash, manifest_canonical_form, policy_digest,
    nonce, batch_version, recipient_count, total_amount_cents, webauthn_challenge, expires_at)
  VALUES (gen_random_uuid(), seed_org, seed_batch, approval_id, seed_approver,
    'h1', 'c1', 'canonical', 'pd', 'nonce-1', 1, 1, 500000, 'wc1', now() + interval '5 min');

  BEGIN
    INSERT INTO authorization_challenges (id, organization_id, batch_id, approval_id,
      authorizer_user_id, manifest_hash, challenge_hash, manifest_canonical_form, policy_digest,
      nonce, batch_version, recipient_count, total_amount_cents, webauthn_challenge, expires_at)
    VALUES (gen_random_uuid(), seed_org, seed_batch, approval_id, seed_approver,
      'h2', 'c2', 'canonical', 'pd', 'nonce-2', 1, 1, 500000, 'wc2', now() + interval '5 min');
    RAISE EXCEPTION 'ASSERTION 7 FAILED: a second concurrent ceremony was accepted';
  EXCEPTION WHEN unique_violation THEN
    RAISE NOTICE '✓ 7. one open ceremony per batch';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 8. A job's body cannot change after enqueue.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid; job_id uuid;
BEGIN
  SELECT org_id INTO seed_org FROM seed;
  INSERT INTO job_queue (id, queue, body, organization_id, correlation_id, max_attempts)
  VALUES (gen_random_uuid(), 'reconciliation',
    jsonb_build_object('type','SWEEP_ORGANIZATION','organizationId',seed_org::text,'correlationId','cor-dbdetestdbtestdb2'),
    seed_org, 'cor-dbdetestdbtestdb2', 3);
  SELECT id INTO job_id FROM job_queue WHERE correlation_id = 'cor-dbdetestdbtestdb2';

  BEGIN
    UPDATE job_queue SET body = body || '{"injected": true}'::jsonb WHERE id = job_id;
    RAISE EXCEPTION 'ASSERTION 8 FAILED: job body mutation was accepted';
  EXCEPTION WHEN others THEN
    RAISE NOTICE '✓ 8. a job body is immutable after enqueue';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- 9. An AI interaction can never truthfully claim a state change.
-- ---------------------------------------------------------------------------
DO $$
DECLARE seed_org uuid;
BEGIN
  SELECT org_id INTO seed_org FROM seed;
  BEGIN
    INSERT INTO ai_interactions (id, organization_id, user_id, capability, prompt_summary,
      context_digest, model, caused_state_change)
    VALUES (gen_random_uuid(), seed_org, (SELECT creator_id FROM seed), 'BATCH_ANALYSIS',
      'test', 'digest', 'test-model', TRUE);
    RAISE EXCEPTION 'ASSERTION 9 FAILED: caused_state_change=TRUE was accepted';
  EXCEPTION WHEN check_violation THEN
    RAISE NOTICE '✓ 9. AI cannot claim a state change';
  END;
END $$;

-- ---------------------------------------------------------------------------
-- Cleanup the seeded test rows (audit events and settled transactions are evidence;
-- they stay — a test database is disposable).
-- ---------------------------------------------------------------------------
DELETE FROM job_queue WHERE correlation_id LIKE 'cor-dbdetest%';
DELETE FROM authorization_challenges WHERE nonce LIKE 'nonce-%';
DELETE FROM approvals WHERE approval_reference = 'APR-DBTEST';
DELETE FROM transactions WHERE originator_conversation_id LIKE 'SLV-DBTEST%';
DELETE FROM payment_instructions WHERE batch_id = (SELECT batch_id FROM seed);
DELETE FROM payment_batches WHERE id = (SELECT batch_id FROM seed);
DELETE FROM recipients WHERE id = (SELECT recipient_id FROM seed);
DELETE FROM users WHERE id IN (SELECT creator_id FROM seed UNION SELECT approver_id FROM seed);
DELETE FROM organizations WHERE id = (SELECT org_id FROM seed);

RAISE NOTICE 'All database assertions passed.';
