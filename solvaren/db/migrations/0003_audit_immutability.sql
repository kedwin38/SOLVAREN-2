-- SOLVAREN migration 0003 — Audit, evidence and immutability (spec §14) plus the
-- Daraja configuration and the failure dictionary.
--
-- The audit layer is a security boundary, not a convenience log:
--   * `audit_events` is append-only for every role: UPDATE and DELETE are refused by
--     trigger, including for table owners.
--   * Every event is sealed to its predecessor: the sequence and chain link are assigned
--     by the `seal_audit_event` trigger, never trusted from the caller, and the digest
--     covers every field that matters.
--   * Guard triggers on transactions, instructions, batches and challenges enforce the
--     state-machine invariants even if application logic is bypassed.

CREATE TABLE audit_events (
  id                UUID PRIMARY KEY,
  event_reference   TEXT NOT NULL,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  sequence          BIGINT NOT NULL CHECK (sequence > 0),
  actor_id          TEXT NOT NULL,             -- user id or "system:…" actor
  actor_level       TEXT CHECK (actor_level IN ('L1', 'L2', 'L3')),
  event_class       TEXT NOT NULL CHECK (event_class IN (
                      'IDENTITY', 'AUTHORITY', 'PAYMENT', 'INTEGRATION', 'SECURITY',
                      'BACKUP', 'ADMINISTRATION', 'DATA_EXPORT')),
  action            TEXT NOT NULL,
  object_type       TEXT NOT NULL,
  object_id         TEXT,
  outcome           TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
  previous_state    JSONB,
  new_state         JSONB,
  security_context  JSONB NOT NULL DEFAULT '{}',
  detail            JSONB NOT NULL DEFAULT '{}',
  correlation_id    TEXT NOT NULL,
  previous_hash     TEXT NOT NULL,
  event_hash        TEXT NOT NULL,
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT audit_sequence_org_unique UNIQUE (organization_id, sequence)
);

CREATE INDEX audit_org_time_idx    ON audit_events (organization_id, occurred_at DESC);
CREATE INDEX audit_org_class_idx   ON audit_events (organization_id, event_class, occurred_at DESC);
CREATE INDEX audit_actor_idx       ON audit_events (organization_id, actor_id, occurred_at DESC);
CREATE INDEX audit_object_idx      ON audit_events (organization_id, object_type, object_id);
CREATE INDEX audit_correlation_idx ON audit_events (correlation_id);
CREATE INDEX audit_denied_idx      ON audit_events (organization_id, occurred_at DESC) WHERE outcome = 'DENIED';

-- Assign sequence and chain link. The digest itself is computed by the application
-- (@solvaren/core `canonicalEventBody` — deterministic key-sorted JSON) and supplied in
-- the INSERT; the trigger owns position and linkage, which the caller must never choose.
-- Tamper-evidence holds because: content changes break the stored digest (recomputed on
-- verification), and insertions, deletions or reordering break the previous_hash chain.
CREATE OR REPLACE FUNCTION seal_audit_event() RETURNS trigger AS $$
DECLARE
  tail RECORD;
BEGIN
  SELECT sequence, event_hash INTO tail
    FROM audit_events
   WHERE organization_id = NEW.organization_id
   ORDER BY sequence DESC
   LIMIT 1
   FOR UPDATE;

  IF tail IS NULL THEN
    NEW.sequence := 1;
    NEW.previous_hash := 'SLV-GENESIS-0000000000000000000000000000000000000000000000000000';
  ELSE
    NEW.sequence := tail.sequence + 1;
    NEW.previous_hash := tail.event_hash;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_seal BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION seal_audit_event();

-- Append-only, for every role. Even the table owner cannot UPDATE or DELETE audit
-- history without disabling these triggers — and the chain makes the resulting gap
-- detectable.
CREATE OR REPLACE FUNCTION refuse() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'SOLVAREN immutability: % on % is not permitted', TG_OP, TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION refuse();
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION refuse();

-- Approvals and callback evidence are append-only history.
CREATE TRIGGER approvals_no_update BEFORE UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION refuse();
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals
  FOR EACH ROW EXECUTE FUNCTION refuse();
CREATE TRIGGER provider_callbacks_no_delete BEFORE DELETE ON provider_callbacks
  FOR EACH ROW EXECUTE FUNCTION refuse();

CREATE OR REPLACE VIEW audit_chain_tails AS
SELECT organization_id, MAX(sequence) AS last_sequence
  FROM audit_events
 GROUP BY organization_id;

-- ---------------------------------------------------------------------------
-- Transaction guards: a settled transaction can never be re-settled, a receipt can
-- never be overwritten, and the financial columns are frozen once written.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION guard_transaction_update() RETURNS trigger AS $$
BEGIN
  IF OLD.status IN ('SUCCESS', 'FAILED', 'CANCELLED') AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'SOLVAREN immutability: transaction % is settled as % and cannot become %', OLD.id, OLD.status, NEW.status;
  END IF;
  IF OLD.mpesa_receipt_number IS NOT NULL AND NEW.mpesa_receipt_number IS DISTINCT FROM OLD.mpesa_receipt_number THEN
    RAISE EXCEPTION 'SOLVAREN immutability: the provider receipt on transaction % cannot be overwritten', OLD.id;
  END IF;
  IF NEW.status = 'SUCCESS' AND (NEW.mpesa_receipt_number IS NULL OR btrim(NEW.mpesa_receipt_number) = '') THEN
    RAISE EXCEPTION 'SOLVAREN immutability: SUCCESS requires a provider receipt (transaction %)', OLD.id;
  END IF;
  IF NEW.status = 'FAILED' AND (NEW.failure_code IS NULL OR btrim(NEW.failure_code) = '') THEN
    RAISE EXCEPTION 'SOLVAREN immutability: FAILED requires a failure code (transaction %)', OLD.id;
  END IF;
  IF NEW.amount_cents <> OLD.amount_cents THEN
    RAISE EXCEPTION 'SOLVAREN immutability: the amount on transaction % cannot change', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER transactions_guard_update BEFORE UPDATE ON transactions
  FOR EACH ROW EXECUTE FUNCTION guard_transaction_update();
CREATE TRIGGER transactions_no_delete BEFORE DELETE ON transactions
  FOR EACH ROW EXECUTE FUNCTION refuse();

-- ---------------------------------------------------------------------------
-- Instruction guards: once a batch has left the editable states, its instructions are
-- part of the financial record and can no longer be edited or removed.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION guard_instruction_update() RETURNS trigger AS $$
DECLARE
  batch_state TEXT;
BEGIN
  SELECT state INTO batch_state FROM payment_batches WHERE id = NEW.batch_id;
  IF batch_state NOT IN ('DRAFT', 'VALIDATED', 'RETURNED_FOR_CORRECTION') THEN
    RAISE EXCEPTION
      'SOLVAREN immutability: batch % is in state %; its instructions can no longer be edited',
      NEW.batch_id, batch_state;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instructions_guard_update BEFORE UPDATE ON payment_instructions
  FOR EACH ROW EXECUTE FUNCTION guard_instruction_update();
CREATE TRIGGER instructions_guard_delete BEFORE DELETE ON payment_instructions
  FOR EACH ROW EXECUTE FUNCTION refuse();

-- ---------------------------------------------------------------------------
-- Batch guards: financial and workflow columns freeze once the batch has been released;
-- state columns cannot be mutated into a settled state by hand.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION guard_batch_update() RETURNS trigger AS $$
BEGIN
  IF OLD.released_at IS NOT NULL THEN
    IF NEW.total_amount_cents <> OLD.total_amount_cents
       OR NEW.instruction_count <> OLD.instruction_count
       OR NEW.version <> OLD.version THEN
      RAISE EXCEPTION
        'SOLVAREN immutability: batch % has been released; its financial columns are frozen',
        OLD.id;
    END IF;
  END IF;
  IF OLD.settled_at IS NOT NULL AND NEW.state <> OLD.state THEN
    RAISE EXCEPTION
      'SOLVAREN immutability: batch % is settled as % and its state cannot change',
      OLD.id, OLD.state;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER batches_guard_update BEFORE UPDATE ON payment_batches
  FOR EACH ROW EXECUTE FUNCTION guard_batch_update();

-- ---------------------------------------------------------------------------
-- Challenge guards: a consumed ceremony is immutable evidence.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION guard_challenge_update() RETURNS trigger AS $$
BEGIN
  IF OLD.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION
      'SOLVAREN immutability: authorization challenge % has been consumed and is evidence',
      OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER challenges_guard_update BEFORE UPDATE ON authorization_challenges
  FOR EACH ROW EXECUTE FUNCTION guard_challenge_update();
CREATE TRIGGER challenges_no_delete BEFORE DELETE ON authorization_challenges
  FOR EACH ROW EXECUTE FUNCTION refuse();

-- ---------------------------------------------------------------------------
-- Daraja integration configuration. Secrets live in the secret store; this table holds
-- references and masked metadata only. The callback URL includes the authentication
-- secret segment so a stored URL is exactly what Safaricom will POST to.
-- ---------------------------------------------------------------------------

CREATE TABLE daraja_configurations (
  id                          UUID PRIMARY KEY,
  organization_id             UUID NOT NULL REFERENCES organizations(id),
  environment                 TEXT NOT NULL CHECK (environment IN ('sandbox', 'production')),
  short_code                  TEXT NOT NULL CONSTRAINT daraja_shortcode_format CHECK (short_code ~ '^[0-9]{5,9}$'),
  initiator_name              TEXT NOT NULL,
  command_id                  TEXT NOT NULL DEFAULT 'BusinessPayment'
                              CHECK (command_id IN ('BusinessPayment', 'SalaryPayment', 'PromotionPayment')),
  consumer_key_secret_ref     TEXT NOT NULL,
  consumer_secret_secret_ref  TEXT NOT NULL,
  security_credential_ref     TEXT NOT NULL,
  callback_secret_ref         TEXT NOT NULL,
  consumer_key_last_four      TEXT,
  credential_version          INTEGER NOT NULL DEFAULT 1,
  credential_rotated_at       TIMESTAMPTZ,
  result_url                  TEXT NOT NULL,
  queue_timeout_url           TEXT NOT NULL,
  status_result_url           TEXT NOT NULL,
  balance_result_url          TEXT NOT NULL,
  status                      TEXT NOT NULL DEFAULT 'DISABLED'
                              CHECK (status IN ('DISABLED', 'TESTING', 'ENABLED', 'ERROR')),
  last_test_at                TIMESTAMPTZ,
  last_test_ok                BOOLEAN,
  last_test_message           TEXT,
  enabled_at                  TIMESTAMPTZ,
  enabled_by_user_id          UUID REFERENCES users(id),
  disabled_reason             TEXT,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT daraja_one_per_environment UNIQUE (organization_id, environment),
  CONSTRAINT daraja_urls_https CHECK (
    result_url LIKE 'https://%'
    AND queue_timeout_url LIKE 'https://%'
    AND status_result_url LIKE 'https://%'
    AND balance_result_url LIKE 'https://%'),
  CONSTRAINT daraja_enabled_requires_passing_test CHECK (
    status <> 'ENABLED' OR last_test_ok = TRUE)
);

CREATE INDEX daraja_active_idx ON daraja_configurations (organization_id) WHERE status = 'ENABLED';

CREATE TRIGGER daraja_configurations_updated_at BEFORE UPDATE ON daraja_configurations
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------------------
-- Failure dictionary: organisation overrides > platform defaults > compiled fallback.
-- ---------------------------------------------------------------------------

CREATE TABLE failure_reason_map (
  provider_code    TEXT NOT NULL,
  organization_id  UUID REFERENCES organizations(id),   -- NULL = platform default
  reason           TEXT NOT NULL,
  failure_class    TEXT NOT NULL CHECK (failure_class IN (
                     'FUNDING', 'RECIPIENT', 'LIMIT', 'CREDENTIAL', 'PERMISSION',
                     'PROVIDER', 'REQUEST', 'AMBIGUOUS', 'UNKNOWN')),
  operator_action  TEXT NOT NULL,
  transient        BOOLEAN NOT NULL DEFAULT FALSE,
  updated_by_user_id UUID REFERENCES users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT failure_map_scope_unique UNIQUE (organization_id, provider_code),
  CONSTRAINT failure_map_reason_not_blank CHECK (btrim(reason) <> '' AND lower(btrim(reason)) <> 'error')
);
