-- SOLVAREN migration 0002 — Payment domain: recipients, batches, instructions,
-- approvals, authorization challenges, idempotency, transactions, callbacks,
-- reconciliation, risk, balances, templates and the financial calendar.

CREATE TABLE departments (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  name              TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
  status            TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT departments_org_name_unique UNIQUE (organization_id, name)
);

CREATE INDEX departments_org_idx ON departments (organization_id) WHERE status = 'ACTIVE';

CREATE TABLE recipients (
  id                  UUID PRIMARY KEY,
  organization_id     UUID NOT NULL REFERENCES organizations(id),
  full_name           TEXT NOT NULL CHECK (char_length(full_name) BETWEEN 1 AND 140),
  msisdn              TEXT NOT NULL
                      CONSTRAINT recipients_msisdn_format CHECK (msisdn ~ '^254(7|1)[0-9]{8}$'),
  external_reference  TEXT,
  department_id       UUID REFERENCES departments(id),
  status              TEXT NOT NULL DEFAULT 'ACTIVE'
                      CHECK (status IN ('ACTIVE', 'INACTIVE', 'BLOCKED')),
  notes               TEXT,
  created_by_user_id  UUID NOT NULL REFERENCES users(id),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT recipients_org_msisdn_unique UNIQUE (organization_id, msisdn)
);

CREATE INDEX recipients_org_status_idx ON recipients (organization_id, status);
CREATE INDEX recipients_department_idx ON recipients (organization_id, department_id);
CREATE INDEX recipients_name_search_idx ON recipients USING gin (to_tsvector('simple', full_name));

CREATE TABLE payment_batches (
  id                     UUID PRIMARY KEY,
  organization_id        UUID NOT NULL REFERENCES organizations(id),
  batch_reference        TEXT NOT NULL,
  purpose                TEXT NOT NULL CHECK (char_length(purpose) BETWEEN 3 AND 200),
  payment_period         TEXT,
  department_id          UUID REFERENCES departments(id),
  state                  TEXT NOT NULL DEFAULT 'DRAFT' CHECK (state IN (
                           'DRAFT', 'VALIDATED', 'SUBMITTED_TO_L2', 'L2_REVIEW',
                           'RETURNED_FOR_CORRECTION', 'L3_READY', 'AUTHORIZATION_PENDING',
                           'AUTHORIZED', 'QUEUED', 'SUBMITTED', 'PROCESSING',
                           'SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'TIMEOUT',
                           'ON_HOLD', 'REJECTED', 'CANCELLED')),
  version                INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  instruction_count      INTEGER NOT NULL DEFAULT 0 CHECK (instruction_count >= 0),
  total_amount_cents     BIGINT  NOT NULL DEFAULT 0 CHECK (total_amount_cents >= 0),
  risk_score             INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  risk_band              TEXT CHECK (risk_band IN ('LOW', 'ELEVATED', 'HIGH', 'CRITICAL')),
  created_by_user_id     UUID NOT NULL REFERENCES users(id),
  submitted_by_user_id   UUID REFERENCES users(id),
  approved_by_user_id    UUID REFERENCES users(id),
  authorized_by_user_id  UUID REFERENCES users(id),
  last_material_edit_at  TIMESTAMPTZ,
  submitted_at           TIMESTAMPTZ,
  approved_at            TIMESTAMPTZ,
  authorized_at          TIMESTAMPTZ,
  released_at            TIMESTAMPTZ,
  settled_at             TIMESTAMPTZ,
  cancelled_at           TIMESTAMPTZ,
  cancel_reason          TEXT,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT batches_totals_non_negative CHECK (instruction_count >= 0 AND total_amount_cents >= 0),
  -- Separation of duties as schema, not just application logic (spec §20).
  CONSTRAINT batches_no_self_approval CHECK (
    approved_by_user_id IS NULL OR approved_by_user_id <> created_by_user_id
  ),
  CONSTRAINT batches_no_self_authorization CHECK (
    authorized_by_user_id IS NULL
    OR (authorized_by_user_id <> created_by_user_id AND authorized_by_user_id <> approved_by_user_id)
  )
);

-- One live batch reference per organization: the human reference is unique.
CREATE UNIQUE INDEX batches_org_reference_unique ON payment_batches (organization_id, batch_reference);

CREATE INDEX batches_org_state_idx    ON payment_batches (organization_id, state, created_at DESC);
CREATE INDEX batches_org_created_idx  ON payment_batches (organization_id, created_at DESC);
CREATE INDEX batches_pending_review_idx ON payment_batches (organization_id, state)
  WHERE state IN ('SUBMITTED_TO_L2', 'L2_REVIEW', 'L3_READY', 'ON_HOLD');

CREATE TABLE payment_instructions (
  id                       UUID PRIMARY KEY,
  organization_id          UUID NOT NULL REFERENCES organizations(id),
  batch_id                 UUID NOT NULL REFERENCES payment_batches(id),
  recipient_id             UUID NOT NULL REFERENCES recipients(id),
  recipient_name_snapshot  TEXT NOT NULL,
  msisdn_snapshot          TEXT NOT NULL
                           CONSTRAINT instructions_msisdn_format CHECK (msisdn_snapshot ~ '^254(7|1)[0-9]{8}$'),
  department_id            UUID REFERENCES departments(id),
  currency                 TEXT NOT NULL DEFAULT 'KES' CHECK (currency = 'KES'),
  amount_cents             BIGINT NOT NULL,
  remarks                  TEXT NOT NULL DEFAULT 'Business payment',
  occasion                 TEXT,
  source_line_number       INTEGER,
  retry_of_instruction_id  UUID REFERENCES payment_instructions(id),
  status                   TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                            'PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING',
                            'RECONCILING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED')),
  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT instructions_amount_range CHECK (amount_cents BETWEEN 1000 AND 25000000),
  CONSTRAINT instructions_amount_whole_shillings CHECK (amount_cents % 100 = 0),
  CONSTRAINT instructions_remarks_length CHECK (char_length(remarks) BETWEEN 2 AND 100),
  CONSTRAINT instructions_occasion_length CHECK (occasion IS NULL OR char_length(occasion) BETWEEN 1 AND 100)
);

CREATE INDEX instructions_batch_idx      ON payment_instructions (batch_id, status);
CREATE INDEX instructions_org_status_idx ON payment_instructions (organization_id, status);
CREATE INDEX instructions_recipient_idx  ON payment_instructions (organization_id, recipient_id, created_at DESC);

-- Totals and counts are maintained by trigger so they can never drift from the rows.
CREATE OR REPLACE FUNCTION refresh_batch_totals() RETURNS trigger AS $$
DECLARE
  target_batch UUID;
BEGIN
  target_batch := COALESCE(NEW.batch_id, OLD.batch_id);
  UPDATE payment_batches b
     SET instruction_count = (SELECT COUNT(*) FROM payment_instructions WHERE batch_id = target_batch),
         total_amount_cents = (SELECT COALESCE(SUM(amount_cents), 0) FROM payment_instructions WHERE batch_id = target_batch),
         updated_at = now()
   WHERE b.id = target_batch;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER instructions_refresh_totals
  AFTER INSERT OR UPDATE OR DELETE ON payment_instructions
  FOR EACH ROW EXECUTE FUNCTION refresh_batch_totals();

CREATE TABLE approvals (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  approval_reference TEXT NOT NULL,
  batch_id          UUID NOT NULL REFERENCES payment_batches(id),
  batch_version     INTEGER NOT NULL,
  actor_user_id     UUID NOT NULL REFERENCES users(id),
  actor_level       TEXT NOT NULL CHECK (actor_level IN ('L1', 'L2', 'L3')),
  action            TEXT NOT NULL CHECK (action IN (
                      'SUBMIT', 'APPROVE', 'REJECT', 'RETURN', 'HOLD', 'RELEASE_HOLD',
                      'AUTHORIZE', 'CANCEL')),
  reason            TEXT,
  risk_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX approvals_batch_idx ON approvals (batch_id, created_at DESC);
CREATE INDEX approvals_actor_idx ON approvals (organization_id, actor_user_id, created_at DESC);

CREATE TABLE batch_editors (
  batch_id         UUID NOT NULL REFERENCES payment_batches(id),
  user_id          UUID NOT NULL REFERENCES users(id),
  edit_count       INTEGER NOT NULL DEFAULT 1,
  last_edited_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (batch_id, user_id)
);

CREATE TABLE authorization_challenges (
  id                     UUID PRIMARY KEY,
  organization_id        UUID NOT NULL REFERENCES organizations(id),
  batch_id               UUID NOT NULL REFERENCES payment_batches(id),
  approval_id            UUID NOT NULL REFERENCES approvals(id),
  authorizer_user_id     UUID NOT NULL REFERENCES users(id),
  manifest_hash          TEXT NOT NULL,
  challenge_hash         TEXT NOT NULL,
  manifest_canonical_form TEXT NOT NULL,
  policy_digest          TEXT NOT NULL,
  nonce                  TEXT NOT NULL UNIQUE,
  batch_version          INTEGER NOT NULL,
  recipient_count        INTEGER NOT NULL,
  total_amount_cents     BIGINT NOT NULL,
  webauthn_challenge     TEXT NOT NULL,
  expires_at             TIMESTAMPTZ NOT NULL,
  issued_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed_at            TIMESTAMPTZ,
  signature_verified_at  TIMESTAMPTZ,
  pin_verified_at        TIMESTAMPTZ,
  webauthn_credential_id UUID REFERENCES webauthn_credentials(id),
  abandoned_at           TIMESTAMPTZ,
  CONSTRAINT challenge_expiry_after_issue CHECK (expires_at > issued_at)
);

-- Two concurrent authorization ceremonies on one batch are refused: this partial unique
-- index is what makes a double release structurally impossible, not just unlikely.
CREATE UNIQUE INDEX challenge_one_open_per_batch
  ON authorization_challenges (batch_id)
  WHERE consumed_at IS NULL AND abandoned_at IS NULL;

CREATE INDEX challenge_expiry_idx ON authorization_challenges (expires_at)
  WHERE consumed_at IS NULL AND abandoned_at IS NULL;

CREATE TABLE idempotency_claims (
  fingerprint                 TEXT PRIMARY KEY,
  organization_id             UUID NOT NULL REFERENCES organizations(id),
  instruction_id              UUID NOT NULL,
  state                       TEXT NOT NULL DEFAULT 'CLAIMED'
                              CHECK (state IN ('CLAIMED', 'SUBMITTED', 'SETTLED', 'ABANDONED')),
  originator_conversation_id  TEXT UNIQUE,
  claimed_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idempotency_instruction_idx ON idempotency_claims (instruction_id);

CREATE TABLE transactions (
  id                          UUID PRIMARY KEY,
  organization_id             UUID NOT NULL REFERENCES organizations(id),
  instruction_id              UUID NOT NULL REFERENCES payment_instructions(id),
  batch_id                    UUID NOT NULL REFERENCES payment_batches(id),
  status                      TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN (
                                'PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING',
                                'RECONCILING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED')),
  originator_conversation_id  TEXT NOT NULL UNIQUE,
  conversation_id             TEXT,
  mpesa_receipt_number        TEXT,
  request_fingerprint         TEXT NOT NULL,
  amount_cents                BIGINT NOT NULL CHECK (amount_cents > 0),
  failure_code                TEXT,
  failure_reason              TEXT,
  failure_class               TEXT,
  provider_result_description TEXT,
  status_source               TEXT CHECK (status_source IN
                                ('SYNC_ACK', 'CALLBACK', 'QUEUE_TIMEOUT', 'STATUS_QUERY', 'SYSTEM')),
  submitted_at                TIMESTAMPTZ,
  completed_at                TIMESTAMPTZ,
  last_status_check_at        TIMESTAMPTZ,
  status_check_count          INTEGER NOT NULL DEFAULT 0,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- A SUCCESS transaction always carries provider evidence; a FAILED one always a
  -- reason that is neither blank nor the bare word "error" (spec §23).
  CONSTRAINT transactions_success_requires_receipt CHECK (
    status <> 'SUCCESS' OR (mpesa_receipt_number IS NOT NULL AND char_length(btrim(mpesa_receipt_number)) > 0)
  ),
  CONSTRAINT transactions_failure_requires_reason CHECK (
    status <> 'FAILED' OR (failure_code IS NOT NULL AND char_length(btrim(COALESCE(failure_reason, 'x'))) > 0
                           AND lower(btrim(failure_reason)) <> 'error')
  ),
  CONSTRAINT transactions_amount_positive CHECK (amount_cents > 0)
);

CREATE INDEX transactions_org_created_idx   ON transactions (organization_id, created_at DESC, id DESC);
CREATE INDEX transactions_org_status_idx    ON transactions (organization_id, status, created_at DESC);
CREATE INDEX transactions_batch_idx         ON transactions (batch_id, status);
CREATE INDEX transactions_instruction_idx   ON transactions (instruction_id);
CREATE INDEX transactions_receipt_idx       ON transactions (organization_id, mpesa_receipt_number)
  WHERE mpesa_receipt_number IS NOT NULL;
CREATE INDEX transactions_conversation_idx  ON transactions (conversation_id) WHERE conversation_id IS NOT NULL;
CREATE INDEX transactions_failure_code_idx  ON transactions (organization_id, failure_code)
  WHERE failure_code IS NOT NULL;
CREATE INDEX transactions_in_flight_idx     ON transactions (organization_id, last_status_check_at NULLS FIRST)
  WHERE status IN ('PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'RECONCILING', 'TIMEOUT');
CREATE INDEX transactions_failed_export_idx ON transactions (organization_id, created_at DESC)
  WHERE status = 'FAILED';

CREATE TABLE provider_callbacks (
  id                        UUID PRIMARY KEY,
  organization_id           UUID NOT NULL REFERENCES organizations(id),
  callback_type             TEXT NOT NULL CHECK (callback_type IN
                              ('B2C_RESULT', 'B2C_TIMEOUT', 'TRANSACTION_STATUS', 'ACCOUNT_BALANCE')),
  originator_conversation_id TEXT,
  conversation_id           TEXT,
  result_code               TEXT,
  payload_digest            TEXT NOT NULL UNIQUE,   -- replay protection by content hash
  raw_payload               JSONB NOT NULL,          -- protected evidence (spec §9.4)
  source_ip                 INET,
  transaction_id            UUID REFERENCES transactions(id),
  processed_at              TIMESTAMPTZ,
  processing_outcome        TEXT CHECK (processing_outcome IN
                              ('PENDING', 'APPLIED', 'DUPLICATE', 'UNMATCHED', 'REJECTED',
                               'IGNORED_SETTLED')),
  processing_note           TEXT,
  received_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX provider_callbacks_txn_idx      ON provider_callbacks (transaction_id, received_at DESC);
CREATE INDEX provider_callbacks_unmatched_idx ON provider_callbacks (organization_id, received_at DESC)
  WHERE processing_outcome IN ('UNMATCHED', 'REJECTED');

CREATE TABLE reconciliation_cases (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  transaction_id    UUID NOT NULL REFERENCES transactions(id),
  case_reference    TEXT NOT NULL,
  state             TEXT NOT NULL DEFAULT 'OPEN' CHECK (state IN
                      ('OPEN', 'QUERYING', 'ESCALATED', 'RESOLVED_SUCCESS', 'RESOLVED_FAILED',
                       'RESOLVED_MANUAL')),
  opened_reason     TEXT NOT NULL,
  discrepancy       BOOLEAN NOT NULL DEFAULT FALSE,
  query_attempts    INTEGER NOT NULL DEFAULT 0,
  next_query_at     TIMESTAMPTZ,
  evidence          JSONB NOT NULL DEFAULT '[]',
  resolved_at       TIMESTAMPTZ,
  resolution_note   TEXT,
  resolved_by_user_id UUID REFERENCES users(id),
  opened_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX reconciliation_reference_unique ON reconciliation_cases (organization_id, case_reference);
CREATE INDEX reconciliation_open_idx ON reconciliation_cases (organization_id, state, next_query_at NULLS FIRST)
  WHERE state IN ('OPEN', 'QUERYING');

CREATE TABLE risk_findings (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  batch_id          UUID NOT NULL REFERENCES payment_batches(id),
  batch_version     INTEGER NOT NULL,
  signal_type       TEXT NOT NULL,
  severity          TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  summary           TEXT NOT NULL,
  evidence          JSONB NOT NULL,
  instruction_ids   UUID[] NOT NULL DEFAULT '{}',
  source            TEXT NOT NULL DEFAULT 'DETERMINISTIC' CHECK (source IN ('DETERMINISTIC', 'AI_ADVISORY')),
  disposition       TEXT NOT NULL DEFAULT 'OPEN'
                    CHECK (disposition IN ('OPEN', 'ACKNOWLEDGED', 'CLEARED', 'ESCALATED')),
  dispositioned_by_user_id UUID REFERENCES users(id),
  dispositioned_at  TIMESTAMPTZ,
  disposition_note  TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX risk_findings_batch_idx ON risk_findings (batch_id, severity, disposition);
CREATE INDEX risk_findings_open_idx  ON risk_findings (organization_id, disposition) WHERE disposition = 'OPEN';

CREATE TABLE account_balance_snapshots (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  account_type      TEXT NOT NULL,
  currency          TEXT NOT NULL DEFAULT 'KES',
  available_cents   BIGINT NOT NULL,
  uncleared_cents   BIGINT NOT NULL DEFAULT 0,
  reserved_cents    BIGINT NOT NULL DEFAULT 0,
  as_of             TIMESTAMPTZ NOT NULL,
  source            TEXT NOT NULL CHECK (source IN ('CALLBACK', 'SCHEDULED', 'ON_DEMAND')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX balance_snapshots_org_idx ON account_balance_snapshots (organization_id, account_type, as_of DESC);

-- ---------------------------------------------------------------------------
-- Batch orchestration (spec §10): recurring templates and the financial calendar.
-- ---------------------------------------------------------------------------

CREATE TABLE batch_templates (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  name              TEXT NOT NULL,
  purpose           TEXT NOT NULL,
  payment_period_pattern TEXT,          -- free-form description, e.g. "monthly"
  department_id     UUID REFERENCES departments(id),
  schedule_cron     TEXT NOT NULL,      -- UTC cron; stored from local time by the API
  schedule_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  last_materialized_at TIMESTAMPTZ,
  next_run_at       TIMESTAMPTZ,
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT batch_templates_name_unique UNIQUE (organization_id, name)
);

CREATE TABLE batch_template_items (
  template_id       UUID NOT NULL REFERENCES batch_templates(id) ON DELETE CASCADE,
  recipient_id      UUID NOT NULL REFERENCES recipients(id),
  amount_cents      BIGINT NOT NULL CHECK (amount_cents BETWEEN 1000 AND 25000000 AND amount_cents % 100 = 0),
  remarks           TEXT NOT NULL DEFAULT 'Business payment',
  PRIMARY KEY (template_id, recipient_id)
);

CREATE TABLE payment_calendar (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  kind              TEXT NOT NULL CHECK (kind IN ('HOLIDAY', 'BLACKOUT', 'CUTOFF_OVERRIDE')),
  local_date        DATE NOT NULL,
  description       TEXT,
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT payment_calendar_unique UNIQUE (organization_id, kind, local_date)
);

CREATE TRIGGER departments_updated_at BEFORE UPDATE ON departments
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER recipients_updated_at BEFORE UPDATE ON recipients
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER instructions_updated_at BEFORE UPDATE ON payment_instructions
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER transactions_updated_at BEFORE UPDATE ON transactions
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER batches_updated_at2 BEFORE UPDATE ON payment_batches
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER batch_templates_updated_at BEFORE UPDATE ON batch_templates
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
