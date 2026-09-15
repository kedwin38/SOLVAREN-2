-- SOLVAREN migration 0004 — Backups, exports, report jobs, AI interactions,
-- security events and the notification outbox.

CREATE TABLE backup_configurations (
  id                    UUID PRIMARY KEY,
  organization_id       UUID NOT NULL UNIQUE REFERENCES organizations(id),
  provider_label        TEXT NOT NULL,
  endpoint              TEXT,
  region                TEXT,
  bucket                TEXT NOT NULL,
  path_prefix           TEXT NOT NULL DEFAULT 'solvaren/backups',
  access_key_secret_ref TEXT NOT NULL,
  secret_key_secret_ref TEXT NOT NULL,
  access_key_last_four  TEXT,
  encryption_mode       TEXT NOT NULL DEFAULT 'SSE_S3'
                        CHECK (encryption_mode IN ('SSE_S3', 'SSE_KMS', 'APPLICATION')),
  status                TEXT NOT NULL DEFAULT 'DISABLED'
                        CHECK (status IN ('CONNECTED', 'ERROR', 'DISABLED')),
  last_test_at          TIMESTAMPTZ,
  last_test_ok          BOOLEAN,
  last_test_message     TEXT,
  schedule_enabled      BOOLEAN NOT NULL DEFAULT FALSE,
  schedule_local_time   TEXT NOT NULL DEFAULT '02:00'
                        CHECK (schedule_local_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  schedule_timezone     TEXT NOT NULL DEFAULT 'Africa/Nairobi',
  retention_max_count   INTEGER NOT NULL DEFAULT 30
                        CONSTRAINT backup_retention_sane CHECK (retention_max_count BETWEEN 1 AND 3650),
  consecutive_failures  INTEGER NOT NULL DEFAULT 0,
  suspended_at          TIMESTAMPTZ,
  suspension_reason     TEXT,
  last_scheduled_run_at TIMESTAMPTZ,
  next_scheduled_run_at TIMESTAMPTZ,
  updated_by_user_id    UUID REFERENCES users(id),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- A schedule may only be enabled on a target whose credentials have passed a test.
  CONSTRAINT backup_schedule_requires_test CHECK (
    schedule_enabled = FALSE OR last_test_ok = TRUE)
);

CREATE TABLE backup_attempts (
  id                    UUID PRIMARY KEY,
  organization_id       UUID NOT NULL REFERENCES organizations(id),
  attempt_reference     TEXT NOT NULL,
  trigger_type          TEXT NOT NULL CHECK (trigger_type IN ('MANUAL', 'SCHEDULED')),
  status                TEXT NOT NULL DEFAULT 'QUEUED'
                        CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCESS', 'FAILED', 'MISSED')),
  started_at            TIMESTAMPTZ,
  ended_at              TIMESTAMPTZ,
  target_description    TEXT NOT NULL,
  snapshot_method       TEXT,          -- e.g. 'logical-json-v1'
  snapshot_identifier   TEXT,
  object_key            TEXT,
  size_bytes            BIGINT,
  checksum              TEXT,
  checksum_algorithm    TEXT,
  error_code            TEXT,
  error_message         TEXT,
  actor_user_id         UUID REFERENCES users(id),   -- NULL = SYSTEM
  correlation_id        TEXT NOT NULL,
  retention_deleted_count  INTEGER NOT NULL DEFAULT 0,
  retention_retained_count INTEGER,
  retention_complete    BOOLEAN,
  object_retired_at     TIMESTAMPTZ,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT backup_attempts_ref_unique UNIQUE (organization_id, attempt_reference),
  -- A SUCCESS attempt must name an object and a size; a FAILED one must explain itself;
  -- any terminal state must have an end timestamp. A failed backup can never masquerade
  -- as a success (spec §13.7).
  CONSTRAINT backup_success_requires_object CHECK (
    status <> 'SUCCESS' OR (object_key IS NOT NULL AND size_bytes IS NOT NULL AND size_bytes > 0)),
  CONSTRAINT backup_failure_requires_reason CHECK (
    status <> 'FAILED' OR (error_code IS NOT NULL AND error_message IS NOT NULL)),
  CONSTRAINT backup_terminal_has_end CHECK (
    status NOT IN ('SUCCESS', 'FAILED', 'MISSED') OR ended_at IS NOT NULL),
  CONSTRAINT backup_retired_only_success CHECK (
    object_retired_at IS NULL OR status = 'SUCCESS')
);

CREATE INDEX backup_attempts_org_idx     ON backup_attempts (organization_id, started_at DESC);
CREATE INDEX backup_attempts_success_idx ON backup_attempts (organization_id, started_at DESC)
  WHERE status = 'SUCCESS';
CREATE INDEX backup_attempts_running_idx ON backup_attempts (organization_id) WHERE status IN ('QUEUED', 'RUNNING');
CREATE INDEX backup_attempts_live_objects_idx ON backup_attempts (organization_id, started_at DESC)
  WHERE status = 'SUCCESS' AND object_key IS NOT NULL AND object_retired_at IS NULL;

-- Status may only advance along the attempt lifecycle; evidence fields are immutable
-- once terminal.
CREATE OR REPLACE FUNCTION guard_backup_attempt_update() RETURNS trigger AS $$
BEGIN
  IF OLD.status IN ('SUCCESS', 'FAILED', 'MISSED') AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'SOLVAREN immutability: backup attempt % is terminal as %', OLD.id, OLD.status;
  END IF;
  IF OLD.status = 'SUCCESS' AND (NEW.object_key IS DISTINCT FROM OLD.object_key
      OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
      OR NEW.checksum IS DISTINCT FROM OLD.checksum) THEN
    RAISE EXCEPTION 'SOLVAREN immutability: the artifact evidence on backup attempt % is frozen', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER backup_attempts_guard_update BEFORE UPDATE ON backup_attempts
  FOR EACH ROW EXECUTE FUNCTION guard_backup_attempt_update();
CREATE TRIGGER backup_attempts_no_delete BEFORE DELETE ON backup_attempts
  FOR EACH ROW EXECUTE FUNCTION refuse();

CREATE TRIGGER backup_configurations_updated_at BEFORE UPDATE ON backup_configurations
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------------------
-- Exports and report jobs (spec §12): every export is recorded; reports generate
-- asynchronously as ReportJob rows.
-- ---------------------------------------------------------------------------

CREATE TABLE export_records (
  id                  UUID PRIMARY KEY,
  organization_id     UUID NOT NULL REFERENCES organizations(id),
  export_reference    TEXT NOT NULL,
  export_type         TEXT NOT NULL CHECK (export_type IN (
                        'FAILED_TRANSACTIONS', 'ALL_TRANSACTIONS', 'REPORT')),
  report_family       TEXT,
  requested_by_user_id UUID NOT NULL REFERENCES users(id),
  requested_by_level  TEXT NOT NULL CHECK (requested_by_level IN ('L1', 'L2', 'L3')),
  filter_description  TEXT NOT NULL,
  filter_json         JSONB NOT NULL DEFAULT '{}',
  row_count           INTEGER,
  byte_size           INTEGER,
  status              TEXT NOT NULL DEFAULT 'COMPLETED'
                        CHECK (status IN ('GENERATING', 'COMPLETED', 'FAILED')),
  error_message       TEXT,
  completed_at        TIMESTAMPTZ,
  correlation_id      TEXT NOT NULL,
  requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT export_completed_has_count CHECK (status <> 'COMPLETED' OR row_count IS NOT NULL),
  CONSTRAINT export_failed_has_reason CHECK (status <> 'FAILED' OR error_message IS NOT NULL)
);

CREATE INDEX export_records_org_idx  ON export_records (organization_id, requested_at DESC);
CREATE INDEX export_records_user_idx ON export_records (organization_id, requested_by_user_id, requested_at DESC);

CREATE TRIGGER export_records_no_delete BEFORE DELETE ON export_records
  FOR EACH ROW EXECUTE FUNCTION refuse();

CREATE TABLE report_jobs (
  id                  UUID PRIMARY KEY,
  organization_id     UUID NOT NULL REFERENCES organizations(id),
  family              TEXT NOT NULL,
  requested_by_user_id UUID NOT NULL REFERENCES users(id),
  filters             JSONB NOT NULL DEFAULT '{}',
  status              TEXT NOT NULL DEFAULT 'QUEUED'
                      CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
  row_count           INTEGER,
  object_key          TEXT,            -- large reports are staged to the backup bucket
  csv_inline          TEXT,            -- small reports are returned inline
  error_message       TEXT,
  requested_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at        TIMESTAMPTZ,
  correlation_id      TEXT NOT NULL
);

CREATE INDEX report_jobs_org_idx ON report_jobs (organization_id, requested_at DESC);

-- ---------------------------------------------------------------------------
-- AI interactions (spec §11): advisory-only, proven by constraint.
-- ---------------------------------------------------------------------------

CREATE TABLE ai_interactions (
  id                  UUID PRIMARY KEY,
  organization_id     UUID NOT NULL REFERENCES organizations(id),
  user_id             UUID NOT NULL REFERENCES users(id),
  capability          TEXT NOT NULL CHECK (capability IN (
                        'BATCH_ANALYSIS', 'FAILURE_EXPLANATION', 'EXPENDITURE_ANALYSIS',
                        'EXECUTIVE_BRIEFING', 'OPERATIONAL_ASSISTANT')),
  prompt_summary      TEXT NOT NULL,
  context_digest      TEXT NOT NULL,
  context_row_count   INTEGER NOT NULL DEFAULT 0,
  model               TEXT NOT NULL,
  response_summary    TEXT,
  degraded            BOOLEAN NOT NULL DEFAULT FALSE,
  -- The AI layer can never truthfully claim to have changed payment state. The route
  -- group is read-only; this constraint is the proof that survives an audit.
  caused_state_change BOOLEAN NOT NULL DEFAULT FALSE
                      CONSTRAINT ai_never_mutates_state CHECK (caused_state_change = FALSE),
  latency_ms          INTEGER,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ai_interactions_org_idx ON ai_interactions (organization_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Security events (Zone 7 evidence that is not part of the hash chain — the chain
-- carries the privileged audit trail; security events are high-volume telemetry).
-- ---------------------------------------------------------------------------

CREATE TABLE security_events (
  id                UUID PRIMARY KEY,
  organization_id   UUID REFERENCES organizations(id),   -- NULL = platform-level
  user_id           UUID REFERENCES users(id),
  event_type        TEXT NOT NULL,
  severity          TEXT NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
  description       TEXT NOT NULL,
  ip                INET,
  user_agent        TEXT,
  detail            JSONB NOT NULL DEFAULT '{}',
  acknowledged_at   TIMESTAMPTZ,
  acknowledged_by_user_id UUID REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX security_events_org_idx ON security_events (organization_id, created_at DESC);
CREATE INDEX security_events_open_idx ON security_events (organization_id, severity, created_at DESC)
  WHERE acknowledged_at IS NULL AND severity IN ('WARNING', 'CRITICAL');
CREATE INDEX security_events_type_idx ON security_events (event_type, created_at DESC);

-- ---------------------------------------------------------------------------
-- Notifications (spec §13.7 "backup failures produce visible operational warnings";
-- generalised into an outbox with optional webhook/email delivery channels).
-- ---------------------------------------------------------------------------

CREATE TABLE notification_channels (
  id                  UUID PRIMARY KEY,
  organization_id     UUID NOT NULL REFERENCES organizations(id),
  kind                TEXT NOT NULL CHECK (kind IN ('WEBHOOK', 'EMAIL')),
  target_secret_ref   TEXT NOT NULL,          -- encrypted webhook URL / email address
  target_display      TEXT NOT NULL,          -- masked display form
  minimum_severity    TEXT NOT NULL DEFAULT 'WARNING' CHECK (minimum_severity IN ('INFO', 'WARNING', 'CRITICAL')),
  enabled             BOOLEAN NOT NULL DEFAULT TRUE,
  last_delivery_at    TIMESTAMPTZ,
  last_delivery_ok    BOOLEAN,
  last_error          TEXT,
  created_by_user_id  UUID NOT NULL REFERENCES users(id),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notifications (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  severity          TEXT NOT NULL CHECK (severity IN ('INFO', 'WARNING', 'CRITICAL')),
  title             TEXT NOT NULL,
  body              TEXT NOT NULL,
  link_path         TEXT,
  read_at           TIMESTAMPTZ,
  read_by_user_id   UUID REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX notifications_org_idx ON notifications (organization_id, created_at DESC)
  WHERE read_at IS NULL;

CREATE TABLE notification_deliveries (
  id                UUID PRIMARY KEY,
  notification_id   UUID NOT NULL REFERENCES notifications(id),
  channel_id        UUID NOT NULL REFERENCES notification_channels(id),
  status            TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED')),
  attempted_at      TIMESTAMPTZ,
  error             TEXT
);

CREATE INDEX notification_deliveries_pending_idx ON notification_deliveries (channel_id)
  WHERE status = 'PENDING';
