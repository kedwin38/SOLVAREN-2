-- SOLVAREN migration 0007 — The durable job queue, rate-control buckets and the
-- scheduler's run markers.
--
-- The queue is PostgreSQL-backed on purpose. Cloudflare Queues and Redis streams cannot
-- offer the property this platform's correctness depends on: enqueueing a job in the
-- SAME transaction as the state change that justified it (spec §23: "do not acknowledge
-- durable payment work before persistence"). A batch release commits its idempotency
-- claims AND its execution jobs atomically, or neither commits at all.
--
-- Redis remains available for ephemeral coordination (rate control acceleration, cache)
-- but the queue's system of record is here.

CREATE TABLE job_queue (
  id                UUID PRIMARY KEY,
  queue             TEXT NOT NULL CHECK (queue IN ('payments', 'callbacks', 'reconciliation', 'backups', 'reports', 'notifications')),
  priority          INTEGER NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 100),  -- 1 = most urgent
  body              JSONB NOT NULL,
  organization_id   UUID REFERENCES organizations(id),
  correlation_id    TEXT,
  status            TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'IN_FLIGHT', 'SUCCEEDED', 'DEAD_LETTERED')),
  attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts      INTEGER NOT NULL CHECK (max_attempts >= 1),
  run_after         TIMESTAMPTZ NOT NULL DEFAULT now(),
  claimed_at        TIMESTAMPTZ,
  claimed_by        TEXT,
  claimed_until     TIMESTAMPTZ,
  last_error        TEXT,
  completed_at      TIMESTAMPTZ,
  dead_lettered_at  TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (status <> 'SUCCEEDED' OR completed_at IS NOT NULL),
  CHECK (status <> 'DEAD_LETTERED' OR dead_lettered_at IS NOT NULL),
  CHECK (status <> 'DEAD_LETTERED' OR (last_error IS NOT NULL AND last_error <> '')),
  CHECK (status <> 'IN_FLIGHT' OR (claimed_until IS NOT NULL AND claimed_by IS NOT NULL))
);

-- Priority ordering: urgent (1) before routine (100), then oldest first.
CREATE INDEX job_queue_claimable_idx
  ON job_queue (queue, priority, run_after, id)
  WHERE status = 'PENDING';
CREATE INDEX job_queue_expired_leases_idx
  ON job_queue (claimed_until)
  WHERE status = 'IN_FLIGHT';
CREATE INDEX job_queue_organization_idx ON job_queue (organization_id, created_at DESC);
CREATE INDEX job_queue_correlation_idx  ON job_queue (correlation_id);
CREATE INDEX job_queue_dead_letter_idx
  ON job_queue (queue, dead_lettered_at DESC)
  WHERE status = 'DEAD_LETTERED';

-- A payment instruction may have at most one live job. A duplicate release attempt is a
-- no-op here rather than an error: the first job is queued and will run.
CREATE UNIQUE INDEX job_queue_one_live_payment_per_instruction
  ON job_queue (jsonb_extract_path_text(body, 'instructionId'))
  WHERE status IN ('PENDING', 'IN_FLIGHT')
    AND queue = 'payments'
    AND jsonb_extract_path_text(body, 'type') = 'EXECUTE_INSTRUCTION';

-- Jobs may not be edited into success or deleted once durable: the queue is evidence of
-- what the system intended to do.
CREATE OR REPLACE FUNCTION guard_job_update() RETURNS trigger AS $$
BEGIN
  IF OLD.status = 'SUCCEEDED' AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'SOLVAREN immutability: job % already succeeded', OLD.id;
  END IF;
  IF OLD.status = 'DEAD_LETTERED' AND NEW.status <> OLD.status THEN
    RAISE EXCEPTION 'SOLVAREN immutability: job % is dead-lettered evidence', OLD.id;
  END IF;
  IF NEW.body::text IS DISTINCT FROM OLD.body::text THEN
    RAISE EXCEPTION 'SOLVAREN immutability: the body of job % cannot change after enqueue', OLD.id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER job_queue_guard_update BEFORE UPDATE ON job_queue
  FOR EACH ROW EXECUTE FUNCTION guard_job_update();
CREATE TRIGGER job_queue_no_delete BEFORE DELETE ON job_queue
  FOR EACH ROW EXECUTE FUNCTION refuse();

-- ---------------------------------------------------------------------------
-- Rate control: a token bucket per organization, mutated under row lock so it is
-- correct across however many replicas are running (spec §10).
-- ---------------------------------------------------------------------------

CREATE TABLE rate_limit_buckets (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id),
  tokens          DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
  last_refill_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Generic keyed buckets for login/export abuse control (key is e.g. 'login:1.2.3.4').
CREATE TABLE rate_limit_keys (
  bucket_key    TEXT PRIMARY KEY,
  tokens        DOUBLE PRECISION NOT NULL CHECK (tokens >= 0),
  last_refill_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Scheduler run markers: persist "this job already ran today" across restarts and
-- replicas (an advisory lock stops two replicas running simultaneously; this marker
-- stops a restarted replica running it twice).
-- ---------------------------------------------------------------------------

CREATE TABLE scheduled_job_runs (
  job_name  TEXT NOT NULL,
  ran_on    DATE NOT NULL,
  ran_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (job_name, ran_on)
);
