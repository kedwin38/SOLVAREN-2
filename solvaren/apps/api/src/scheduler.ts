/**
 * Scheduled work (spec §10, §13.4).
 *
 * Five jobs on fixed intervals, every one guarded by a PostgreSQL advisory lock:
 *
 *   every 30 seconds — template scheduler: materialize due recurring batches
 *   every 5 minutes  — reconciliation and status sweeps
 *   every minute     — backup schedule check (next_run_at based, missed-run detection)
 *   every 10 minutes — notification outbox drain
 *   daily at 02:00   — housekeeping: expire stale ceremonies and sessions
 *
 * **Every run takes an advisory lock first.** A Node process on Railway has no platform
 * guarantee that a timer fires once per schedule across replicas; the moment the service
 * scales to two instances, every timer fires in both. `pg_try_advisory_lock` is the
 * cheapest correct answer: whichever replica gets the lock runs the job, the others
 * return immediately, and a replica that dies mid-job releases the lock when its
 * connection drops.
 *
 * Backup schedules are stored as the organisation's intended local time + timezone and
 * translated to UTC at computation time (spec §13.4); execution minutes are not treated
 * as financial deadlines.
 */

import { correlationId, nextRun } from '@solvaren/core';
import type { Sql } from './db/client.js';
import type { Env } from './env.js';

const THIRTY_SECONDS_MS = 30 * 1000;
const ONE_MINUTE_MS = 60 * 1000;
const FIVE_MINUTES_MS = 5 * 60 * 1000;
const TEN_MINUTES_MS = 10 * 60 * 1000;
/** Checked often; the daily job itself only runs once the UTC day has turned past 02:00. */
const DAILY_CHECK_MS = 10 * 60 * 1000;

/**
 * Advisory lock keys. Arbitrary but fixed constants in a range a text hash is
 * vanishingly unlikely to produce, each distinct so two jobs never block each other.
 */
const LOCK_KEYS = {
  templates: 947_200_001,
  reconciliation: 947_200_002,
  backups: 947_200_003,
  housekeeping: 947_200_004,
  notifications: 947_200_005,
} as const;

export interface SchedulerHandle {
  stop(): Promise<void>;
}

/**
 * Start the timers. Each job runs once at startup too, after a short stagger: a deploy
 * landing between two ticks should not leave in-flight payments unreconciled for the
 * remainder of the interval.
 */
export function startScheduler(env: Env): SchedulerHandle {
  const timers: NodeJS.Timeout[] = [];
  let running = true;
  let active: Promise<unknown> = Promise.resolve();

  const schedule = (
    name: keyof typeof LOCK_KEYS,
    intervalMs: number,
    job: (env: Env, correlation: string) => Promise<void>,
    shouldRun?: (sql: Sql) => Promise<boolean>,
  ) => {
    const tick = () => {
      if (!running) return;
      active = active
        .then(() => runLocked(env, name, job, shouldRun))
        .catch((error) => {
          console.error(
            JSON.stringify({
              level: 'error',
              message: 'Scheduled job failed',
              job: name,
              error: error instanceof Error ? error.message : String(error),
            }),
          );
        });
    };
    timers.push(setInterval(tick, intervalMs));
    // Stagger the startup runs so five jobs do not contend for the pool at once.
    timers.push(setTimeout(tick, 5000 + timers.length * 2000));
  };

  schedule('templates', THIRTY_SECONDS_MS, runTemplateScheduler);
  schedule('reconciliation', FIVE_MINUTES_MS, runReconciliationSweep);
  schedule('backups', ONE_MINUTE_MS, runBackupSchedules);
  schedule('notifications', TEN_MINUTES_MS, runNotificationSweep);
  schedule('housekeeping', DAILY_CHECK_MS, runHousekeeping, dailyWindowHasNotRunToday);

  console.log(
    JSON.stringify({
      level: 'info',
      message: 'Scheduler started',
      jobs: Object.keys(LOCK_KEYS),
    }),
  );

  return {
    async stop() {
      running = false;
      for (const timer of timers) clearTimeout(timer);
      for (const timer of timers) clearInterval(timer);
      // Let whatever is mid-flight finish rather than tearing down its transaction.
      await active.catch(() => {});
      console.log(JSON.stringify({ level: 'info', message: 'Scheduler stopped' }));
    },
  };
}

/** Run a job while holding its session-scoped advisory lock. */
async function runLocked(
  env: Env,
  name: keyof typeof LOCK_KEYS,
  job: (env: Env, correlation: string) => Promise<void>,
  shouldRun?: (sql: Sql) => Promise<boolean>,
): Promise<void> {
  const key = LOCK_KEYS[name];
  const reserved = await env.sql.reserve();

  try {
    const locked = await reserved<{ acquired: boolean }[]>`
      SELECT pg_try_advisory_lock(${key}) AS acquired
    `;
    if (!locked[0]?.acquired) {
      // Another replica is running it. Not an error.
      return;
    }

    try {
      if (shouldRun && !(await shouldRun(reserved as unknown as Sql))) return;

      const correlation = correlationId();
      const started = Date.now();
      await job(env, correlation);
      console.log(
        JSON.stringify({
          level: 'info',
          message: 'Scheduled job complete',
          job: name,
          durationMs: Date.now() - started,
          correlationId: correlation,
        }),
      );
    } finally {
      await reserved`SELECT pg_advisory_unlock(${key})`;
    }
  } finally {
    reserved.release();
  }
}

/**
 * Gate the daily job to once per UTC day, after 02:00.
 *
 * The marker is a row rather than process state so it survives a restart and is shared
 * across replicas — the advisory lock stops two replicas running it *simultaneously*,
 * and the marker stops a restarted replica running it *again*.
 */
async function dailyWindowHasNotRunToday(sql: Sql): Promise<boolean> {
  const now = new Date();
  if (now.getUTCHours() < 2) return false;

  const today = now.toISOString().slice(0, 10);
  const rows = await sql<{ claimed: boolean }[]>`
    INSERT INTO scheduled_job_runs (job_name, ran_on)
    VALUES ('housekeeping', ${today}::date)
    ON CONFLICT (job_name, ran_on) DO NOTHING
    RETURNING TRUE AS claimed
  `;
  return rows.length > 0;
}

// ---------------------------------------------------------------------------
// The jobs
// ---------------------------------------------------------------------------

/**
 * Template scheduler: materialize recurring batches whose next_run_at has arrived.
 *
 * A materialized template becomes an ordinary DRAFT batch owned by the system user's
 * organisation — it then travels the same L1 submit → L2 approve → L3 authorize path as
 * any hand-made batch. The scheduler never releases money; it only prepares work.
 */
export async function runTemplateScheduler(env: Env, correlation: string): Promise<void> {
  const due = await env.sql<
    {
      id: string;
      organization_id: string;
      name: string;
      purpose: string;
      payment_period_pattern: string | null;
      department_id: string | null;
      schedule_cron: string;
    }[]
  >`
    SELECT id, organization_id, name, purpose, payment_period_pattern, department_id, schedule_cron
      FROM batch_templates
     WHERE schedule_enabled = TRUE
       AND (next_run_at IS NULL OR next_run_at <= now())
       FOR UPDATE SKIP LOCKED
  `;

  for (const template of due) {
    try {
      await env.sql.begin(async (tx) => {
        // Materialize: copy template items into a fresh DRAFT batch.
        const batchReference = `SLV-AUTO-${Date.now().toString(36).toUpperCase()}`;
        const batch = await tx<{ id: string }[]>`
          INSERT INTO payment_batches (
            organization_id, batch_reference, purpose, payment_period, department_id,
            state, created_by_user_id
          ) VALUES (
            ${template.organization_id}, ${batchReference},
            ${`${template.purpose} (from template: ${template.name})`},
            ${template.payment_period_pattern}, ${template.department_id},
            'DRAFT',
            (SELECT id FROM users WHERE organization_id = ${template.organization_id} AND authority_level = 'L1' ORDER BY created_at LIMIT 1)
          )
          RETURNING id
        `;
        const batchId = batch[0]!.id;

        await tx`
          INSERT INTO payment_instructions (
            organization_id, batch_id, recipient_id, recipient_name_snapshot,
            msisdn_snapshot, department_id, amount_cents, remarks
          )
          SELECT ${template.organization_id}, ${batchId}, bti.recipient_id,
                 r.full_name, r.msisdn,
                 (SELECT department_id FROM recipients WHERE id = bti.recipient_id),
                 bti.amount_cents, bti.remarks
            FROM batch_template_items bti
            JOIN recipients r ON r.id = bti.recipient_id
           WHERE bti.template_id = ${template.id}
             AND r.status = 'ACTIVE'
        `;

        // Advance the schedule with the cron's own arithmetic.
        const upcoming = safeNextRun(template.schedule_cron);
        await tx`
          UPDATE batch_templates
             SET last_materialized_at = now(), next_run_at = ${upcoming}
           WHERE id = ${template.id}
        `;

        await tx`
          INSERT INTO notifications (organization_id, severity, title, body, link_path)
          VALUES (
            ${template.organization_id}, 'INFO',
            ${`Batch template "${template.name}" materialized`},
            ${`A draft batch was created from the recurring template and is ready for validation and submission.`},
            ${'/batches'}
          )
        `;

        console.info(
          JSON.stringify({
            level: 'info',
            message: 'Batch template materialized',
            templateId: template.id,
            batchId,
            nextRunAt: upcoming?.toISOString() ?? null,
            correlationId: correlation,
          }),
        );
      });
    } catch (err) {
      console.error(
        JSON.stringify({
          level: 'error',
          message: 'Template materialization failed',
          templateId: template.id,
          error: err instanceof Error ? err.message : String(err),
          correlationId: correlation,
        }),
      );
      // Back the template off by an hour rather than spinning on it every 30 seconds.
      await env.sql`
        UPDATE batch_templates SET next_run_at = now() + interval '1 hour'
         WHERE id = ${template.id} AND next_run_at <= now()
      `;
    }
  }
}

/** Enqueue a reconciliation sweep per organisation with enabled integration and stuck work. */
export async function runReconciliationSweep(env: Env, correlation: string): Promise<void> {
  await env.sql.begin(async (sql) => {
    const organizations = await sql<{ organization_id: string }[]>`
      SELECT DISTINCT t.organization_id
        FROM transactions t
        JOIN daraja_configurations dc
          ON dc.organization_id = t.organization_id AND dc.status = 'ENABLED'
       WHERE t.status IN ('SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'TIMEOUT', 'RECONCILING')
         AND t.submitted_at < now() - interval '10 minutes'
    `;

    for (const org of organizations) {
      await sql`
        INSERT INTO job_queue (queue, priority, body, organization_id, correlation_id, max_attempts, run_after)
        VALUES (
          'reconciliation', 100,
          ${sql.json({ type: 'SWEEP_ORGANIZATION', organizationId: org.organization_id, correlationId: correlation })},
          ${org.organization_id}, ${correlation}, 3, now()
        )
        ON CONFLICT DO NOTHING
      `;
    }

    if (organizations.length > 0) {
      console.info(
        JSON.stringify({
          level: 'info',
          message: 'Reconciliation sweep dispatched',
          organizations: organizations.length,
          correlationId: correlation,
        }),
      );
    }
  });
}

/**
 * Fire due backup schedules.
 *
 * A schedule whose window has passed by more than two hours records a MISSED attempt
 * before the next run is queued (spec §13.4: "a missed execution must be observable
 * rather than silently disappearing"). next_scheduled_run_at is computed from the local
 * wall-clock time + timezone via the cron engine, not a fixed +1 day.
 */
export async function runBackupSchedules(env: Env, correlation: string): Promise<void> {
  const due = await env.sql<
    { organization_id: string; schedule_local_time: string; schedule_timezone: string; last_scheduled_run_at: string | null; next_scheduled_run_at: string | null }[]
  >`
    SELECT organization_id, schedule_local_time, schedule_timezone,
           last_scheduled_run_at, next_scheduled_run_at
      FROM backup_configurations
     WHERE schedule_enabled = TRUE
       AND suspended_at IS NULL
       AND (next_scheduled_run_at IS NULL OR next_scheduled_run_at <= now())
       FOR UPDATE SKIP LOCKED
  `;

  for (const schedule of due) {
    // Record the miss before queueing the new run, so the history shows both.
    if (schedule.next_scheduled_run_at) {
      const overdueHours =
        (Date.now() - new Date(schedule.next_scheduled_run_at).getTime()) / 3_600_000;
      if (overdueHours > 2) {
        await env.sql`
          INSERT INTO backup_attempts (
            organization_id, attempt_reference, trigger_type, status, started_at, ended_at,
            target_description, error_code, error_message, correlation_id
          ) VALUES (
            ${schedule.organization_id},
            ${'BAK-MISSED-' + new Date(schedule.next_scheduled_run_at).toISOString().slice(0, 16)},
            'SCHEDULED', 'MISSED', ${schedule.next_scheduled_run_at}, now(),
            ${'scheduled window'}, 'SCHEDULE_MISSED',
            ${`The backup scheduled for ${schedule.next_scheduled_run_at} did not run and is ${Math.floor(overdueHours)} hours overdue.`},
            ${correlation}
          )
          ON CONFLICT (organization_id, attempt_reference) DO NOTHING
        `;
      }
    }

    await env.sql`
      INSERT INTO job_queue (queue, priority, body, organization_id, correlation_id, max_attempts, run_after)
      VALUES (
        'backups', 100,
        ${env.sql.json({ type: 'RUN_BACKUP', organizationId: schedule.organization_id, trigger: 'SCHEDULED', correlationId: correlation })},
        ${schedule.organization_id}, ${correlation}, 2, now()
      )
      ON CONFLICT DO NOTHING
    `;

    // Next window from the cron engine (daily at the local time).
    const upcoming = nextDailyUtc(schedule.schedule_local_time);
    await env.sql`
      UPDATE backup_configurations
         SET last_scheduled_run_at = now(), next_scheduled_run_at = ${upcoming}
       WHERE organization_id = ${schedule.organization_id}
    `;
  }
}

/** Drain the notification outbox for every organisation with enabled channels. */
export async function runNotificationSweep(env: Env, correlation: string): Promise<void> {
  const orgs = await env.sql<{ organization_id: string }[]>`
    SELECT DISTINCT organization_id FROM notification_channels WHERE enabled = TRUE
  `;
  for (const org of orgs) {
    await env.sql`
      INSERT INTO job_queue (queue, priority, body, organization_id, correlation_id, max_attempts, run_after)
      VALUES (
        'notifications', 100,
        ${env.sql.json({ type: 'DELIVER_NOTIFICATIONS', organizationId: org.organization_id, correlationId: correlation })},
        ${org.organization_id}, ${correlation}, 5, now()
      )
      ON CONFLICT DO NOTHING
    `;
  }
}

/** Daily housekeeping: expire stale ceremonies and sessions. Never touches ledger rows. */
export async function runHousekeeping(env: Env, correlation: string): Promise<void> {
  await env.sql.begin(async (sql) => {
    // An authorization ceremony left open past its expiry blocks the partial unique
    // index and prevents a new one from being started.
    const abandoned = await sql<{ id: string }[]>`
      UPDATE authorization_challenges
         SET abandoned_at = now()
       WHERE consumed_at IS NULL AND abandoned_at IS NULL AND expires_at < now() - interval '1 hour'
      RETURNING id
    `;
    if (abandoned.length > 0) {
      await sql`
        UPDATE payment_batches SET state = 'L3_READY'
         WHERE state = 'AUTHORIZATION_PENDING'
           AND id IN (
             SELECT batch_id FROM authorization_challenges
              WHERE id = ANY(${sql.array(abandoned.map((a) => a.id))})
           )
      `;
    }

    await sql`
      UPDATE sessions SET revoked_at = now(), revocation_reason = 'Expired'
       WHERE revoked_at IS NULL AND expires_at < now() - interval '1 day'
    `;

    console.info(
      JSON.stringify({
        level: 'info',
        message: 'Housekeeping complete',
        expiredCeremonies: abandoned.length,
        correlationId: correlation,
      }),
    );
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeNextRun(cron: string): Date | null {
  try {
    return nextRun(cron);
  } catch {
    // A template with an impossible cron must not wedge the scheduler.
    return new Date(Date.now() + 24 * 60 * 60 * 1000);
  }
}

/**
 * The next UTC instant of a local wall-clock time ("HH:MM") in Africa/Nairobi (UTC+3,
 * no DST). Kenya observes no daylight saving, so the fixed offset is exact.
 */
function nextDailyUtc(localTime: string): Date {
  const [h, m] = localTime.split(':').map(Number);
  const now = new Date();
  const eatNow = new Date(now.getTime() + 3 * 60 * 60 * 1000);
  let candidate = Date.UTC(
    eatNow.getUTCFullYear(), eatNow.getUTCMonth(), eatNow.getUTCDate(),
    h ?? 2, m ?? 0, 0,
  ) - 3 * 60 * 60 * 1000;
  if (candidate <= now.getTime()) {
    candidate += 24 * 60 * 60 * 1000;
  }
  return new Date(candidate);
}
