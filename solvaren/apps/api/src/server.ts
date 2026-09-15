/**
 * SOLVAREN API — server entry point.
 *
 * One process may serve three roles:
 *   HTTP      — the API, via @hono/node-server
 *   workers   — payment execution, callbacks, reconciliation, backups, reports, notifications
 *   scheduler — template materialization, reconciliation sweeps, backup schedules, housekeeping
 *
 * Keeping them together means they share the same domain code, state machines and audit
 * writer; a reconciliation sweep cannot drift from the rules the API enforces. They can
 * still be split for deployment (spec §17.1): `RUN_WORKERS=false` gives a web-only
 * replica; `RUN_WORKERS=true RUN_SCHEDULER=true` with no public port gives the private
 * worker service.
 *
 * Startup order is deliberate: validate configuration, prove the database is reachable
 * and migrated, and only then bind the port. A process that accepts a payment request
 * before confirming it can write to the ledger is a process that loses payments.
 */

import { serve } from '@hono/node-server';
import { app } from './index.js';
import { loadConfigOrExit } from './config.js';
import { createPool, type Sql } from './db/client.js';
import { PostgresJobQueue } from './queue/queue.js';
import { startWorkers, type WorkerHandle } from './queue/runner.js';
import { startScheduler, type SchedulerHandle } from './scheduler.js';
import { S3ObjectStore } from '@solvaren/storage';
import { PostgresRateLimiter } from './rate-limiter.js';
import { S3SecretStore, FileSecretStore, type SecretStore } from './services/secret-store.js';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { Env } from './env.js';

const config = loadConfigOrExit();

const pool = createPool(config.DATABASE_URL);

// Production secrets live in the S3 bucket's secrets/ prefix (envelope-encrypted under
// SECRET_ENCRYPTION_KEY). Local development and the integration suite use the file
// store — same envelopes, no cloud dependency.
let secrets: SecretStore;
if (config.ENVIRONMENT === 'development' && !config.S3_ENDPOINT) {
  const dir = join(process.cwd(), '.local-secrets');
  mkdirSync(dir, { recursive: true });
  secrets = new FileSecretStore(dir, config.SECRET_ENCRYPTION_KEY);
} else {
  const objects = new S3ObjectStore({
    endpoint: config.S3_ENDPOINT,
    region: config.S3_REGION,
    bucket: config.S3_BUCKET,
    accessKeyId: config.S3_ACCESS_KEY_ID,
    secretAccessKey: config.S3_SECRET_ACCESS_KEY,
    forcePathStyle: config.S3_FORCE_PATH_STYLE,
  });
  secrets = new S3SecretStore(objects, config.SECRET_ENCRYPTION_KEY);
}

const env: Env = {
  sql: pool,
  queue: new PostgresJobQueue(pool),
  rateLimiter: new PostgresRateLimiter(pool),
  objects: new S3ObjectStore({
    endpoint: config.S3_ENDPOINT,
    region: config.S3_REGION,
    bucket: config.S3_BUCKET,
    accessKeyId: config.S3_ACCESS_KEY_ID,
    secretAccessKey: config.S3_SECRET_ACCESS_KEY,
    forcePathStyle: config.S3_FORCE_PATH_STYLE,
  }),
  secrets,

  SESSION_SIGNING_KEY: config.SESSION_SIGNING_KEY,
  SECRET_ENCRYPTION_KEY: config.SECRET_ENCRYPTION_KEY,
  ...(config.CALLBACK_SHARED_SECRET ? { CALLBACK_SHARED_SECRET: config.CALLBACK_SHARED_SECRET } : {}),
  ...(config.AI_API_KEY ? { AI_API_KEY: config.AI_API_KEY } : {}),

  ENVIRONMENT: config.ENVIRONMENT,
  APP_ORIGIN: config.APP_ORIGIN,
  API_BASE_URL: config.API_BASE_URL,
  WEBAUTHN_RP_ID: config.WEBAUTHN_RP_ID,
  WEBAUTHN_RP_NAME: config.WEBAUTHN_RP_NAME,
  ...(config.AI_MODEL ? { AI_MODEL: config.AI_MODEL } : {}),
};

/**
 * Refuse to serve traffic against a database that is unreachable or not migrated.
 *
 * The schema check is not ceremony. Every immutability guarantee this system claims —
 * the append-only audit log, the refusal to record a SUCCESS without a receipt, the ban
 * on self-approval — is a trigger or a constraint in the database. A process running
 * against an unmigrated database would accept payments with none of them in force, and
 * would look completely healthy while doing it.
 */
async function verifyDatabase(sql: Sql): Promise<void> {
  await sql`SELECT 1`;

  const required = [
    'organizations',
    'users',
    'payment_batches',
    'payment_instructions',
    'transactions',
    'audit_events',
    'idempotency_claims',
    'job_queue',
    'rate_limit_buckets',
    'scheduled_job_runs',
    'permission_overrides',
    'daraja_configurations',
    'backup_attempts',
    'report_jobs',
    'notifications',
  ];

  const present = await sql<{ table_name: string }[]>`
    SELECT table_name
      FROM information_schema.tables
     WHERE table_schema = 'public'
       AND table_name = ANY(
         SELECT jsonb_array_elements_text(${sql.json(required)}::jsonb)
       )
  `;

  const found = new Set(present.map((row) => row.table_name));
  const missing = required.filter((table) => !found.has(table));
  if (missing.length > 0) {
    throw new Error(
      `The database is missing ${missing.length} required table(s): ${missing.join(', ')}. ` +
        'Run the migrations (pnpm db:migrate) before starting the server.',
    );
  }

  // The audit immutability trigger is the single guarantee most worth confirming: without
  // it the ledger is editable and nothing else in the system would notice.
  const triggers = await sql<{ tgname: string }[]>`
    SELECT tgname FROM pg_trigger
     WHERE NOT tgisinternal AND tgname = 'audit_events_no_update'
  `;
  if (triggers.length === 0) {
    throw new Error(
      'The audit immutability trigger (audit_events_no_update) is not installed. ' +
        'This database does not protect its audit log; refusing to start.',
    );
  }
}

let workers: WorkerHandle | null = null;
let scheduler: SchedulerHandle | null = null;
let server: ReturnType<typeof serve> | null = null;

async function main(): Promise<void> {
  try {
    await verifyDatabase(pool);
  } catch (error) {
    console.error('');
    console.error('  SOLVAREN cannot start: the database is not usable.');
    console.error(`  ${error instanceof Error ? error.message : String(error)}`);
    console.error('');
    await pool.end({ timeout: 5 }).catch(() => {});
    process.exit(1);
  }

  if (config.RUN_WORKERS) workers = startWorkers(env);
  if (config.RUN_SCHEDULER) scheduler = startScheduler(env);

  server = serve({ fetch: (request) => app.fetch(request, env), port: config.PORT }, (info) => {
    console.log(
      JSON.stringify({
        level: 'info',
        message: 'SOLVAREN API listening',
        port: info.port,
        environment: config.ENVIRONMENT,
        workers: config.RUN_WORKERS,
        scheduler: config.RUN_SCHEDULER,
      }),
    );
  });
}

/**
 * Graceful shutdown.
 *
 * Railway sends SIGTERM and waits before SIGKILL. The order matters: stop accepting new
 * requests, let in-flight queue work finish, then close the pool. A payment executor cut
 * off mid-submission leaves a committed idempotency claim and no record of the
 * provider's answer — recoverable, because reconciliation is built for exactly that,
 * but an avoidable on-call page.
 */
let shuttingDown = false;
async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ level: 'info', message: 'Shutting down', signal }));

  const deadline = setTimeout(() => {
    console.error(
      JSON.stringify({ level: 'error', message: 'Shutdown timed out; exiting immediately' }),
    );
    process.exit(1);
  }, 25_000);
  // Do not let the timer itself hold the event loop open once shutdown finishes early.
  deadline.unref();

  try {
    server?.close();
    await Promise.allSettled([workers?.stop(), scheduler?.stop()]);
    await pool.end({ timeout: 10 });
    console.log(JSON.stringify({ level: 'info', message: 'Shutdown complete' }));
    process.exit(0);
  } catch (error) {
    console.error(
      JSON.stringify({
        level: 'error',
        message: 'Shutdown failed',
        error: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exit(1);
  }
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

// An unhandled rejection in a payment path must not be swallowed. Log it and let the
// platform restart the process rather than continuing in an unknown state.
process.on('unhandledRejection', (reason) => {
  console.error(
    JSON.stringify({
      level: 'error',
      message: 'Unhandled promise rejection',
      reason: reason instanceof Error ? `${reason.name}: ${reason.message}` : String(reason),
    }),
  );
});

void main();
