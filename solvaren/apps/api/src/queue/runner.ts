/**
 * Queue worker runner.
 *
 * One polling loop per queue, all inside the same process (a deployment may split them:
 * `RUN_WORKERS=true` on a private worker service with no public port). The six consumers
 * have very different shapes — a backup snapshot holds a job for minutes while a
 * callback takes milliseconds — and a single shared loop would let the slow one starve
 * the fast ones.
 *
 * Polling rather than LISTEN/NOTIFY. A notification is delivered only to sessions
 * connected *at the time it fires*, so a worker that is restarting misses it entirely
 * and the job then waits for whatever fallback poll exists anyway. Since correctness
 * requires the poll regardless, NOTIFY buys lower latency at the cost of a second
 * delivery path to reason about. A one-second poll on an indexed partial index is
 * cheap, and its latency is invisible next to an M-PESA round trip.
 */

import { correlationId } from '@solvaren/core';
import type { Sql } from '../db/client.js';
import type { Env, QueueName } from '../env.js';
import { handlePaymentBatch } from '../queues/payment-executor.js';
import { handleCallbackBatch } from '../queues/callback-processor.js';
import { handleReconciliationBatch } from '../queues/reconciliation-worker.js';
import { handleBackupBatch } from '../queues/backup-worker.js';
import { handleReportBatch } from '../queues/report-worker.js';
import { handleNotificationBatch } from '../queues/notification-worker.js';
import {
  claimBatch,
  settleBatch,
  recoverExpiredLeases,
  workerIdentity,
  QUEUE_POLICIES,
  type ClaimedBatch,
} from './queue.js';

/** How long to wait before polling again when the last poll found nothing. */
const IDLE_POLL_MS = 1000;
/** How long to wait after an unexpected error, so a broken dependency is not hammered. */
const ERROR_BACKOFF_MS = 5000;
/** How often to return jobs whose worker died holding them. */
const LEASE_RECOVERY_INTERVAL_MS = 30_000;

type Consumer = (batch: ClaimedBatch<never>, env: Env) => Promise<void>;

/**
 * Dispatch table. The casts are confined to this one object: each consumer is strongly
 * typed against its own message type; the runner is generic over all six, and this is
 * the single seam where those two facts are reconciled.
 */
const CONSUMERS: Record<QueueName, Consumer> = {
  payments: handlePaymentBatch,
  callbacks: handleCallbackBatch,
  reconciliation: handleReconciliationBatch,
  backups: handleBackupBatch,
  reports: handleReportBatch,
  notifications: handleNotificationBatch,
};

export interface WorkerHandle {
  /** Stop polling and wait for in-flight work to finish. */
  stop(): Promise<void>;
}

/**
 * Start one polling loop per queue, plus the lease recovery timer.
 *
 * `stop()` lets the current batch finish rather than cutting it off: a payment executor
 * interrupted mid-submission leaves a claim committed and no record of the provider's
 * answer — recoverable by reconciliation, but an avoidable on-call page.
 */
export function startWorkers(env: Env): WorkerHandle {
  const workerId = workerIdentity();
  let running = true;
  const settled: Promise<void>[] = [];

  const queues = Object.keys(CONSUMERS) as QueueName[];

  for (const queue of queues) {
    settled.push(runQueueLoop(queue, env, workerId, () => running));
  }
  settled.push(runLeaseRecoveryLoop(env.sql, () => running));

  console.log(
    JSON.stringify({
      level: 'info',
      message: 'Queue workers started',
      workerId,
      queues,
    }),
  );

  return {
    async stop() {
      running = false;
      await Promise.allSettled(settled);
      console.log(JSON.stringify({ level: 'info', message: 'Queue workers stopped', workerId }));
    },
  };
}

async function runQueueLoop(
  queue: QueueName,
  env: Env,
  workerId: string,
  isRunning: () => boolean,
): Promise<void> {
  const policy = QUEUE_POLICIES[queue];
  const consumer = CONSUMERS[queue];

  while (isRunning()) {
    try {
      const batch = await claimBatch<never>(env.sql, queue, workerId, policy);

      if (batch.messages.length === 0) {
        await sleep(IDLE_POLL_MS, isRunning);
        continue;
      }

      let consumerError: unknown;
      try {
        await consumer(batch, env);
      } catch (error) {
        // A consumer that threw has not dispositioned its remaining messages. Those
        // default to retry in settleBatch — the safe direction.
        consumerError = error;
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Queue consumer threw',
            queue,
            error: error instanceof Error ? error.message : String(error),
          }),
        );
      }

      // Settling is not optional: a batch left unsettled stays IN_FLIGHT until its lease
      // expires, which delays every job in it by the visibility timeout. If settling
      // itself fails, lease recovery is the backstop.
      await settleBatch(env.sql, batch, policy, consumerError);
    } catch (error) {
      console.error(
        JSON.stringify({
          level: 'error',
          message: 'Queue loop error',
          queue,
          error: error instanceof Error ? error.message : String(error),
        }),
      );
      await sleep(ERROR_BACKOFF_MS, isRunning);
    }
  }
}

async function runLeaseRecoveryLoop(sql: Sql, isRunning: () => boolean): Promise<void> {
  while (isRunning()) {
    await sleep(LEASE_RECOVERY_INTERVAL_MS, isRunning);
    if (!isRunning()) return;
    try {
      const recovered = await recoverExpiredLeases(sql);
      if (recovered > 0) {
        console.warn(
          JSON.stringify({
            level: 'warn',
            message: 'Recovered jobs from expired worker leases',
            count: recovered,
            correlationId: correlationId(),
          }),
        );
      }
    } catch (error) {
      console.error(
        JSON.stringify({
          level: 'error',
          message: 'Lease recovery failed',
          error: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  }
}

/**
 * Sleep, waking early if the runner is stopping.
 *
 * A plain 30-second `setTimeout` would make shutdown take up to 30 seconds and the
 * platform would SIGKILL the process partway through a drain. Checking in 100ms slices
 * keeps shutdown prompt without busy-waiting.
 */
async function sleep(ms: number, isRunning: () => boolean): Promise<void> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (!isRunning()) return;
    await new Promise((resolve) => setTimeout(resolve, Math.min(100, deadline - Date.now())));
  }
}

/**
 * Drain every queue once, for tests.
 *
 * The integration suite runs the consumers deterministically rather than waiting on a
 * poll interval: this claims and processes whatever is pending, once per queue.
 */
export async function drainQueuesOnce(env: Env, queue?: QueueName): Promise<number> {
  const workerId = workerIdentity();
  const queues = queue ? [queue] : (Object.keys(CONSUMERS) as QueueName[]);
  let handled = 0;

  for (const name of queues) {
    // Loop until the queue drains (each claim takes at most batchSize).
    for (let round = 0; round < 100; round++) {
      const policy = QUEUE_POLICIES[name];
      const batch = await claimBatch<never>(env.sql, name, workerId, policy);
      if (batch.messages.length === 0) break;

      let consumerError: unknown;
      try {
        await CONSUMERS[name](batch, env);
      } catch (error) {
        consumerError = error;
      }
      await settleBatch(env.sql, batch, policy, consumerError);
      handled += batch.messages.length;
      if (consumerError) {
        if (consumerError instanceof Error) throw consumerError;
        throw new Error(`Queue consumer for ${name} failed: ${JSON.stringify(consumerError)}`);
      }
    }
  }

  return handled;
}
