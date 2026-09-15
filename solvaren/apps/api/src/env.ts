/**
 * Runtime environment contract and the application context threaded through Hono.
 *
 * The Env object carries every external dependency the API touches — database, queue,
 * rate limiter, object store, secrets, signing keys — so handlers stay pure with respect
 * to the outside world and tests can substitute any of them.
 */

import type { S3ObjectStore } from '@solvaren/storage';
import type { Sql } from './db/client.js';
import type { PostgresJobQueue } from './queue/queue.js';
import type { PostgresRateLimiter } from './rate-limiter.js';
import type { SecretStore } from './services/secret-store.js';
import type { AuthenticatedActor, EffectiveMatrixCarrier } from './services/auth.js';
import type { EffectiveMatrix } from '@solvaren/core';

export type QueueName = 'payments' | 'callbacks' | 'reconciliation' | 'backups' | 'reports' | 'notifications';

interface QueueJobBase {
  organizationId: string;
  correlationId: string;
}

export interface PaymentQueueMessage extends QueueJobBase {
  type: 'EXECUTE_INSTRUCTION';
  batchId: string;
  instructionId: string;
  batchVersion: number;
  manifestHash: string;
  fingerprint: string;
  challengeId: string;
  attempt: number;
}

export interface CallbackQueueMessage extends QueueJobBase {
  type: 'PROCESS_CALLBACK';
  callbackId: string;
  callbackType: 'B2C_RESULT' | 'B2C_TIMEOUT' | 'TRANSACTION_STATUS' | 'ACCOUNT_BALANCE';
}

export type ReconciliationSweepMessage = QueueJobBase & {
  type: 'SWEEP_ORGANIZATION';
};

export type ReconcileTransactionMessage = QueueJobBase & {
  type: 'RECONCILE_TRANSACTION';
  transactionId?: string;
  requestedByUserId?: string;
};

export type RefreshBalanceMessage = QueueJobBase & {
  type: 'REFRESH_BALANCE';
  requestedByUserId?: string;
};

export type ReconciliationQueueMessage =
  | ReconciliationSweepMessage
  | ReconcileTransactionMessage
  | RefreshBalanceMessage;

export interface BackupQueueMessage extends QueueJobBase {
  type: 'RUN_BACKUP' | 'ENFORCE_RETENTION';
  attemptId?: string;
  trigger: 'MANUAL' | 'SCHEDULED';
  requestedByUserId?: string;
}

export interface ReportQueueMessage extends QueueJobBase {
  type: 'GENERATE_REPORT';
  reportJobId: string;
  requestedByUserId: string;
}

export interface NotificationQueueMessage extends QueueJobBase {
  type: 'DELIVER_NOTIFICATIONS';
}

export type QueueMessage =
  | PaymentQueueMessage
  | CallbackQueueMessage
  | ReconciliationQueueMessage
  | BackupQueueMessage
  | ReportQueueMessage
  | NotificationQueueMessage;

export interface EnqueueOptions {
  delaySeconds?: number;
  priority?: number;
}

export interface QueueMessageHandle<T> {
  readonly body: T;
  readonly attempts: number;
  ack(): void;
  retry(options?: { delaySeconds?: number }): void;
}

export interface QueueBatch<T> {
  readonly queue: QueueName;
  readonly messages: QueueMessageHandle<T>[];
}

export interface Env {
  sql: Sql;
  queue: PostgresJobQueue;
  rateLimiter: PostgresRateLimiter;
  objects: S3ObjectStore;
  secrets: SecretStore;

  SESSION_SIGNING_KEY: string;
  SECRET_ENCRYPTION_KEY: string;
  CALLBACK_SHARED_SECRET?: string;
  AI_API_KEY?: string;
  AI_MODEL?: string;

  ENVIRONMENT: 'development' | 'staging' | 'production';
  APP_ORIGIN: string;
  API_BASE_URL: string;
  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;
}

export interface SecurityContext {
  ip: string | null;
  userAgent: string | null;
  country: string | null;
  deviceFingerprint: string | null;
  [key: string]: unknown;
}

export type AppContext = {
  Variables: {
    correlationId: string;
    securityContext: SecurityContext;
    actor: AuthenticatedActor;
    permissionMatrix: EffectiveMatrix;
  };
  /** `app.fetch(request, env)` — c.env *is* the Env (Hono's Bindings). */
  Bindings: Env;
};

/** `actor` + matrix carrier for services that need both (and tests that fake them). */
export type { EffectiveMatrixCarrier };
