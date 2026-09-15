/**
 * Daraja credential management (spec §9.1; Zone 6 secrets).
 *
 * The governing rule: **no code path returns a plaintext Daraja secret to any caller, at
 * any authority level.** The configuration API returns a masked view and nothing else.
 *
 * Two corrections from the previous system's post-mortem are structural here:
 *
 *   1. **The callback secret is part of the stored URLs.** Safaricom POSTs to the
 *      ResultURL exactly as configured and never sends custom headers, so the URL itself
 *      must carry the authentication material: `/api/daraja/callbacks/<org>/<secret>`.
 *      The one-time configuration response shows the full callback URL so the L3 can
 *      register it on the Daraja portal; afterwards only the masked view exists.
 *
 *   2. **One client per configuration, cached.** The token cache inside `DarajaClient`
 *      only earns its keep if the same client serves many submissions; constructing a
 *      fresh client per payment doubled the provider call volume and courted
 *      spike-arrest (500.003.02). Clients are cached by configuration id and invalidated
 *      on rotation.
 */

import {
  DarajaClient,
  cleanSecurityCredential,
  generateSecurityCredential,
  isPrecomputedCredential,
  validateInitiatorPassword,
  type DarajaCredentials,
  type DarajaEnvironment,
  type B2cCommandId,
} from '@solvaren/daraja';
import { notFoundError, stateError, validationError } from '@solvaren/core';
import { decryptSecret, encryptSecret, timingSafeEqual } from './crypto.js';
import type { SecretStore } from './secret-store.js';
import { secretReference } from './secret-store.js';
import type { Sql } from '../db/client.js';
import type { Env } from '../env.js';

export interface DarajaConfigRow {
  id: string;
  organization_id: string;
  environment: DarajaEnvironment;
  short_code: string;
  initiator_name: string;
  command_id: B2cCommandId;
  consumer_key_secret_ref: string;
  consumer_secret_secret_ref: string;
  security_credential_ref: string;
  callback_secret_ref: string;
  consumer_key_last_four: string | null;
  credential_version: number;
  credential_rotated_at: string | null;
  result_url: string;
  queue_timeout_url: string;
  status_result_url: string;
  balance_result_url: string;
  status: 'DISABLED' | 'TESTING' | 'ENABLED' | 'ERROR';
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string | null;
}

/** The only shape the configuration API ever returns. */
export interface MaskedDarajaConfig {
  id: string;
  environment: DarajaEnvironment;
  shortCode: string;
  initiatorName: string;
  commandId: B2cCommandId;
  /** Always the literal mask plus the last four characters of the *public* consumer key. */
  consumerKeyMasked: string;
  consumerSecretMasked: string;
  securityCredentialMasked: string;
  credentialVersion: number;
  credentialRotatedAt: string | null;
  resultUrl: string;
  queueTimeoutUrl: string;
  statusResultUrl: string;
  balanceResultUrl: string;
  status: DarajaConfigRow['status'];
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
}

const MASK = '••••••••';

export function maskConfig(row: DarajaConfigRow): MaskedDarajaConfig {
  return {
    id: row.id,
    environment: row.environment,
    shortCode: row.short_code,
    initiatorName: row.initiator_name,
    commandId: row.command_id,
    // Four characters of a consumer key (a public identifier) let an administrator tell
    // two keys apart mid-rotation. The secret itself has no partial disclosure at all.
    consumerKeyMasked: `${MASK}${row.consumer_key_last_four ?? ''}`,
    consumerSecretMasked: MASK,
    securityCredentialMasked: MASK,
    credentialVersion: row.credential_version,
    credentialRotatedAt: row.credential_rotated_at,
    // The stored URLs already contain the secret path segment; they are shown to L3 in
    // full because L3 needs them to configure the Daraja portal — and L3 is the level
    // permitted to know them. Nothing here reveals the *stored secrets themselves*.
    resultUrl: row.result_url,
    queueTimeoutUrl: row.queue_timeout_url,
    statusResultUrl: row.status_result_url,
    balanceResultUrl: row.balance_result_url,
    status: row.status,
    lastTestAt: row.last_test_at,
    lastTestOk: row.last_test_ok,
    lastTestMessage: row.last_test_message,
  };
}

export interface ConfigureDarajaInput {
  organizationId: string;
  environment: DarajaEnvironment;
  shortCode: string;
  initiatorName: string;
  commandId: B2cCommandId;
  consumerKey: string;
  consumerSecret: string;
  /** Raw initiator password (encrypted against the M-PESA cert, then discarded) or a pre-computed credential. */
  initiatorPasswordOrCredential: string;
  mpesaCertificatePem?: string;
  apiBaseUrl: string;
  actorUserId: string;
}

export interface ConfigureDarajaResult {
  config: MaskedDarajaConfig;
  /** The callback secret, exactly once, at configuration time. Never retrievable again. */
  callbackSecret: string;
  callbackUrls: {
    resultUrl: string;
    queueTimeoutUrl: string;
    statusResultUrl: string;
    balanceResultUrl: string;
  };
}

/**
 * Write a Daraja configuration.
 *
 * Plaintext inputs are local to this function; they are not returned, logged, or written
 * to an audit detail. The initiator password is never persisted at all — it exists only
 * long enough to produce the `SecurityCredential`.
 */
export async function configureDaraja(
  sql: Sql,
  env: Env,
  input: ConfigureDarajaInput,
): Promise<ConfigureDarajaResult> {
  const store = env.secrets;

  // Derive the SecurityCredential now, so the initiator password need never be stored.
  let securityCredential: string;
  if (isPrecomputedCredential(input.initiatorPasswordOrCredential)) {
    // Strip line wrapping from a portal-pasted credential; embedded whitespace would be
    // rejected by Daraja at request time even though it does not change the base64 value.
    securityCredential = cleanSecurityCredential(input.initiatorPasswordOrCredential);
  } else {
    if (!input.mpesaCertificatePem) {
      throw validationError(
        'DARAJA_CERTIFICATE_REQUIRED',
        'Supply the M-PESA public certificate so the initiator password can be encrypted, or paste a SecurityCredential generated on the Daraja portal',
      );
    }
    const passwordCheck = validateInitiatorPassword(input.initiatorPasswordOrCredential);
    if (!passwordCheck.ok) {
      throw validationError('DARAJA_INITIATOR_PASSWORD_INVALID', passwordCheck.problems.join('; '), {
        problems: passwordCheck.problems,
      });
    }
    securityCredential = generateSecurityCredential(
      input.initiatorPasswordOrCredential,
      input.mpesaCertificatePem,
    );
  }

  // Resolve existing configuration: rotation keeps the same callback secret so portal
  // registration does not need redoing; first configuration generates one.
  const existing = await sql<{ callback_secret_ref: string }[]>`
    SELECT callback_secret_ref FROM daraja_configurations
     WHERE organization_id = ${input.organizationId} AND environment = ${input.environment}
     LIMIT 1
  `;

  const refs = {
    consumerKey: secretReference(input.organizationId, `daraja:${input.environment}`, 'consumer_key'),
    consumerSecret: secretReference(input.organizationId, `daraja:${input.environment}`, 'consumer_secret'),
    securityCredential: secretReference(input.organizationId, `daraja:${input.environment}`, 'security_credential'),
    callbackSecret: secretReference(input.organizationId, `daraja:${input.environment}`, 'callback_secret'),
  };

  let callbackSecret: string;
  if (existing[0]) {
    const stored = await store.get(existing[0].callback_secret_ref, 'callback-secret');
    callbackSecret = stored ?? crypto.randomUUID() + crypto.randomUUID();
  } else {
    callbackSecret = crypto.randomUUID() + crypto.randomUUID();
  }

  await Promise.all([
    store.put(refs.consumerKey, await encryptSecret(input.consumerKey, env.SECRET_ENCRYPTION_KEY, 'daraja')),
    store.put(refs.consumerSecret, await encryptSecret(input.consumerSecret, env.SECRET_ENCRYPTION_KEY, 'daraja')),
    store.put(refs.securityCredential, await encryptSecret(securityCredential, env.SECRET_ENCRYPTION_KEY, 'daraja')),
    store.put(refs.callbackSecret, await encryptSecret(callbackSecret, env.SECRET_ENCRYPTION_KEY, 'callback-secret')),
  ]);

  // THE FIX: the secret is embedded in every stored callback URL, because Safaricom
  // delivers to the URL exactly as configured and sends no custom headers.
  const resultUrl = `${input.apiBaseUrl}/api/daraja/callbacks/${input.organizationId}/${callbackSecret}`;
  const queueTimeoutUrl = `${input.apiBaseUrl}/api/daraja/callbacks/timeout/${input.organizationId}/${callbackSecret}`;
  const statusResultUrl = `${input.apiBaseUrl}/api/daraja/callbacks/status/${input.organizationId}/${callbackSecret}`;
  const balanceResultUrl = `${input.apiBaseUrl}/api/daraja/callbacks/balance/${input.organizationId}/${callbackSecret}`;

  const rows = await sql<DarajaConfigRow[]>`
    INSERT INTO daraja_configurations (
      organization_id, environment, short_code, initiator_name, command_id,
      consumer_key_secret_ref, consumer_secret_secret_ref, security_credential_ref,
      callback_secret_ref, consumer_key_last_four, result_url, queue_timeout_url,
      status_result_url, balance_result_url, status
    ) VALUES (
      ${input.organizationId}, ${input.environment}, ${input.shortCode}, ${input.initiatorName},
      ${input.commandId}, ${refs.consumerKey}, ${refs.consumerSecret}, ${refs.securityCredential},
      ${refs.callbackSecret}, ${input.consumerKey.slice(-4)}, ${resultUrl}, ${queueTimeoutUrl},
      ${statusResultUrl}, ${balanceResultUrl}, 'TESTING'
    )
    ON CONFLICT (organization_id, environment) DO UPDATE SET
      short_code = EXCLUDED.short_code,
      initiator_name = EXCLUDED.initiator_name,
      command_id = EXCLUDED.command_id,
      consumer_key_secret_ref = EXCLUDED.consumer_key_secret_ref,
      consumer_secret_secret_ref = EXCLUDED.consumer_secret_secret_ref,
      security_credential_ref = EXCLUDED.security_credential_ref,
      consumer_key_last_four = EXCLUDED.consumer_key_last_four,
      result_url = EXCLUDED.result_url,
      queue_timeout_url = EXCLUDED.queue_timeout_url,
      status_result_url = EXCLUDED.status_result_url,
      balance_result_url = EXCLUDED.balance_result_url,
      -- A credential change resets the integration to TESTING: it cannot keep processing
      -- production payments on credentials that have not been proven to work.
      status = 'TESTING',
      last_test_ok = NULL,
      last_test_message = NULL,
      credential_version = daraja_configurations.credential_version + 1,
      credential_rotated_at = now()
    RETURNING *
  `;

  invalidateClientCache(rows[0]!.id);

  return {
    config: maskConfig(rows[0]!),
    callbackSecret,
    callbackUrls: { resultUrl, queueTimeoutUrl, statusResultUrl, balanceResultUrl },
  };
}

// ---------------------------------------------------------------------------
// Client cache: one DarajaClient per configuration id
// ---------------------------------------------------------------------------

const clientCache = new Map<string, { client: DarajaClient; credentialVersion: number }>();

export function invalidateClientCache(configId?: string): void {
  if (configId) clientCache.delete(configId);
  else clientCache.clear();
}

/** Load a cached-or-new client for the config. Never exposes decrypted material. */
export async function loadDarajaClient(
  sql: Sql,
  env: Env,
  organizationId: string,
): Promise<{
  client: DarajaClient;
  credentials: DarajaCredentials;
  config: {
    id: string;
    commandId: B2cCommandId;
    resultUrl: string;
    queueTimeoutUrl: string;
    statusResultUrl: string;
    balanceResultUrl: string;
    environment: DarajaEnvironment;
    shortCode: string;
    initiatorName: string;
    credentialVersion: number;
  };
}> {
  const rows = await sql<DarajaConfigRow[]>`
    SELECT * FROM daraja_configurations
     WHERE organization_id = ${organizationId} AND status = 'ENABLED'
     ORDER BY environment = 'production' DESC
     LIMIT 1
  `;
  const config = rows[0];
  if (!config) {
    throw stateError(
      'DARAJA_NOT_CONFIGURED',
      'No enabled Daraja integration is configured for this organisation',
    );
  }
  const built = await buildClient(sql, env, config);
  return { ...built, config: describeConfig(config) };
}

/** Load a specific configuration for a connection test, regardless of enabled state. */
export async function loadDarajaClientById(
  sql: Sql,
  env: Env,
  organizationId: string,
  configId: string,
) {
  const rows = await sql<DarajaConfigRow[]>`
    SELECT * FROM daraja_configurations
     WHERE id = ${configId} AND organization_id = ${organizationId}
     LIMIT 1
  `;
  const config = rows[0];
  if (!config) {
    throw notFoundError('DARAJA_CONFIG_NOT_FOUND', 'That Daraja configuration could not be found');
  }
  const built = await buildClient(sql, env, config);
  return { ...built, config: describeConfig(config) };
}

function describeConfig(config: DarajaConfigRow) {
  return {
    id: config.id,
    commandId: config.command_id,
    resultUrl: config.result_url,
    queueTimeoutUrl: config.queue_timeout_url,
    statusResultUrl: config.status_result_url,
    balanceResultUrl: config.balance_result_url,
    environment: config.environment,
    shortCode: config.short_code,
    initiatorName: config.initiator_name,
    credentialVersion: config.credential_version,
  };
}

async function buildClient(sql: Sql, env: Env, config: DarajaConfigRow) {
  const cached = clientCache.get(config.id);
  if (cached && cached.credentialVersion === config.credential_version) {
    const credentials = await loadCredentials(env, config);
    return { client: cached.client, credentials };
  }

  const credentials = await loadCredentials(env, config);

  const client = new DarajaClient({
    environment: config.environment,
    credentials,
    onEvent: (event) => {
      // Structured, and deliberately carries no request body — the body holds the
      // SecurityCredential on every B2C call.
      console.info(
        JSON.stringify({
          level: 'info',
          scope: 'daraja',
          type: event.type,
          endpoint: event.endpoint,
          httpStatus: event.httpStatus,
          durationMs: event.durationMs,
        }),
      );
    },
  });

  clientCache.set(config.id, { client, credentialVersion: config.credential_version });
  return { client, credentials };
}

async function loadCredentials(env: Env, config: DarajaConfigRow): Promise<DarajaCredentials> {
  const [keyEnvelope, secretEnvelope, credentialEnvelope] = await Promise.all([
    env.secrets.get(config.consumer_key_secret_ref, 'daraja'),
    env.secrets.get(config.consumer_secret_secret_ref, 'daraja'),
    env.secrets.get(config.security_credential_ref, 'daraja'),
  ]);

  if (!keyEnvelope || !secretEnvelope || !credentialEnvelope) {
    throw stateError(
      'DARAJA_SECRETS_MISSING',
      'The stored Daraja credentials could not be retrieved. Reconfigure the integration.',
    );
  }

  return {
    consumerKey: await decryptSecret(keyEnvelope, env.SECRET_ENCRYPTION_KEY, 'daraja'),
    consumerSecret: await decryptSecret(secretEnvelope, env.SECRET_ENCRYPTION_KEY, 'daraja'),
    securityCredential: await decryptSecret(credentialEnvelope, env.SECRET_ENCRYPTION_KEY, 'daraja'),
    initiatorName: config.initiator_name,
    shortCode: config.short_code,
  };
}

/** Resolve the shared secret a callback must present (spec §9.4). */
export async function loadCallbackSecret(
  sql: Sql,
  env: Env,
  organizationId: string,
): Promise<string | null> {
  const rows = await sql<{ callback_secret_ref: string }[]>`
    SELECT callback_secret_ref FROM daraja_configurations
     WHERE organization_id = ${organizationId}
     ORDER BY status = 'ENABLED' DESC
     LIMIT 1
  `;
  if (!rows[0]) return null;
  const envelope = await env.secrets.get(rows[0].callback_secret_ref, 'callback-secret');
  return envelope ? decryptSecret(envelope, env.SECRET_ENCRYPTION_KEY, 'callback-secret') : null;
}

export { timingSafeEqual };
