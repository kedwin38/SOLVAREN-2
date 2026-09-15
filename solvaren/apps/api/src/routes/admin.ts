/**
 * Administration (spec §4.3): users, Daraja, backups, policies, the dynamic permission
 * engine, batch templates and the financial calendar. Everything here is L3-only except
 * where the permission matrix says otherwise; the Daraja endpoints in particular never
 * return a plaintext secret in any response shape.
 *
 * AC-16: the Daraja routes are mounted under this L3-only router — an L1/L2 session is
 * refused at the server with an authorization denial and a security event, not by a
 * hidden UI.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  reference,
  policySchema,
  assertValidOverride,
  describeOverrideChange,
  effectivePermissions,
  baselinePermissions,
  notFoundError,
  validationError,
  stateError,
  isValidCron,
  nextRun,
  GRANT_CEILINGS,
  PERMISSIONS,
  AUTHORITY_LEVELS,
} from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import {
  configureDaraja,
  loadDarajaClientById,
  maskConfig,
  invalidateClientCache,
  type DarajaConfigRow,
} from '../services/daraja-config.js';
import { encryptSecret } from '../services/crypto.js';
import { assertFreshAuthentication, assertWebAuthnSession, revokeAllSessions } from '../services/auth.js';
import { verifyAuthorizationPin } from '../services/crypto.js';
import { hashPassword, assertPinShape, hashAuthorizationPin } from '../services/crypto.js';
import { loadPolicy } from '../services/policy-store.js';
import { loadEffectiveMatrix, listOverrides } from '../services/permissions.js';
import { secretReference } from '../services/secret-store.js';
import type { AppContext, BackupQueueMessage } from '../env.js';

export const adminRoutes = new Hono<AppContext>();
adminRoutes.use('*', requireAuth);

// ---------------------------------------------------------------------------
// Users (spec §4.3 Organization Administration)
// ---------------------------------------------------------------------------

const createUserSchema = z.object({
  email: z.string().trim().email().max(320),
  fullName: z.string().trim().min(1).max(140),
  authorityLevel: z.enum(['L1', 'L2', 'L3']),
  temporaryPassword: z.string().min(12).max(1024),
  /** The FPAC PIN for L2/L3 accounts — mandatory at creation for privileged levels. */
  authorizationPin: z.string().min(6).max(12).optional(),
});

adminRoutes.post(
  '/users',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = createUserSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    if (body.authorityLevel !== 'L1' && !body.authorizationPin) {
      throw validationError(
        'PIN_REQUIRED',
        'Level 2 and Level 3 accounts require a Frontier Authorization PIN at creation',
      );
    }
    if (body.authorizationPin) assertPinShape(body.authorizationPin);

    const created = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        // Governance: assigning L3 requires an existing active L3 (the actor is one) and
        // records a distinct, high-severity event.
        const rows = await tx<{ id: string }[]>`
          INSERT INTO users (
            organization_id, email, full_name, authority_level, status, password_hash,
            authorization_pin_hash, authorization_pin_updated_at
          ) VALUES (
            ${actor.organizationId}, ${body.email.trim().toLowerCase()}, ${body.fullName},
            ${body.authorityLevel},
            ${body.authorityLevel === 'L1' ? 'ACTIVE' : 'PENDING_ENROLMENT'},
            ${await hashPassword(body.temporaryPassword)},
            ${body.authorizationPin ? await hashAuthorizationPin(body.authorizationPin, 'pending') : null},
            ${body.authorizationPin ? nowIso() : null}
          )
          RETURNING id
        `;
        const userId = rows[0]!.id;

        // The PIN hash binds to the user id; re-hash now that the id exists.
        if (body.authorizationPin) {
          await tx`
            UPDATE users
               SET authorization_pin_hash = ${await hashAuthorizationPin(body.authorizationPin, userId)},
                   authorization_pin_updated_at = now()
             WHERE id = ${userId}
          `;
        }

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'user.created',
          objectType: 'User',
          objectId: userId,
          outcome: 'SUCCESS',
          newState: { email: body.email, level: body.authorityLevel },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            privileged: body.authorityLevel !== 'L1',
            enrolmentRequired: body.authorityLevel !== 'L1',
          },
        });

        return { userId };
      }),
    );

    return c.json(
      {
        userId: created.userId,
        nextStep:
          body.authorityLevel === 'L1'
            ? 'Share the temporary password; the user should change it at first sign-in.'
            : 'Share the temporary password. The account activates when the user enrols a security key (they will be prompted at first sign-in).',
      },
      201,
    );
  },
);

adminRoutes.get('/users', requirePermissions('admin:users'), async (c) => {
  const actor = actorOf(c);
  const users = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        email: string;
        full_name: string;
        authority_level: string;
        status: string;
        last_login_at: string | null;
        created_at: string;
        active_sessions: string;
        webauthn_count: string;
      }[]
    >`
      SELECT u.id, u.email, u.full_name, u.authority_level, u.status, u.last_login_at, u.created_at,
             (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > now()) AS active_sessions,
             (SELECT COUNT(*) FROM webauthn_credentials w WHERE w.user_id = u.id AND w.status = 'ACTIVE') AS webauthn_count
        FROM users u
       WHERE u.organization_id = ${actor.organizationId}
       ORDER BY u.authority_level DESC, u.full_name
    `,
  );
  return c.json({
    users: users.map((u) => ({
      userId: u.id,
      email: u.email,
      fullName: u.full_name,
      level: u.authority_level,
      status: u.status,
      lastLoginAt: u.last_login_at,
      createdAt: u.created_at,
      activeSessions: Number(u.active_sessions),
      webauthnCredentials: Number(u.webauthn_count),
    })),
  });
});

const userPatchSchema = z
  .object({
    status: z.enum(['ACTIVE', 'DISABLED', 'LOCKED']).optional(),
    authorityLevel: z.enum(['L1', 'L2', 'L3']).optional(),
    resetPassword: z.string().min(12).max(1024).optional(),
    unlock: z.boolean().optional(),
    revokeSessions: z.boolean().optional(),
  })
  .refine((v) => Object.keys(v).length > 0, { message: 'Nothing to change' });

adminRoutes.patch(
  '/users/:id',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    const targetId = c.req.param('id');
    const body = userPatchSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; email: string; authority_level: string; status: string }[]>`
          SELECT id, email, authority_level, status FROM users
           WHERE id = ${targetId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const target = rows[0];
        if (!target) throw notFoundError('USER_NOT_FOUND', 'That user could not be found');

        if (target.id === actor.userId && body.status === 'DISABLED') {
          throw stateError('CANNOT_DISABLE_SELF', 'You cannot disable your own account.');
        }

        const before = { level: target.authority_level, status: target.status };

        if (body.unlock) {
          await tx`UPDATE users SET failed_login_count = 0, locked_until = NULL, status = 'ACTIVE' WHERE id = ${target.id}`;
        }
        if (body.status) {
          // A demoted or disabled privileged account must complete enrolment again on
          // the way back to ACTIVE if it has no authenticator.
          await tx`UPDATE users SET status = ${body.status} WHERE id = ${target.id}`;
        }
        if (body.authorityLevel) {
          await tx`UPDATE users SET authority_level = ${body.authorityLevel} WHERE id = ${target.id}`;
        }
        if (body.resetPassword) {
          await tx`
            UPDATE users
               SET password_hash = ${await hashPassword(body.resetPassword)},
                   failed_login_count = 0, locked_until = NULL
             WHERE id = ${target.id}
          `;
        }
        if (body.revokeSessions || body.status === 'DISABLED') {
          await tx`
            UPDATE sessions SET revoked_at = now(), revocation_reason = 'Administrative action'
             WHERE user_id = ${target.id} AND revoked_at IS NULL
          `;
        }

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'user.updated',
          objectType: 'User',
          objectId: target.id,
          outcome: 'SUCCESS',
          previousState: before,
          newState: {
            level: body.authorityLevel ?? before.level,
            status: body.status ?? (body.unlock ? 'ACTIVE' : before.status),
            passwordReset: Boolean(body.resetPassword),
            sessionsRevoked: Boolean(body.revokeSessions || body.status === 'DISABLED'),
          },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { changedFields: Object.keys(body) },
        });

        return { updated: true as const };
      }),
    );

    return c.json(result);
  },
);

/** POST /api/admin/users/:id/admin-recovery — controlled administrative recovery (§8.3). */
adminRoutes.post(
  '/users/:id/admin-recovery',
  requireExactLevel('L3'),
  requirePermissions('admin:users'),
  async (c) => {
    const actor = actorOf(c);
    const targetId = c.req.param('id');
    const body = z
      .object({
        reason: z.string().trim().min(10).max(500),
        authorizationPin: z.string().min(6).max(12),
      })
      .parse(await c.req.json());
    const correlationId = c.get('correlationId');

    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);

    const result = await withConnection(c.env, async (sql) => {
      // The acting L3's own FPAC PIN is required: administrative recovery is a
      // privileged financial-boundary action, not a casual toggle.
      const rows = await sql<{ authorization_pin_hash: string | null }[]>`
        SELECT authorization_pin_hash FROM users WHERE id = ${actor.userId} LIMIT 1
      `;
      const pinOk = await verifyAuthorizationPin(
        body.authorizationPin,
        actor.userId,
        rows[0]?.authorization_pin_hash ?? null,
      );
      if (!pinOk) {
        throw validationError('AUTHORIZATION_PIN_INVALID', 'Your Frontier Authorization PIN was not correct.');
      }

      return inTransaction(sql, async (tx) => {
        const targets = await tx<{ id: string; email: string; authority_level: string }[]>`
          SELECT id, email, authority_level FROM users
           WHERE id = ${targetId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const target = targets[0];
        if (!target) throw notFoundError('USER_NOT_FOUND', 'That user could not be found');

        // Recovery resets the account to PENDING_ENROLMENT and revokes everything: the
        // user re-enrols an authenticator (and L2/L3 re-enrols a PIN) before acting.
        await tx`
          UPDATE users
             SET status = 'PENDING_ENROLMENT', authorization_pin_hash = NULL,
                 authorization_pin_updated_at = NULL, failed_login_count = 0, locked_until = NULL
           WHERE id = ${target.id}
        `;
        await tx`
          UPDATE webauthn_credentials
             SET status = 'REVOKED', revoked_at = now(), revoked_reason = 'Administrative recovery'
           WHERE user_id = ${target.id} AND status = 'ACTIVE'
        `;
        await tx`
          UPDATE recovery_codes SET consumed_at = now()
           WHERE user_id = ${target.id} AND consumed_at IS NULL
        `;
        await revokeAllSessions(tx, target.id, 'Administrative recovery');

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'SECURITY',
          action: 'user.admin_recovery',
          objectType: 'User',
          objectId: target.id,
          outcome: 'SUCCESS',
          previousState: { email: target.email, level: target.authority_level },
          newState: { status: 'PENDING_ENROLMENT', authenticatorsRevoked: 'all' },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { reason: body.reason, note: 'Full re-enrolment required; financial boundary intact.' },
        });

        return {
          recovered: true as const,
          nextStep:
            'The account now signs in with its password and is prompted to enrol a new security key. No privileged action is possible until enrolment completes.',
        };
      });
    });

    return c.json(result);
  },
);

// ---------------------------------------------------------------------------
// Daraja administration — LEVEL 3 ONLY (spec §9.1, AC-16)
// ---------------------------------------------------------------------------

const darajaConfigSchema = z.object({
  environment: z.enum(['sandbox', 'production']),
  shortCode: z.string().regex(/^\d{5,9}$/, 'The shortcode must be 5 to 9 digits'),
  initiatorName: z.string().trim().min(1).max(64),
  commandId: z.enum(['BusinessPayment', 'SalaryPayment', 'PromotionPayment']).default('BusinessPayment'),
  consumerKey: z.string().trim().min(10).max(200),
  consumerSecret: z.string().trim().min(10).max(200),
  initiatorPasswordOrCredential: z.string().trim().min(8).max(2000),
  mpesaCertificatePem: z.string().trim().max(10_000).optional(),
});

/**
 * POST /api/admin/daraja — configure or rotate credentials.
 *
 * Requires fresh authentication, a WebAuthn session AND the FPAC PIN on top of L3
 * authority (spec §9.1: credential changes require re-authentication + WebAuthn + PIN).
 */
adminRoutes.post(
  '/daraja',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);
    const bodyWithPin = z
      .intersection(darajaConfigSchema, z.object({ authorizationPin: z.string().min(6).max(12) }))
      .parse(await c.req.json());
    const correlationId = c.get('correlationId');

    // The PIN gate (§9.1) — verified before anything is written.
    const pinRows = await withConnection(c.env, (sql) =>
      sql<{ authorization_pin_hash: string | null }[]>`
        SELECT authorization_pin_hash FROM users WHERE id = ${actor.userId} LIMIT 1
      `,
    );
    const pinOk = await verifyAuthorizationPin(
      bodyWithPin.authorizationPin,
      actor.userId,
      pinRows[0]?.authorization_pin_hash ?? null,
    );
    if (!pinOk) {
      throw validationError(
        'AUTHORIZATION_PIN_INVALID',
        'Your Frontier Authorization PIN was not correct. Credential rotation has not been performed.',
      );
    }

    const { authorizationPin: _pin, ...body } = bodyWithPin;

    const result = await withConnection(c.env, async (sql) => {
      const previous = await sql<{ credential_version: number; status: string }[]>`
        SELECT credential_version, status FROM daraja_configurations
         WHERE organization_id = ${actor.organizationId} AND environment = ${body.environment}
      `;

      const configured = await configureDaraja(sql, c.env, {
        organizationId: actor.organizationId,
        environment: body.environment,
        shortCode: body.shortCode,
        initiatorName: body.initiatorName,
        commandId: body.commandId,
        consumerKey: body.consumerKey,
        consumerSecret: body.consumerSecret,
        initiatorPasswordOrCredential: body.initiatorPasswordOrCredential,
        mpesaCertificatePem: body.mpesaCertificatePem,
        apiBaseUrl: c.env.API_BASE_URL,
        actorUserId: actor.userId,
      });

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: previous[0] ? 'daraja.credentials.rotated' : 'daraja.configured',
          objectType: 'DarajaConfiguration',
          objectId: configured.config.id,
          outcome: 'SUCCESS',
          previousState: previous[0]
            ? { credentialVersion: previous[0].credential_version, status: previous[0].status }
            : null,
          newState: { credentialVersion: configured.config.credentialVersion, status: configured.config.status },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            environment: body.environment,
            shortCode: body.shortCode,
            initiatorName: body.initiatorName,
            commandId: body.commandId,
            note: 'Integration reset to TESTING; a connection test is required before it can process payments.',
          },
        }),
      );

      return configured;
    });

    return c.json({
      configuration: result.config,
      // The secret is shown exactly once, at configuration time, so the L3 can register
      // the callback URLs on the Daraja portal. It is never retrievable again.
      callbackSecret: result.callbackSecret,
      callbackUrls: result.callbackUrls,
      nextStep:
        'Register the callback URLs on the Daraja portal, then run a connection test. The integration cannot process production payments until a test passes.',
    });
  },
);

adminRoutes.get(
  '/daraja',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    const configs = await withConnection(c.env, async (sql) => {
      const rows = await sql<DarajaConfigRow[]>`
        SELECT * FROM daraja_configurations
         WHERE organization_id = ${actor.organizationId}
         ORDER BY environment
      `;
      return rows.map(maskConfig);
    });
    return c.json({ configurations: configs });
  },
);

adminRoutes.post(
  '/daraja/:id/test',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    const configId = c.req.param('id');
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, async (sql) => {
      const { client } = await loadDarajaClientById(sql, c.env, actor.organizationId, configId);
      const test = await client.testConnection();

      await inTransaction(sql, async (tx) => {
        await tx`
          UPDATE daraja_configurations
             SET last_test_at = now(), last_test_ok = ${test.ok}, last_test_message = ${test.message},
                 status = ${test.ok ? 'TESTING' : 'ERROR'}
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.connection_tested',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: test.ok ? 'SUCCESS' : 'FAILURE',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { ok: test.ok, message: test.message, latencyMs: test.latencyMs },
        });
      });

      return test;
    });

    return c.json(result);
  },
);

adminRoutes.post(
  '/daraja/:id/enable',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const configId = c.req.param('id');
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ last_test_ok: boolean | null; environment: string }[]>`
          SELECT last_test_ok, environment FROM daraja_configurations
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        const config = rows[0];
        if (!config) throw notFoundError('DARAJA_CONFIG_NOT_FOUND', 'That configuration could not be found');

        // The database constraint enforces this too; checking here produces a better message.
        if (config.last_test_ok !== true) {
          throw stateError(
            'DARAJA_TEST_REQUIRED',
            'Run a successful connection test before enabling this integration. Enabling an untested integration means discovering a credential problem during a live payroll run.',
          );
        }

        // Only one enabled integration per organisation: two would make "which
        // credentials paid this?" ambiguous.
        await tx`
          UPDATE daraja_configurations SET status = 'DISABLED'
           WHERE organization_id = ${actor.organizationId} AND id <> ${configId} AND status = 'ENABLED'
        `;
        await tx`
          UPDATE daraja_configurations
             SET status = 'ENABLED', enabled_at = now(), enabled_by_user_id = ${actor.userId}
           WHERE id = ${configId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.enabled',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: 'SUCCESS',
          newState: { status: 'ENABLED' },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { environment: config.environment },
        });
      }),
    );

    return c.json({ status: 'ENABLED' });
  },
);

adminRoutes.post(
  '/daraja/:id/disable',
  requireExactLevel('L3'),
  requirePermissions('admin:daraja'),
  async (c) => {
    const actor = actorOf(c);
    const configId = c.req.param('id');
    const body = z.object({ reason: z.string().trim().max(500) }).parse(await c.req.json());

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        await tx`
          UPDATE daraja_configurations SET status = 'DISABLED', disabled_reason = ${body.reason}
           WHERE id = ${configId} AND organization_id = ${actor.organizationId}
        `;
        invalidateClientCache(configId);
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'daraja.disabled',
          objectType: 'DarajaConfiguration',
          objectId: configId,
          outcome: 'SUCCESS',
          newState: { status: 'DISABLED' },
          correlationId: c.get('correlationId'),
          securityContext: c.get('securityContext'),
          detail: { reason: body.reason },
        });
      }),
    );

    return c.json({
      status: 'DISABLED',
      note: 'No further payments will be submitted. Instructions already in flight will still report their outcome.',
    });
  },
);

// ---------------------------------------------------------------------------
// Backups (spec §13)
// ---------------------------------------------------------------------------

const backupConfigSchema = z.object({
  providerLabel: z.string().trim().max(80).default('S3-compatible'),
  endpoint: z.string().url().max(300).optional(),
  region: z.string().trim().max(40).optional(),
  bucket: z.string().trim().min(1).max(200),
  pathPrefix: z.string().trim().max(200).default('solvaren/backups'),
  accessKeyId: z.string().trim().min(4).max(200),
  secretAccessKey: z.string().trim().min(8).max(400),
  encryptionMode: z.enum(['SSE_S3', 'SSE_KMS', 'APPLICATION']).default('SSE_S3'),
  retentionMaxCount: z.number().int().min(1).max(3650).default(30),
});

adminRoutes.post(
  '/backups/target',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = backupConfigSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, async (sql) => {
      const accessRef = secretReference(actor.organizationId, 'backup', 'access_key');
      const secretRef = secretReference(actor.organizationId, 'backup', 'secret_key');

      // Credentials are encrypted before persistence and masked after save (BAK-002).
      await c.env.secrets.put(accessRef, await encryptSecret(body.accessKeyId, c.env.SECRET_ENCRYPTION_KEY, 'backup'));
      await c.env.secrets.put(secretRef, await encryptSecret(body.secretAccessKey, c.env.SECRET_ENCRYPTION_KEY, 'backup'));

      const rows = await sql<{ id: string; status: string }[]>`
        INSERT INTO backup_configurations (
          organization_id, provider_label, endpoint, region, bucket, path_prefix,
          access_key_secret_ref, secret_key_secret_ref, access_key_last_four,
          encryption_mode, retention_max_count, updated_by_user_id
        ) VALUES (
          ${actor.organizationId}, ${body.providerLabel}, ${body.endpoint ?? null},
          ${body.region ?? null}, ${body.bucket}, ${body.pathPrefix}, ${accessRef}, ${secretRef},
          ${body.accessKeyId.slice(-4)}, ${body.encryptionMode}, ${body.retentionMaxCount}, ${actor.userId}
        )
        ON CONFLICT (organization_id) DO UPDATE SET
          provider_label = EXCLUDED.provider_label, endpoint = EXCLUDED.endpoint,
          region = EXCLUDED.region, bucket = EXCLUDED.bucket, path_prefix = EXCLUDED.path_prefix,
          access_key_secret_ref = EXCLUDED.access_key_secret_ref,
          secret_key_secret_ref = EXCLUDED.secret_key_secret_ref,
          access_key_last_four = EXCLUDED.access_key_last_four,
          encryption_mode = EXCLUDED.encryption_mode,
          retention_max_count = EXCLUDED.retention_max_count, updated_by_user_id = EXCLUDED.updated_by_user_id,
          -- A credential change resets the tested state and lifts any suspension.
          status = 'DISABLED', last_test_ok = NULL, schedule_enabled = FALSE,
          consecutive_failures = 0, suspended_at = NULL, suspension_reason = NULL
        RETURNING id, status
      `;

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: 'backup.target.configured',
          objectType: 'BackupConfiguration',
          objectId: rows[0]!.id,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            provider: body.providerLabel,
            bucket: body.bucket,
            pathPrefix: body.pathPrefix,
            retentionMaxCount: body.retentionMaxCount,
            accessKeyLastFour: body.accessKeyId.slice(-4),
          },
        }),
      );

      return rows[0]!;
    });

    return c.json({
      configurationId: result.id,
      status: result.status,
      accessKeyMasked: `••••••••${body.accessKeyId.slice(-4)}`,
      secretKeyMasked: '••••••••',
      nextStep: 'Run a connection test before enabling the schedule.',
    });
  },
);

/** POST /api/admin/backups/test — prove the target credentials work. */
adminRoutes.post(
  '/backups/test',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');

    const result = await withConnection(c.env, async (sql) => {
      const configs = await sql<
        { id: string; endpoint: string | null; region: string | null; bucket: string; access_key_secret_ref: string; secret_key_secret_ref: string }[]
      >`
        SELECT id, endpoint, region, bucket, access_key_secret_ref, secret_key_secret_ref
          FROM backup_configurations WHERE organization_id = ${actor.organizationId} LIMIT 1
      `;
      const config = configs[0];
      if (!config) throw validationError('BACKUP_NOT_CONFIGURED', 'Configure a backup target first.');

      const { decryptSecret } = await import('../services/crypto.js');
      const accessKey = await decryptSecret(
        (await c.env.secrets.get(config.access_key_secret_ref, 'backup'))!,
        c.env.SECRET_ENCRYPTION_KEY,
        'backup',
      );
      const secretKey = await decryptSecret(
        (await c.env.secrets.get(config.secret_key_secret_ref, 'backup'))!,
        c.env.SECRET_ENCRYPTION_KEY,
        'backup',
      );

      const { S3ObjectStore } = await import('@solvaren/storage');
      const store = new S3ObjectStore({
        endpoint: config.endpoint ?? undefined,
        region: config.region ?? 'auto',
        bucket: config.bucket,
        accessKeyId: accessKey,
        secretAccessKey: secretKey,
        forcePathStyle: true,
      });
      const test = await store.testConnection();

      await inTransaction(sql, async (tx) => {
        await tx`
          UPDATE backup_configurations
             SET last_test_at = now(), last_test_ok = ${test.ok}, last_test_message = ${test.message},
                 status = ${test.ok ? 'CONNECTED' : 'ERROR'}
           WHERE organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: 'backup.target.tested',
          objectType: 'BackupConfiguration',
          objectId: config.id,
          outcome: test.ok ? 'SUCCESS' : 'FAILURE',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { ok: test.ok, message: test.message },
        });
      });

      return test;
    });

    return c.json(result);
  },
);

adminRoutes.post(
  '/backups/run',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');
    const attemptReference = reference('backup');

    await withConnection(c.env, async (sql) => {
      const configs = await sql<{ id: string }[]>`
        SELECT id FROM backup_configurations WHERE organization_id = ${actor.organizationId}
      `;
      if (!configs[0]) {
        throw validationError('BACKUP_NOT_CONFIGURED', 'Connect an S3-compatible storage target before running a backup');
      }

      const message: BackupQueueMessage = {
        type: 'RUN_BACKUP',
        organizationId: actor.organizationId,
        attemptId: attemptReference,
        trigger: 'MANUAL',
        requestedByUserId: actor.userId,
        correlationId,
      };
      await c.env.queue.send({ queue: 'backups', body: message });

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: 'backup.requested',
          objectType: 'BackupAttempt',
          objectId: attemptReference,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { trigger: 'MANUAL', attemptReference },
        }),
      );
    });

    // NFR-PERF: the browser request never holds the operation open.
    return c.json(
      {
        accepted: true,
        attemptReference,
        message: 'The backup has been queued. Its progress and result appear in the backup history.',
      },
      202,
    );
  },
);

adminRoutes.get(
  '/backups',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);

    const data = await withConnection(c.env, async (sql) => {
      const configs = await sql<
        {
          id: string;
          provider_label: string;
          bucket: string;
          path_prefix: string;
          region: string | null;
          endpoint: string | null;
          access_key_last_four: string | null;
          encryption_mode: string;
          status: string;
          last_test_at: string | null;
          last_test_ok: boolean | null;
          last_test_message: string | null;
          schedule_enabled: boolean;
          schedule_local_time: string;
          schedule_timezone: string;
          retention_max_count: number;
          last_scheduled_run_at: string | null;
          next_scheduled_run_at: string | null;
          consecutive_failures: number;
          suspended_at: string | null;
          suspension_reason: string | null;
        }[]
      >`
        SELECT id, provider_label, bucket, path_prefix, region, endpoint, access_key_last_four,
               encryption_mode, status, last_test_at, last_test_ok, last_test_message,
               schedule_enabled, schedule_local_time, schedule_timezone, retention_max_count,
               last_scheduled_run_at, next_scheduled_run_at, consecutive_failures,
               suspended_at, suspension_reason
          FROM backup_configurations WHERE organization_id = ${actor.organizationId}
      `;

      const attempts = await sql<
        {
          attempt_reference: string;
          trigger_type: string;
          status: string;
          started_at: string | null;
          ended_at: string | null;
          size_bytes: string | null;
          checksum: string | null;
          object_key: string | null;
          error_message: string | null;
          retention_deleted_count: number;
          retention_complete: boolean | null;
          object_retired_at: string | null;
        }[]
      >`
        SELECT attempt_reference, trigger_type, status, started_at, ended_at, size_bytes,
               checksum, object_key, error_message, retention_deleted_count,
               retention_complete, object_retired_at
          FROM backup_attempts
         WHERE organization_id = ${actor.organizationId}
         ORDER BY COALESCE(started_at, created_at) DESC
         LIMIT 100
      `;

      const config = configs[0];
      const latest = attempts[0] ?? null;

      return {
        configuration: config
          ? {
              configurationId: config.id,
              providerLabel: config.provider_label,
              bucket: config.bucket,
              pathPrefix: config.path_prefix,
              region: config.region,
              endpoint: config.endpoint,
              accessKeyMasked: config.access_key_last_four ? `••••••••${config.access_key_last_four}` : '••••••••',
              secretKeyMasked: '••••••••',
              encryptionMode: config.encryption_mode,
              status: config.status,
              lastTestAt: config.last_test_at,
              lastTestOk: config.last_test_ok,
              lastTestMessage: config.last_test_message,
              scheduleEnabled: config.schedule_enabled,
              scheduleLocalTime: config.schedule_local_time,
              scheduleTimezone: config.schedule_timezone,
              retentionMaxCount: config.retention_max_count,
              lastScheduledRunAt: config.last_scheduled_run_at,
              nextScheduledRunAt: config.next_scheduled_run_at,
              suspended: config.suspended_at !== null,
              suspensionReason: config.suspension_reason,
              consecutiveFailures: config.consecutive_failures,
            }
          : null,
        // BAK-008: the most recent result is always visible, and a failure is shown as a
        // failure — never smoothed into "no recent backups".
        latestResult: latest
          ? {
              attemptReference: latest.attempt_reference,
              trigger: latest.trigger_type,
              status: latest.status,
              startedAt: latest.started_at,
              endedAt: latest.ended_at,
              sizeBytes: latest.size_bytes ? Number(latest.size_bytes) : null,
              checksum: latest.checksum,
              errorMessage: latest.error_message,
              retentionDeletedCount: latest.retention_deleted_count,
              retentionComplete: latest.retention_complete,
            }
          : null,
        history: attempts.map((a) => ({
          attemptReference: a.attempt_reference,
          trigger: a.trigger_type,
          status: a.status,
          startedAt: a.started_at,
          endedAt: a.ended_at,
          sizeBytes: a.size_bytes ? Number(a.size_bytes) : null,
          errorMessage: a.error_message,
          objectRetained: a.object_key !== null && a.object_retired_at === null,
          objectRetiredAt: a.object_retired_at,
        })),
        restoreValidationNote:
          'A backup that has never been restore-validated is not disaster-recovery proven. See docs/runbooks/backup-restore.md.',
      };
    });

    return c.json(data);
  },
);

adminRoutes.patch(
  '/backups/schedule',
  requireExactLevel('L3'),
  requirePermissions('admin:backups'),
  async (c) => {
    const actor = actorOf(c);
    const body = z
      .object({
        enabled: z.boolean(),
        localTime: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/).optional(),
        timezone: z.string().trim().max(60).optional(),
        retentionMaxCount: z.number().int().min(1).max(3650).optional(),
      })
      .parse(await c.req.json());

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ last_test_ok: boolean | null }[]>`
          SELECT last_test_ok FROM backup_configurations WHERE organization_id = ${actor.organizationId}
        `;
        if (!rows[0]) throw notFoundError('BACKUP_NOT_CONFIGURED', 'No backup target is configured');
        if (body.enabled && rows[0].last_test_ok !== true) {
          throw stateError(
            'BACKUP_TEST_REQUIRED',
            'Run a successful connection test before enabling a backup schedule',
          );
        }

        await tx`
          UPDATE backup_configurations
             SET schedule_enabled = ${body.enabled},
                 schedule_local_time = COALESCE(${body.localTime ?? null}, schedule_local_time),
                 schedule_timezone = COALESCE(${body.timezone ?? null}, schedule_timezone),
                 retention_max_count = COALESCE(${body.retentionMaxCount ?? null}, retention_max_count),
                 updated_by_user_id = ${actor.userId},
                 next_scheduled_run_at = CASE WHEN ${body.enabled} THEN now() ELSE next_scheduled_run_at END
           WHERE organization_id = ${actor.organizationId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'BACKUP',
          action: body.enabled ? 'backup.schedule.enabled' : 'backup.schedule.disabled',
          objectType: 'BackupConfiguration',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          correlationId: c.get('correlationId'),
          securityContext: c.get('securityContext'),
          detail: { localTime: body.localTime, retentionMaxCount: body.retentionMaxCount },
        });
      }),
    );

    return c.json({ scheduleEnabled: body.enabled });
  },
);

// ---------------------------------------------------------------------------
// Policies (spec §21) and the dynamic permission engine (AC-17)
// ---------------------------------------------------------------------------

adminRoutes.get(
  '/policies',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const policy = await withConnection(c.env, (sql) => loadPolicy(sql, actor.organizationId));
    return c.json({ policy });
  },
);

adminRoutes.patch(
  '/policies',
  requireExactLevel('L3'),
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = policySchema.partial().parse(await c.req.json());
    const correlationId = c.get('correlationId');

    const updated = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const before = await loadPolicy(tx, actor.organizationId);
        const merged = policySchema.parse({ ...before, ...body });

        await tx`
          INSERT INTO policies (
            organization_id, max_instruction_amount_cents, max_batch_total_cents,
            max_batch_instructions, high_value_threshold_cents, cooling_off_seconds,
            blocking_risk_band, allow_l1_failed_export, allow_l1_retry, max_export_rows,
            daily_disbursement_ceiling_cents, release_cutoff_local_time, holiday_dates,
            updated_by_user_id
          ) VALUES (
            ${actor.organizationId}, ${merged.maxInstructionAmountCents}, ${merged.maxBatchTotalCents},
            ${merged.maxBatchInstructions}, ${merged.highValueThresholdCents}, ${merged.coolingOffSeconds},
            ${merged.blockingRiskBand}, ${merged.allowL1FailedExport}, ${merged.allowL1Retry},
            ${merged.maxExportRows}, ${merged.dailyDisbursementCeilingCents},
            ${merged.releaseCutoffLocalTime}, ${tx.array(merged.holidayDates)}, ${actor.userId}
          )
          ON CONFLICT (organization_id) DO UPDATE SET
            max_instruction_amount_cents = EXCLUDED.max_instruction_amount_cents,
            max_batch_total_cents = EXCLUDED.max_batch_total_cents,
            max_batch_instructions = EXCLUDED.max_batch_instructions,
            high_value_threshold_cents = EXCLUDED.high_value_threshold_cents,
            cooling_off_seconds = EXCLUDED.cooling_off_seconds,
            blocking_risk_band = EXCLUDED.blocking_risk_band,
            allow_l1_failed_export = EXCLUDED.allow_l1_failed_export,
            allow_l1_retry = EXCLUDED.allow_l1_retry,
            max_export_rows = EXCLUDED.max_export_rows,
            daily_disbursement_ceiling_cents = EXCLUDED.daily_disbursement_ceiling_cents,
            release_cutoff_local_time = EXCLUDED.release_cutoff_local_time,
            holiday_dates = EXCLUDED.holiday_dates,
            updated_by_user_id = EXCLUDED.updated_by_user_id,
            updated_at = now()
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: 'policy.updated',
          objectType: 'Policy',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          previousState: before,
          newState: merged,
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { changedFields: Object.keys(body) },
        });

        return merged;
      }),
    );

    return c.json({ policy: updated });
  },
);

/**
 * GET /api/admin/permissions — the dynamic permission engine's state: baseline matrix,
 * live overrides (versioned), effective matrix, and the immutable ceilings as data for
 * the admin UI (the engine applies them in code — this display cannot bypass them).
 */
adminRoutes.get(
  '/permissions',
  requireExactLevel('L3'),
  requirePermissions('admin:permissions'),
  async (c) => {
    const actor = actorOf(c);
    const data = await withConnection(c.env, async (sql) => {
      const overrides = await listOverrides(sql, actor.organizationId);
      const matrix = await loadEffectiveMatrix(sql, actor.organizationId);
      return {
        baseline: Object.fromEntries(
          AUTHORITY_LEVELS.map((level) => [level, [...baselinePermissions(level)].sort()]),
        ),
        effective: Object.fromEntries(
          AUTHORITY_LEVELS.map((level) => [level, [...matrix[level]].sort()]),
        ),
        ceilings: GRANT_CEILINGS,
        overrides: overrides.map((o) => ({
          id: o.id,
          level: o.level,
          permission: o.permission,
          effect: o.effect,
          version: o.version,
          reason: o.reason,
          grantedByUserId: o.granted_by_user_id,
          createdAt: o.created_at,
          superseded: o.superseded,
        })),
        catalogue: PERMISSIONS,
      };
    });
    return c.json(data);
  },
);

const overrideSchema = z.object({
  level: z.enum(['L1', 'L2']),
  permission: z.string(),
  effect: z.enum(['GRANT', 'REVOKE']),
  reason: z.string().trim().min(3).max(500),
});

/**
 * POST /api/admin/permissions/overrides — grant or revoke an L1/L2 capability (AC-17).
 *
 * Every change: validated against the immutable ceilings, versioned, audited as a
 * high-severity AUTHORITY event, and effective on the very next request. L3 authority
 * itself is not configurable — the engine refuses it outright.
 */
adminRoutes.post(
  '/permissions/overrides',
  requireExactLevel('L3'),
  requirePermissions('admin:permissions'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    assertWebAuthnSession(actor);
    const body = overrideSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    // The engine's own validation: ceiling breaches and unknown permissions refuse here.
    assertValidOverride({ level: body.level, permission: body.permission, effect: body.effect });

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const versionRow = await tx<{ version: number }[]>`
          SELECT COALESCE(MAX(version), 0) + 1 AS version FROM permission_policy_versions
           WHERE organization_id = ${actor.organizationId}
        `;
        const version = Number(versionRow[0]!.version);

        await tx`
          INSERT INTO permission_policy_versions (organization_id, version, created_by_user_id, note)
          VALUES (${actor.organizationId}, ${version}, ${actor.userId},
                  ${`Override ${body.effect} ${body.permission} for ${body.level}`})
        `;

        // Supersede any live override on the same key, then insert the new one.
        await tx`
          UPDATE permission_overrides
             SET superseded_by_id = '00000000-0000-0000-0000-000000000000'
           WHERE organization_id = ${actor.organizationId}
             AND level = ${body.level} AND permission = ${body.permission}
             AND superseded_by_id IS NULL
        `;
        const inserted = await tx<{ id: string }[]>`
          INSERT INTO permission_overrides (
            organization_id, level, permission, effect, version, reason, granted_by_user_id
          ) VALUES (
            ${actor.organizationId}, ${body.level}, ${body.permission}, ${body.effect},
            ${version}, ${body.reason}, ${actor.userId}
          )
          RETURNING id
        `;
        // Point the superseded rows at the real successor now that its id exists.
        await tx`
          UPDATE permission_overrides
             SET superseded_by_id = ${inserted[0]!.id}
           WHERE organization_id = ${actor.organizationId}
             AND level = ${body.level} AND permission = ${body.permission}
             AND superseded_by_id = '00000000-0000-0000-0000-000000000000'
             AND id <> ${inserted[0]!.id}
        `;

        // Recompute the effective matrix inside the same transaction so the audit event
        // records exactly what the organisation's permissions became.
        const live = await tx<{ level: 'L1' | 'L2'; permission: string; effect: 'GRANT' | 'REVOKE'; version: number; reason: string; granted_by_user_id: string }[]>`
          SELECT level, permission, effect, version, reason, granted_by_user_id
            FROM permission_overrides
           WHERE organization_id = ${actor.organizationId} AND superseded_by_id IS NULL
        `;
        const effective = effectivePermissions(
          live.map((o) => ({
            level: o.level,
            permission: o.permission as never,
            effect: o.effect,
            version: o.version,
            reason: o.reason,
            grantedByUserId: o.granted_by_user_id,
          })),
        );

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'permission.override.applied',
          objectType: 'PermissionOverride',
          objectId: inserted[0]!.id,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            override: { level: body.level, permission: body.permission, effect: body.effect },
            reason: body.reason,
            policyVersion: version,
            effectiveL1: [...effective.L1].sort(),
            effectiveL2: [...effective.L2].sort(),
            diff: describeOverrideChange(
              live.map((o) => ({
                level: o.level,
                permission: o.permission as never,
                effect: o.effect,
                version: o.version,
                reason: o.reason,
                grantedByUserId: o.granted_by_user_id,
              })),
            ),
          },
        });

        return { overrideId: inserted[0]!.id, policyVersion: version };
      }),
    );

    return c.json(
      {
        applied: true,
        overrideId: result.overrideId,
        policyVersion: result.policyVersion,
        note: 'The change is live immediately: every request recomputes the effective matrix.',
      },
      201,
    );
  },
);

/** POST /api/admin/permissions/reset — restore the baseline matrix (audited). */
adminRoutes.post(
  '/permissions/reset',
  requireExactLevel('L3'),
  requirePermissions('admin:permissions'),
  async (c) => {
    const actor = actorOf(c);
    assertFreshAuthentication(actor);
    const body = z.object({ reason: z.string().trim().min(3).max(500) }).parse(await c.req.json());
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const versionRow = await tx<{ version: number }[]>`
          SELECT COALESCE(MAX(version), 0) + 1 AS version FROM permission_policy_versions
           WHERE organization_id = ${actor.organizationId}
        `;
        const version = Number(versionRow[0]!.version);

        await tx`
          UPDATE permission_overrides
             SET superseded_by_id = '00000000-0000-0000-0000-000000000000'
           WHERE organization_id = ${actor.organizationId} AND superseded_by_id IS NULL
             AND level IN ('L1', 'L2')
        `;
        const marker = await tx<{ id: string }[]>`
          INSERT INTO permission_overrides (
            organization_id, level, permission, effect, version, reason, granted_by_user_id
          ) VALUES (
            ${actor.organizationId}, 'L1', 'batch:read', 'GRANT', ${version},
            ${`Reset marker: ${body.reason}`}, ${actor.userId}
          )
          RETURNING id
        `;
        await tx`
          UPDATE permission_overrides
             SET superseded_by_id = ${marker[0]!.id}
           WHERE organization_id = ${actor.organizationId}
             AND superseded_by_id = '00000000-0000-0000-0000-000000000000'
             AND id <> ${marker[0]!.id}
        `;
        await tx`DELETE FROM permission_overrides WHERE id = ${marker[0]!.id}`;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'AUTHORITY',
          action: 'permission.overrides.reset',
          objectType: 'PermissionOverride',
          objectId: actor.organizationId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { reason: body.reason, note: 'All overrides superseded; baseline matrix restored.' },
        });
      }),
    );

    return c.json({ reset: true });
  },
);

// ---------------------------------------------------------------------------
// Batch templates + financial calendar (spec §10)
// ---------------------------------------------------------------------------

const templateSchema = z.object({
  name: z.string().trim().min(3).max(100),
  purpose: z.string().trim().min(3).max(200),
  paymentPeriodPattern: z.string().trim().max(60).optional(),
  departmentId: z.string().uuid().optional(),
  /** Local EAT "HH:MM" — translated to a UTC cron by the server. */
  scheduleLocalTime: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/),
  items: z
    .array(
      z.object({
        recipientId: z.string().uuid(),
        amountCents: z.number().int().min(1000).max(25_000_000),
        remarks: z.string().max(100).optional(),
      }),
    )
    .min(1)
    .max(5000),
});

adminRoutes.post(
  '/templates',
  requirePermissions('admin:templates'),
  async (c) => {
    const actor = actorOf(c);
    const body = templateSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    // Daily at the local time → UTC cron via the EAT offset (UTC+3, no DST).
    const [h, m] = body.scheduleLocalTime.split(':').map(Number);
    const cron = `${m} ${((h ?? 2) - 3 + 24) % 24} * * *`;
    if (!isValidCron(cron)) {
      throw validationError('CRON_INVALID', 'The schedule could not be translated to a valid cron');
    }

    const created = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string }[]>`
          INSERT INTO batch_templates (
            organization_id, name, purpose, payment_period_pattern, department_id,
            schedule_cron, schedule_enabled, next_run_at, created_by_user_id
          ) VALUES (
            ${actor.organizationId}, ${body.name}, ${body.purpose},
            ${body.paymentPeriodPattern ?? null}, ${body.departmentId ?? null},
            ${cron}, FALSE, ${nextRun(cron)}, ${actor.userId}
          )
          RETURNING id
        `;
        const templateId = rows[0]!.id;

        for (const item of body.items) {
          await tx`
            INSERT INTO batch_template_items (template_id, recipient_id, amount_cents, remarks)
            VALUES (${templateId}, ${item.recipientId}, ${item.amountCents},
                    ${item.remarks ?? 'Business payment'})
          `;
        }

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: 'template.created',
          objectType: 'BatchTemplate',
          objectId: templateId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { name: body.name, cron, itemCount: body.items.length, enabled: false },
        });

        return { templateId };
      }),
    );

    return c.json({ templateId: created.templateId, scheduleCron: cron, enabled: false }, 201);
  },
);

adminRoutes.get('/templates', requirePermissions('admin:templates'), async (c) => {
  const actor = actorOf(c);
  const templates = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        name: string;
        purpose: string;
        schedule_cron: string;
        schedule_enabled: boolean;
        next_run_at: string | null;
        last_materialized_at: string | null;
        item_count: string;
      }[]
    >`
      SELECT t.id, t.name, t.purpose, t.schedule_cron, t.schedule_enabled,
             t.next_run_at, t.last_materialized_at,
             (SELECT COUNT(*) FROM batch_template_items WHERE template_id = t.id) AS item_count
        FROM batch_templates t
       WHERE t.organization_id = ${actor.organizationId}
       ORDER BY t.name
    `,
  );
  return c.json({
    templates: templates.map((t) => ({
      templateId: t.id,
      name: t.name,
      purpose: t.purpose,
      scheduleCron: t.schedule_cron,
      scheduleEnabled: t.schedule_enabled,
      nextRunAt: t.next_run_at,
      lastMaterializedAt: t.last_materialized_at,
      itemCount: Number(t.item_count),
    })),
  });
});

adminRoutes.patch(
  '/templates/:id',
  requirePermissions('admin:templates'),
  async (c) => {
    const actor = actorOf(c);
    const templateId = c.req.param('id');
    const body = z
      .object({ enabled: z.boolean() })
      .parse(await c.req.json());
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ schedule_cron: string }[]>`
          SELECT schedule_cron FROM batch_templates
           WHERE id = ${templateId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        if (!rows[0]) throw notFoundError('TEMPLATE_NOT_FOUND', 'That template could not be found');

        await tx`
          UPDATE batch_templates
             SET schedule_enabled = ${body.enabled},
                 next_run_at = CASE WHEN ${body.enabled} THEN ${nextRun(rows[0].schedule_cron)} ELSE next_run_at END
           WHERE id = ${templateId}
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: body.enabled ? 'template.enabled' : 'template.disabled',
          objectType: 'BatchTemplate',
          objectId: templateId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {},
        });
      }),
    );

    return c.json({ scheduleEnabled: body.enabled });
  },
);

const calendarSchema = z.object({
  kind: z.enum(['HOLIDAY', 'BLACKOUT', 'CUTOFF_OVERRIDE']),
  localDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  description: z.string().trim().max(200).optional(),
});

adminRoutes.post(
  '/calendar',
  requirePermissions('admin:policies'),
  async (c) => {
    const actor = actorOf(c);
    const body = calendarSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        await tx`
          INSERT INTO payment_calendar (organization_id, kind, local_date, description, created_by_user_id)
          VALUES (${actor.organizationId}, ${body.kind}, ${body.localDate}, ${body.description ?? null}, ${actor.userId})
          ON CONFLICT (organization_id, kind, local_date) DO UPDATE
            SET description = EXCLUDED.description
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'ADMINISTRATION',
          action: 'calendar.updated',
          objectType: 'PaymentCalendar',
          objectId: body.localDate,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: body,
        });
      }),
    );

    return c.json({ added: true }, 201);
  },
);

function nowIso(): Date {
  return new Date();
}

