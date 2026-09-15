/**
 * Authentication routes (spec §7, §8).
 *
 * There is no SMS endpoint here, and no way to add one without changing the schema: there
 * is no phone column on any identity table, and the invariant checker fails CI if one
 * appears. Recovery consumes a stored recovery code (redeemed here — the full flow the
 * previous system never finished) or goes through administrative recovery via the L3
 * users API.
 *
 * Login is two-staged for L2/L3 because WebAuthn is mandatory at those levels (spec
 * §7.3): the password stage returns a short-lived challenge ticket and *no session*, so
 * a stolen password alone yields nothing that can read financial data.
 *
 * The step-up endpoint (spec §8.2) is the relief valve for the five-minute freshness
 * gate: password + WebAuthn re-verification refreshes `sessions.authenticated_at`
 * in place, so a release ceremony never requires a full logout-and-login.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import {
  authenticationError,
  validationError,
  capabilitiesFor,
  randomToken,
  LEVEL_TITLES,
} from '@solvaren/core';
import {
  verifyPasswordStage,
  issueSession,
  revokeSession,
  revokeAllSessions,
  deriveDeviceFingerprint,
  toActor,
  type UserRow,
} from '../services/auth.js';
import {
  hashAuthorizationPin,
  assertPinShape,
  verifyPassword,
  generateRecoveryCode,
  hashSessionToken,
} from '../services/crypto.js';
import { requireAuth, actorOf, limitBodySize, rateLimit } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadEffectiveMatrix } from '../services/permissions.js';
import type { AppContext, Env } from '../env.js';

/** The transports a credential may declare (matches @simplewebauthn/types locally). */
type Transport = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb';

export const authRoutes = new Hono<AppContext>();

authRoutes.use('*', limitBodySize(16 * 1024));

const loginSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(1024),
  deviceId: z.string().max(200).optional(),
});

/**
 * POST /api/auth/login — stage one.
 *
 * L1 receives a session. L2 and L3 receive a WebAuthn challenge and must complete
 * `/api/auth/webauthn/authenticate` before any session exists.
 */
authRoutes.post('/login', rateLimit('ip', { ratePerSecond: 0.2, burst: 10 }), async (c) => {
  const body = loginSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    let stage;
    try {
      stage = await verifyPasswordStage(sql, {
        email: body.email,
        password: body.password,
        deviceFingerprint: security.deviceFingerprint,
        ip: security.ip,
        userAgent: security.userAgent,
      });
    } catch (err) {
      // Failed logins are security evidence in their own right (spec §14).
      await sql`
        INSERT INTO security_events (event_type, severity, description, ip, user_agent, detail)
        VALUES ('LOGIN_FAILED', 'INFO', ${'A sign-in attempt failed'}, ${security.ip},
                ${security.userAgent}, ${sql.json({ email: body.email.slice(0, 3) + '***' })})
      `.catch(() => {});
      throw err;
    }

    const { user, requiresWebAuthn } = stage;
    const deviceFingerprint = await deriveDeviceFingerprint(body.deviceId ?? null, security.userAgent);

    if (requiresWebAuthn) {
      const credentials = await sql<{ credential_id: string; transports: string[] }[]>`
        SELECT credential_id, transports FROM webauthn_credentials
         WHERE user_id = ${user.id} AND status = 'ACTIVE'
      `;
      if (credentials.length === 0) {
        // First sign-in of a privileged account, or recovery of a keyless one: the
        // passkey enrolment is mandatory and happens NOW. Issue a short-lived
        // enrolment-only session — no WebAuthn verification, so every privileged action
        // refuses it; its entire power is registering a first key (and, if the account has
        // no PIN yet, setting one). If the officer abandons the prompt, the session
        // expires in 15 minutes, the account stays PENDING_ENROLMENT, and the next
        // sign-in lands here again.
        const enrolmentToken = randomToken(32);
        const tokenHash = await hashSessionToken(enrolmentToken, c.env.SESSION_SIGNING_KEY);
        const now = new Date();
        const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);
        await sql`
          INSERT INTO sessions (
            organization_id, user_id, token_hash, authenticated_at, issued_at, expires_at, ip, user_agent
          ) VALUES (
            ${user.organization_id}, ${user.id}, ${tokenHash}, ${now}, ${now}, ${expiresAt},
            ${security.ip}, ${security.userAgent}
          )
        `;
        await sql`
          INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
          VALUES (${user.organization_id}, ${user.id}, 'WEBAUTHN_ENROLMENT_SESSION_ISSUED', 'INFO',
                  ${'A mandatory enrolment session was issued at first sign-in'}, ${security.ip}, ${sql.json({})})
        `;

        return {
          stage: 'ENROLMENT_REQUIRED' as const,
          token: enrolmentToken,
          expiresAt: expiresAt.toISOString(),
          level: user.authority_level,
        };
      }

      const options = await generateAuthenticationOptions({
        rpID: c.env.WEBAUTHN_RP_ID,
        userVerification: 'required',
        allowCredentials: credentials.map((cred) => ({
          id: cred.credential_id,
          transports: cred.transports as Transport[],
        })),
      });

      // The challenge is held server-side, keyed by a single-use ticket. Nothing the
      // client holds can be replayed into a session.
      const ticket = randomToken(32);
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${user.organization_id}, ${user.id}, 'WEBAUTHN_CHALLENGE_ISSUED', 'INFO',
                ${'A WebAuthn challenge was issued during sign-in'}, ${security.ip},
                ${sql.json({ challenge: options.challenge, ticket, deviceFingerprint })})
      `;

      return {
        stage: 'WEBAUTHN_REQUIRED' as const,
        ticket,
        options,
        level: user.authority_level,
      };
    }

    // L1: password is sufficient for identity, and L1 cannot release money.
    const session = await issueSession(sql, c.env.SESSION_SIGNING_KEY, {
      user,
      trustedDeviceId: null,
      webauthnVerified: false,
      ip: security.ip,
      userAgent: security.userAgent,
    });

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.login',
        objectType: 'User',
        objectId: user.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { method: 'password', level: user.authority_level },
      }),
    );

    return {
      stage: 'AUTHENTICATED' as const,
      token: session.token,
      expiresAt: session.expiresAt.toISOString(),
      user: await publicUser(sql, user),
    };
  });

  return c.json(result);
});

const webauthnAuthSchema = z.object({
  ticket: z.string().min(16).max(64),
  response: z.record(z.unknown()),
  deviceId: z.string().max(200).optional(),
});

/**
 * POST /api/auth/webauthn/authenticate — stage two for L2/L3.
 *
 * Verifies the assertion and only then issues a session. The signature counter is
 * checked: a counter that fails to advance indicates a cloned authenticator, which is a
 * CRITICAL security event rather than a successful sign-in.
 */
authRoutes.post('/webauthn/authenticate', async (c) => {
  const body = webauthnAuthSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    const events = await sql<
      {
        id: string;
        organization_id: string;
        user_id: string;
        detail: { challenge: string; ticket: string };
        created_at: string;
      }[]
    >`
      SELECT id, organization_id, user_id, detail, created_at
        FROM security_events
       WHERE event_type = 'WEBAUTHN_CHALLENGE_ISSUED'
         AND detail->>'ticket' = ${body.ticket}
         AND created_at > now() - interval '5 minutes'
       ORDER BY created_at DESC
       LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw authenticationError('WEBAUTHN_CHALLENGE_EXPIRED', 'That sign-in attempt expired. Start again.');
    }

    const response = body.response as Record<string, unknown> & { id?: string };
    const credentialId = typeof response.id === 'string' ? response.id : '';

    const credentials = await sql<
      {
        id: string;
        credential_id: string;
        public_key: Uint8Array;
        signature_counter: string;
        transports: string[];
      }[]
    >`
      SELECT id, credential_id, public_key, signature_counter, transports
        FROM webauthn_credentials
       WHERE user_id = ${pending.user_id} AND credential_id = ${credentialId} AND status = 'ACTIVE'
       LIMIT 1
    `;
    const credential = credentials[0];
    if (!credential) {
      throw authenticationError('WEBAUTHN_CREDENTIAL_UNKNOWN', 'That authenticator is not registered to this account');
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.response as never,
        expectedChallenge: pending.detail.challenge,
        expectedOrigin: c.env.APP_ORIGIN,
        expectedRPID: c.env.WEBAUTHN_RP_ID,
        requireUserVerification: true,
        authenticator: {
          credentialID: credential.credential_id,
          credentialPublicKey: new Uint8Array(credential.public_key),
          counter: Number(credential.signature_counter),
          transports: credential.transports as Transport[],
        },
      });
    } catch (err) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${pending.organization_id}, ${pending.user_id}, 'WEBAUTHN_VERIFICATION_FAILED', 'WARNING',
                ${'A WebAuthn assertion failed verification'}, ${security.ip},
                ${sql.json({ error: err instanceof Error ? err.message : 'unknown' })})
      `;
      throw authenticationError('WEBAUTHN_VERIFICATION_FAILED', 'The security key verification failed');
    }

    if (!verification.verified) {
      throw authenticationError('WEBAUTHN_VERIFICATION_FAILED', 'The security key verification failed');
    }

    // Cloned-authenticator detection. Both counters at zero is normal for some platform
    // authenticators; a counter that goes backwards is not.
    const newCounter = verification.authenticationInfo.newCounter;
    const storedCounter = Number(credential.signature_counter);
    if (newCounter !== 0 && newCounter <= storedCounter) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${pending.organization_id}, ${pending.user_id}, 'WEBAUTHN_COUNTER_REGRESSION', 'CRITICAL',
                ${'An authenticator signature counter did not advance, which can indicate a cloned key'},
                ${security.ip}, ${sql.json({ storedCounter, newCounter })})
      `;
      throw authenticationError(
        'WEBAUTHN_COUNTER_REGRESSION',
        'This security key failed an integrity check and cannot be used. Contact your administrator.',
      );
    }

    await sql`
      UPDATE webauthn_credentials
         SET signature_counter = ${newCounter}, last_used_at = now()
       WHERE id = ${credential.id}
    `;

    const users = await sql<UserRow[]>`
      SELECT id, organization_id, email, full_name, authority_level, status, password_hash,
             authorization_pin_hash, failed_login_count, locked_until
        FROM users WHERE id = ${pending.user_id} LIMIT 1
    `;
    const user = users[0]!;

    // Register or refresh the trusted device binding (spec §8.1).
    const deviceFingerprint = await deriveDeviceFingerprint(body.deviceId ?? null, security.userAgent);
    let trustedDeviceId: string | null = null;
    if (deviceFingerprint) {
      const devices = await sql<{ id: string; trust_status: string }[]>`
        INSERT INTO trusted_devices (
          organization_id, user_id, device_fingerprint, webauthn_credential_id,
          trust_status, first_seen_ip, last_seen_ip, user_agent
        ) VALUES (
          ${user.organization_id}, ${user.id}, ${deviceFingerprint}, ${credential.id},
          'TRUSTED', ${security.ip}, ${security.ip}, ${security.userAgent}
        )
        ON CONFLICT (user_id, device_fingerprint) DO UPDATE
          SET last_activity_at = now(), last_seen_ip = EXCLUDED.last_seen_ip
        RETURNING id, trust_status
      `;
      if (devices[0]?.trust_status === 'BLOCKED' || devices[0]?.trust_status === 'REVOKED') {
        throw authenticationError('DEVICE_BLOCKED', 'This device is not permitted to access SOLVAREN');
      }
      trustedDeviceId = devices[0]?.id ?? null;
    }

    // Burn the pending challenge so the ticket cannot be reused.
    await sql`UPDATE security_events SET detail = detail - 'ticket' WHERE id = ${pending.id}`;

    const session = await issueSession(sql, c.env.SESSION_SIGNING_KEY, {
      user,
      trustedDeviceId,
      webauthnVerified: true,
      ip: security.ip,
      userAgent: security.userAgent,
    });

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'IDENTITY',
        action: 'auth.login.webauthn',
        objectType: 'User',
        objectId: user.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { credentialId: credential.id, trustedDeviceId, level: user.authority_level },
      }),
    );

    return {
      stage: 'AUTHENTICATED' as const,
      token: session.token,
      expiresAt: session.expiresAt.toISOString(),
      user: await publicUser(sql, user),
    };
  });

  return c.json(result);
});

// ---------------------------------------------------------------------------
// Step-up authentication (spec §8.2) — the freshness relief valve.
// ---------------------------------------------------------------------------

const stepUpSchema = z.object({
  password: z.string().min(1).max(1024),
  webauthnResponse: z.record(z.unknown()).optional(),
});

/**
 * POST /api/auth/step-up — refresh the session's authenticated_at.
 *
 * Requires the password AND, for L2/L3 (the only levels that can act on a fresh-auth
 * gate), a WebAuthn assertion over a fresh challenge. On success the existing session's
 * freshness timestamp advances, without issuing a new token — so all other tabs keep
 * working and the audit trail shows one continuous session stepping up.
 */
authRoutes.post('/step-up', requireAuth, rateLimit('actor', { ratePerSecond: 0.1, burst: 5 }), async (c) => {
  const actor = actorOf(c);
  const body = stepUpSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const outcome = await withConnection(c.env, async (sql) => {
    const users = await sql<UserRow[]>`
      SELECT id, organization_id, email, full_name, authority_level, status, password_hash,
             authorization_pin_hash, failed_login_count, locked_until
        FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    const user = users[0];
    if (!user || !(await verifyPassword(body.password, user.password_hash))) {
      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'SECURITY',
          action: 'auth.step_up.denied',
          objectType: 'Session',
          objectId: actor.sessionId,
          outcome: 'DENIED',
          correlationId,
          securityContext: security,
          detail: { reason: 'password' },
        }),
      );
      throw authenticationError('PASSWORD_INCORRECT', 'Your password was not correct');
    }

    // L1 sessions may step up with the password alone; privileged levels must re-touch
    // the authenticator.
    if (user.authority_level !== 'L1') {
      if (!body.webauthnResponse) {
        throw authenticationError(
          'WEBAUTHN_REQUIRED',
          'Confirming your identity requires your security key. Complete the passkey prompt and try again.',
        );
      }
      const verified = await verifyStepUpAssertion(
        sql,
        c.env,
        user.id,
        body.webauthnResponse as Record<string, unknown> & { id?: string },
      );
      if (!verified) {
        await inTransaction(sql, (tx) =>
          writeAuditEvent(tx, {
            organizationId: actor.organizationId,
            actorId: actor.userId,
            actorLevel: actor.level,
            eventClass: 'SECURITY',
            action: 'auth.step_up.denied',
            objectType: 'Session',
            objectId: actor.sessionId,
            outcome: 'DENIED',
            correlationId,
            securityContext: security,
            detail: { reason: 'webauthn' },
          }),
        );
        throw authenticationError('WEBAUTHN_VERIFICATION_FAILED', 'The security key verification failed');
      }
    }

    await sql`
      UPDATE sessions
         SET authenticated_at = now()
       WHERE id = ${actor.sessionId} AND revoked_at IS NULL
    `;

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.step_up.completed',
        objectType: 'Session',
        objectId: actor.sessionId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { level: actor.level },
      }),
    );

    return { steppedUp: true as const, authenticatedAt: new Date().toISOString() };
  });

  return c.json(outcome);
});

/** Generate + verify a one-shot step-up WebAuthn challenge inside one request cycle. */
async function verifyStepUpAssertion(
  sql: Parameters<Parameters<typeof withConnection>[1]>[0],
  env: Env,
  userId: string,
  response: Record<string, unknown> & { id?: string },
): Promise<boolean> {
  const credentials = await sql<{ credential_id: string; transports: string[] }[]>`
    SELECT credential_id, transports FROM webauthn_credentials
     WHERE user_id = ${userId} AND status = 'ACTIVE'
  `;
  if (credentials.length === 0) return false;

  const options = await generateAuthenticationOptions({
    rpID: env.WEBAUTHN_RP_ID,
    userVerification: 'required',
    allowCredentials: credentials.map((cred) => ({
      id: cred.credential_id,
      transports: cred.transports as Transport[],
    })),
  });
  const expectedChallenge = options.challenge;

  const credentialId = typeof response.id === 'string' ? response.id : '';
  const rows = await sql<
    { id: string; credential_id: string; public_key: Uint8Array; signature_counter: string; transports: string[] }[]
  >`
    SELECT id, credential_id, public_key, signature_counter, transports
      FROM webauthn_credentials
     WHERE user_id = ${userId} AND credential_id = ${credentialId} AND status = 'ACTIVE'
     LIMIT 1
  `;
  const credential = rows[0];
  if (!credential) return false;

  try {
    const verification = await verifyAuthenticationResponse({
      response: response as never,
      expectedChallenge,
      expectedOrigin: env.APP_ORIGIN,
      expectedRPID: env.WEBAUTHN_RP_ID,
      requireUserVerification: true,
      authenticator: {
        credentialID: credential.credential_id,
        credentialPublicKey: new Uint8Array(credential.public_key),
        counter: Number(credential.signature_counter),
        transports: credential.transports as Transport[],
      },
    });
    if (!verification.verified) return false;
    const newCounter = verification.authenticationInfo.newCounter;
    const stored = Number(credential.signature_counter);
    if (newCounter !== 0 && newCounter <= stored) return false; // cloned key — refuse
    await sql`
      UPDATE webauthn_credentials
         SET signature_counter = ${newCounter}, last_used_at = now()
       WHERE id = ${credential.id}
    `;
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// WebAuthn enrolment
// ---------------------------------------------------------------------------

/** POST /api/auth/webauthn/register/options — begin enrolling an authenticator. */
authRoutes.post('/webauthn/register/options', requireAuth, async (c) => {
  const actor = actorOf(c);

  const options = await withConnection(c.env, async (sql) => {
    const existing = await sql<{ credential_id: string }[]>`
      SELECT credential_id FROM webauthn_credentials WHERE user_id = ${actor.userId} AND status = 'ACTIVE'
    `;

    const generated = await generateRegistrationOptions({
      rpName: c.env.WEBAUTHN_RP_NAME,
      rpID: c.env.WEBAUTHN_RP_ID,
      userName: actor.email,
      userDisplayName: actor.fullName,
      attestationType: 'none',
      // Prevents enrolling the same authenticator twice, which would silently halve the
      // value of a "two keys registered" policy.
      excludeCredentials: existing.map((e) => ({ id: e.credential_id })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });

    await sql`
      INSERT INTO security_events (organization_id, user_id, event_type, severity, description, detail)
      VALUES (${actor.organizationId}, ${actor.userId}, 'WEBAUTHN_REGISTRATION_STARTED', 'INFO',
              ${'An authenticator enrolment was started'},
              ${sql.json({ challenge: generated.challenge })})
    `;
    return generated;
  });

  return c.json(options);
});

/** POST /api/auth/webauthn/register — complete enrolment. */
authRoutes.post('/webauthn/register', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ response: z.record(z.unknown()), friendlyName: z.string().trim().max(80).optional() })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, async (sql) => {
    const events = await sql<{ detail: { challenge: string } }[]>`
      SELECT detail FROM security_events
       WHERE user_id = ${actor.userId} AND event_type = 'WEBAUTHN_REGISTRATION_STARTED'
         AND created_at > now() - interval '10 minutes'
       ORDER BY created_at DESC LIMIT 1
    `;
    const pending = events[0];
    if (!pending) {
      throw validationError('WEBAUTHN_REGISTRATION_EXPIRED', 'That enrolment expired. Start again.');
    }

    const verification = await verifyRegistrationResponse({
      response: body.response as never,
      expectedChallenge: pending.detail.challenge,
      expectedOrigin: c.env.APP_ORIGIN,
      expectedRPID: c.env.WEBAUTHN_RP_ID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw validationError('WEBAUTHN_REGISTRATION_FAILED', 'The authenticator could not be registered');
    }

    const info = verification.registrationInfo;
    await inTransaction(sql, async (tx) => {
      await tx`
        INSERT INTO webauthn_credentials (
          organization_id, user_id, credential_id, public_key, signature_counter,
          transports, device_type, backed_up, friendly_name, aaguid
        ) VALUES (
          ${actor.organizationId}, ${actor.userId}, ${info.credentialID},
          ${Buffer.from(info.credentialPublicKey)}, ${info.counter},
          ${sql`'{}'::text[]`}, ${info.credentialDeviceType === 'multiDevice' ? 'PLATFORM' : 'CROSS_PLATFORM'},
          ${info.credentialBackedUp}, ${body.friendlyName ?? 'Security key'}, ${info.aaguid ?? null}
        )
      `;
      // Enrolling a first authenticator completes enrolment for a pending account.
      await tx`UPDATE users SET status = 'ACTIVE' WHERE id = ${actor.userId} AND status = 'PENDING_ENROLMENT'`;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.webauthn.registered',
        objectType: 'WebAuthnCredential',
        objectId: info.credentialID,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          friendlyName: body.friendlyName,
          deviceType: info.credentialDeviceType,
          backedUp: info.credentialBackedUp,
        },
      });
    });

    // The console uses this to decide what the officer must do next: an account that
    // already has a PIN (admin-created) goes straight to a normal sign-in; one without
    // (bootstrap) must set its Frontier Authorization PIN before it can act.
    const pinRows = await withConnection(c.env, (sql) =>
      sql<{ pin_enrolled: boolean }[]>`
        SELECT authorization_pin_hash IS NOT NULL AS pin_enrolled
          FROM users WHERE id = ${actor.userId} LIMIT 1
      `,
    );

    return {
      registered: true as const,
      credentialId: info.credentialID,
      authorizationPinEnrolled: pinRows[0]?.pin_enrolled ?? false,
    };
  });

  return c.json(result, 201);
});

// ---------------------------------------------------------------------------
// FPAC PIN management
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/authorization-pin — set or change the FPAC PIN (spec §7.4).
 * Requires the current password: the PIN is a second factor of authority, so changing it
 * must not be possible from a hijacked session alone.
 */
authRoutes.post('/authorization-pin', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ currentPassword: z.string().min(1).max(1024), pin: z.string().min(6).max(12) })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  assertPinShape(body.pin);

  await withConnection(c.env, async (sql) => {
    const users = await sql<{ password_hash: string }[]>`
      SELECT password_hash FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    if (!users[0] || !(await verifyPassword(body.currentPassword, users[0].password_hash))) {
      throw authenticationError('PASSWORD_INCORRECT', 'Your current password was not correct');
    }

    const hash = await hashAuthorizationPin(body.pin, actor.userId);
    await inTransaction(sql, async (tx) => {
      await tx`
        UPDATE users SET authorization_pin_hash = ${hash}, authorization_pin_updated_at = now()
         WHERE id = ${actor.userId}
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.authorization_pin.set',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        // The PIN itself never appears here; `redactForAudit` would strip it anyway.
        detail: { rotated: true },
      });
    });
  });

  return c.json({ updated: true });
});

// ---------------------------------------------------------------------------
// Recovery — the full redeem flow (spec §8.3)
// ---------------------------------------------------------------------------

/** POST /api/auth/recovery-codes — regenerate recovery codes. Shown once, stored hashed. */
authRoutes.post('/recovery-codes', requireAuth, async (c) => {
  const actor = actorOf(c);
  const body = z.object({ currentPassword: z.string().min(1).max(1024) }).parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const codes = await withConnection(c.env, async (sql) => {
    const users = await sql<{ password_hash: string }[]>`
      SELECT password_hash FROM users WHERE id = ${actor.userId} LIMIT 1
    `;
    if (!users[0] || !(await verifyPassword(body.currentPassword, users[0].password_hash))) {
      throw authenticationError('PASSWORD_INCORRECT', 'Your current password was not correct');
    }

    const generated = Array.from({ length: 10 }, () => generateRecoveryCode());
    await inTransaction(sql, async (tx) => {
      // Regenerating invalidates the previous set: two live sets doubles the attack surface.
      await tx`UPDATE recovery_codes SET consumed_at = now() WHERE user_id = ${actor.userId} AND consumed_at IS NULL`;
      for (const code of generated) {
        const hash = await hashSessionToken(code, c.env.SESSION_SIGNING_KEY);
        await tx`
          INSERT INTO recovery_codes (organization_id, user_id, code_hash)
          VALUES (${actor.organizationId}, ${actor.userId}, ${hash})
        `;
      }
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.recovery_codes.regenerated',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { count: generated.length },
      });
    });
    return generated;
  });

  return c.json({
    codes,
    note: 'Store these somewhere safe. They are shown once and cannot be retrieved again. SOLVAREN never sends recovery codes by SMS.',
  });
});

const redeemSchema = z.object({
  email: z.string().trim().email().max(320),
  password: z.string().min(1).max(1024),
  recoveryCode: z.string().trim().min(20).max(30),
});

/**
 * POST /api/auth/recovery/redeem — recover access with password + one recovery code.
 *
 * Two independent factors (password + a single-use code that only the legitimate user
 * could hold) unlock a "reset session": authenticated, but flagged so that every
 * privileged action — release, Daraja, policies — refuses it until a new WebAuthn
 * credential is enrolled. The reset session CAN register a new authenticator and set a
 * new PIN; that is its entire power. This is the controlled recovery path spec §8.3
 * describes, with the financial authorization boundary intact throughout.
 */
authRoutes.post('/recovery/redeem', rateLimit('ip', { ratePerSecond: 0.05, burst: 5 }), async (c) => {
  const body = redeemSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');
  const security = c.get('securityContext');

  const result = await withConnection(c.env, async (sql) => {
    const stage = await verifyPasswordStage(sql, {
      email: body.email,
      password: body.password,
      deviceFingerprint: null,
      ip: security.ip,
      userAgent: security.userAgent,
    });
    const user = stage.user;

    const codeHash = await hashSessionToken(body.recoveryCode.trim().toUpperCase(), c.env.SESSION_SIGNING_KEY);
    const redeemed = await sql<{ id: string }[]>`
      UPDATE recovery_codes
         SET consumed_at = now(), consumed_ip = ${security.ip}
       WHERE user_id = ${user.id} AND code_hash = ${codeHash} AND consumed_at IS NULL
      RETURNING id
    `;
    if (redeemed.length === 0) {
      await sql`
        INSERT INTO security_events (organization_id, user_id, event_type, severity, description, ip, detail)
        VALUES (${user.organization_id}, ${user.id}, 'RECOVERY_CODE_REDEEM_FAILED', 'CRITICAL',
                ${'A recovery-code redemption failed after a correct password'}, ${security.ip}, ${sql.json({})})
      `;
      throw authenticationError(
        'RECOVERY_CODE_INVALID',
        'That recovery code was not recognised. Each code can be used once; check your stored list.',
      );
    }

    // Recovery burns every existing session: a lost authenticator must not leave
    // orphaned privileged sessions behind.
    await revokeAllSessions(sql, user.id, 'Credential recovery');

    // A privileged account cannot return to ACTIVE use without a working authenticator;
    // the status moves to PENDING_ENROLMENT until a new key is enrolled (which the
    // reset session may do via /webauthn/register).
    if (user.authority_level !== 'L1') {
      await sql`
        UPDATE webauthn_credentials
           SET status = 'REVOKED', revoked_at = now(), revoked_reason = 'Credential recovery'
         WHERE user_id = ${user.id} AND status = 'ACTIVE'
      `;
      await sql`UPDATE users SET status = 'PENDING_ENROLMENT' WHERE id = ${user.id}`;
    }

    // Issue a recovery session: webauthnVerified = false, so every WebAuthn-gated
    // privileged action refuses it; enrolment endpoints accept it.
    const token = randomToken(32);
    const tokenHash = await hashSessionToken(token, c.env.SESSION_SIGNING_KEY);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 minutes — long enough to enroll a key, no longer
    await sql`
      INSERT INTO sessions (
        organization_id, user_id, token_hash, authenticated_at, issued_at, expires_at, ip, user_agent
      ) VALUES (
        ${user.organization_id}, ${user.id}, ${tokenHash}, ${now}, ${now}, ${expiresAt},
        ${security.ip}, ${security.userAgent}
      )
    `;

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: user.organization_id,
        actorId: user.id,
        actorLevel: user.authority_level,
        eventClass: 'SECURITY',
        action: 'auth.recovery.redeemed',
        objectType: 'User',
        objectId: user.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: security,
        detail: { sessionsRevoked: 'all', privileged: user.authority_level !== 'L1' },
      }),
    );

    return {
      recovered: true as const,
      token,
      expiresAt: expiresAt.toISOString(),
      nextStep:
        user.authority_level === 'L1'
          ? 'Sign in normally with your new password if you changed it, or continue with this session.'
          : 'Enroll a new security key now (Settings → Security → Add security key). Until then, payment authorization and administration are refused.',
    };
  });

  return c.json(result);
});

// ---------------------------------------------------------------------------
// Session info and lifecycle
// ---------------------------------------------------------------------------

/** GET /api/auth/session — who am I, and what may I do. */
authRoutes.get('/session', requireAuth, async (c) => {
  const actor = actorOf(c);
  return c.json({
    user: {
      userId: actor.userId,
      email: actor.email,
      fullName: actor.fullName,
      level: actor.level,
      levelTitle: LEVEL_TITLES[actor.level],
      organizationId: actor.organizationId,
    },
    session: {
      authenticatedAt: new Date(actor.authenticatedAt).toISOString(),
      webauthnVerified: actor.webauthnVerifiedAt !== null,
      trustedDeviceId: actor.trustedDeviceId,
      sessionId: actor.sessionId,
    },
    // The UI renders from this. It is a convenience, not a control: every endpoint
    // re-checks server-side against the live matrix (spec §4 HARD CONTROL).
    capabilities: await withConnection(c.env, (sql) => {
      const matrix = loadEffectiveMatrix;
      return matrix(sql, actor.organizationId).then((m) => capabilitiesFor(toActor(actor), m));
    }),
  });
});

/** POST /api/auth/logout */
authRoutes.post('/logout', requireAuth, async (c) => {
  const actor = actorOf(c);
  const correlationId = c.get('correlationId');

  await withConnection(c.env, async (sql) => {
    await revokeSession(sql, actor.sessionId, 'User signed out');
    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'IDENTITY',
        action: 'auth.logout',
        objectType: 'Session',
        objectId: actor.sessionId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {},
      }),
    );
  });

  return c.json({ signedOut: true });
});

/** POST /api/auth/logout-all — revoke every session, for a suspected compromise. */
authRoutes.post('/logout-all', requireAuth, async (c) => {
  const actor = actorOf(c);
  const correlationId = c.get('correlationId');

  const revoked = await withConnection(c.env, async (sql) => {
    const count = await revokeAllSessions(sql, actor.userId, 'User revoked all sessions');
    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'auth.sessions.revoked_all',
        objectType: 'User',
        objectId: actor.userId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { sessionsRevoked: count },
      }),
    );
    return count;
  });

  return c.json({ sessionsRevoked: revoked });
});

async function publicUser(
  sql: Parameters<Parameters<typeof withConnection>[1]>[0],
  user: UserRow,
) {
  const matrix = await loadEffectiveMatrix(sql, user.organization_id);
  return {
    userId: user.id,
    email: user.email,
    fullName: user.full_name,
    level: user.authority_level,
    levelTitle: LEVEL_TITLES[user.authority_level],
    organizationId: user.organization_id,
    authorizationPinEnrolled: user.authorization_pin_hash !== null,
    capabilities: capabilitiesFor(
      { level: user.authority_level, status: user.status === 'ACTIVE' ? 'ACTIVE' : user.status },
      matrix,
    ),
  };
}
