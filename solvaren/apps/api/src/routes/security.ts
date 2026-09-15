/**
 * Security Center (spec §22): devices, sessions, security events, the audit viewer with
 * chain verification, notifications, and the operator's queue diagnostics (spec §10:
 * "operator-visible queue state, retry count and stuck-job diagnostics").
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { verifyChainAsync, GENESIS_HASH, notFoundError, validationError, type AuditEvent } from '@solvaren/core';
import { requireAuth, requirePermissions, requireExactLevel, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { revokeAllSessions } from '../services/auth.js';
import type { AppContext } from '../env.js';

export const securityRoutes = new Hono<AppContext>();
securityRoutes.use('*', requireAuth);

// ---------------------------------------------------------------------------
// Devices (spec §8.1)
// ---------------------------------------------------------------------------

securityRoutes.get('/security/devices', requirePermissions('admin:security'), async (c) => {
  const actor = actorOf(c);
  const devices = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        user_id: string;
        user_name: string;
        friendly_name: string | null;
        trust_status: string;
        first_seen_ip: string | null;
        last_seen_ip: string | null;
        user_agent: string | null;
        registered_at: string;
        last_activity_at: string;
        revoked_at: string | null;
        credential_nickname: string | null;
      }[]
    >`
      SELECT td.id, td.user_id, COALESCE(u.full_name, td.user_id::text) AS user_name,
             td.friendly_name, td.trust_status, td.first_seen_ip, td.last_seen_ip,
             td.user_agent, td.registered_at, td.last_activity_at, td.revoked_at,
             wc.friendly_name AS credential_nickname
        FROM trusted_devices td
        JOIN users u ON u.id = td.user_id
        LEFT JOIN webauthn_credentials wc ON wc.id = td.webauthn_credential_id
       WHERE td.organization_id = ${actor.organizationId}
       ORDER BY td.last_activity_at DESC
       LIMIT 200
    `,
  );
  return c.json({
    devices: devices.map((d) => ({
      deviceId: d.id,
      userId: d.user_id,
      userName: d.user_name,
      friendlyName: d.friendly_name ?? d.credential_nickname ?? 'Unknown device',
      trustStatus: d.trust_status,
      firstSeenIp: d.first_seen_ip,
      lastSeenIp: d.last_seen_ip,
      userAgent: d.user_agent,
      registeredAt: d.registered_at,
      lastActivityAt: d.last_activity_at,
      revoked: d.revoked_at !== null,
    })),
  });
});

/** POST /api/security/devices/:id/revoke — immediate invalidation for privileged use. */
securityRoutes.post('/security/devices/:id/revoke', requirePermissions('admin:security'), async (c) => {
  const actor = actorOf(c);
  const deviceId = c.req.param('id');
  const body = z.object({ reason: z.string().trim().min(3).max(500) }).parse(await c.req.json());
  const correlationId = c.get('correlationId');

  await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const rows = await tx<{ id: string; user_id: string }[]>`
        SELECT id, user_id FROM trusted_devices
         WHERE id = ${deviceId} AND organization_id = ${actor.organizationId}
         FOR UPDATE
      `;
      if (!rows[0]) throw notFoundError('DEVICE_NOT_FOUND', 'That device could not be found');

      await tx`
        UPDATE trusted_devices
           SET trust_status = 'REVOKED', revoked_at = now(), revoked_reason = ${body.reason}
         WHERE id = ${deviceId}
      `;
      // Revocation takes effect on the device holder's next request: their sessions die too.
      await revokeAllSessions(tx, rows[0].user_id, `Device revoked: ${body.reason}`);

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'device.revoked',
        objectType: 'TrustedDevice',
        objectId: deviceId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason, sessionsRevoked: 'all' },
      });
    }),
  );

  return c.json({ revoked: true });
});

securityRoutes.post('/security/devices/:id/trust', requirePermissions('admin:security'), async (c) => {
  const actor = actorOf(c);
  const deviceId = c.req.param('id');
  await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await tx`
        UPDATE trusted_devices SET trust_status = 'TRUSTED'
         WHERE id = ${deviceId} AND organization_id = ${actor.organizationId} AND revoked_at IS NULL
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'device.trusted',
        objectType: 'TrustedDevice',
        objectId: deviceId,
        outcome: 'SUCCESS',
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
        detail: {},
      });
    }),
  );
  return c.json({ trusted: true });
});

// ---------------------------------------------------------------------------
// Security events
// ---------------------------------------------------------------------------

securityRoutes.get('/security/events', requirePermissions('audit:read_org'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const severity = url.searchParams.get('severity');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '100'), 500);

  const events = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        event_type: string;
        severity: string;
        description: string;
        ip: string | null;
        user_agent: string | null;
        detail: unknown;
        acknowledged_at: string | null;
        created_at: string;
        user_name: string | null;
      }[]
    >`
      SELECT se.id, se.event_type, se.severity, se.description, se.ip, se.user_agent,
             se.detail, se.acknowledged_at, se.created_at,
             (SELECT full_name FROM users WHERE id = se.user_id) AS user_name
        FROM security_events se
       WHERE se.organization_id = ${actor.organizationId}
         AND (${severity ?? null}::text IS NULL OR se.severity = ${severity ?? null}::text)
       ORDER BY se.created_at DESC
       LIMIT ${limit}
    `,
  );

  return c.json({
    events: events.map((e) => ({
      eventId: e.id,
      eventType: e.event_type,
      severity: e.severity,
      description: e.description,
      ip: e.ip,
      userAgent: e.user_agent,
      detail: e.detail,
      acknowledged: e.acknowledged_at !== null,
      createdAt: e.created_at,
      userName: e.user_name,
    })),
  });
});

securityRoutes.post('/security/events/:id/acknowledge', requirePermissions('audit:read_org'), async (c) => {
  const actor = actorOf(c);
  const eventId = c.req.param('id');
  await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await tx`
        UPDATE security_events SET acknowledged_at = now(), acknowledged_by_user_id = ${actor.userId}
         WHERE id = ${eventId} AND organization_id = ${actor.organizationId}
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'SECURITY',
        action: 'security_event.acknowledged',
        objectType: 'SecurityEvent',
        objectId: eventId,
        outcome: 'SUCCESS',
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
        detail: {},
      });
    }),
  );
  return c.json({ acknowledged: true });
});

// ---------------------------------------------------------------------------
// Audit viewer + chain verification (spec §14)
// ---------------------------------------------------------------------------

securityRoutes.get('/security/audit', requirePermissions('audit:read_org'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const eventClass = url.searchParams.get('eventClass');
  const objectId = url.searchParams.get('objectId');
  const outcome = url.searchParams.get('outcome');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '100'), 500);
  const offset = Math.max(Number(url.searchParams.get('offset') ?? '0'), 0);

  const events = await withConnection(c.env, (sql) =>
    sql<
      {
        event_reference: string;
        sequence: string;
        actor_id: string;
        actor_level: string | null;
        event_class: string;
        action: string;
        object_type: string;
        object_id: string | null;
        outcome: string;
        occurred_at: string;
        correlation_id: string;
        detail: unknown;
        previous_state: unknown;
        new_state: unknown;
      }[]
    >`
      SELECT event_reference, sequence, actor_id, actor_level, event_class, action,
             object_type, object_id, outcome, occurred_at, correlation_id, detail,
             previous_state, new_state
        FROM audit_events
       WHERE organization_id = ${actor.organizationId}
         AND (${eventClass ?? null}::text IS NULL OR event_class = ${eventClass ?? null}::text)
         AND (${objectId ?? null}::text   IS NULL OR object_id = ${objectId ?? null}::text)
         AND (${outcome ?? null}::text    IS NULL OR outcome = ${outcome ?? null}::text)
       ORDER BY sequence DESC
       LIMIT ${limit} OFFSET ${offset}
    `,
  );

  return c.json({ events });
});

/**
 * POST /api/security/audit/verify — verify the tamper-evident chain.
 *
 * Recomputes every digest and every link. A break is reported with the exact event at
 * which verification failed, which is what turns "we have logs" into "we can prove the
 * logs are intact".
 */
securityRoutes.post(
  '/security/audit/verify',
  requireExactLevel('L3'),
  requirePermissions('audit:read_full'),
  async (c) => {
    const actor = actorOf(c);
    const body = z
      .object({
        fromSequence: z.number().int().min(1).default(1),
        limit: z.number().int().min(1).max(5000).default(1000),
      })
      .parse(await c.req.json().catch(() => ({})));

    const verification = await withConnection(c.env, async (sql) => {
      const rows = await sql<
        {
          id: string;
          event_reference: string;
          organization_id: string;
          actor_id: string;
          actor_level: string | null;
          event_class: string;
          action: string;
          object_type: string;
          object_id: string | null;
          outcome: string;
          occurred_at: string;
          previous_state: unknown;
          new_state: unknown;
          security_context: Record<string, unknown>;
          detail: Record<string, unknown>;
          correlation_id: string;
          previous_hash: string;
          event_hash: string;
          sequence: string;
        }[]
      >`
        SELECT id, event_reference, organization_id, actor_id, actor_level, event_class, action,
               object_type, object_id, outcome, occurred_at, previous_state, new_state,
               security_context, detail, correlation_id, previous_hash, event_hash, sequence
          FROM audit_events
         WHERE organization_id = ${actor.organizationId} AND sequence >= ${body.fromSequence}
         ORDER BY sequence ASC
         LIMIT ${body.limit}
      `;

      const events: AuditEvent[] = rows.map((r) => ({
        eventId: r.id,
        organizationId: r.organization_id,
        actorId: r.actor_id,
        actorLevel: r.actor_level,
        eventClass: r.event_class as AuditEvent['eventClass'],
        action: r.action,
        objectType: r.object_type,
        objectId: r.object_id,
        outcome: r.outcome as AuditEvent['outcome'],
        occurredAt: new Date(r.occurred_at).toISOString(),
        previousState: r.previous_state,
        newState: r.new_state,
        securityContext: r.security_context,
        detail: r.detail,
        correlationId: r.correlation_id,
        previousHash: r.previous_hash,
        eventHash: r.event_hash,
        sequence: Number(r.sequence),
      }));

      const startHash =
        body.fromSequence === 1
          ? GENESIS_HASH
          : ((
              await sql<{ event_hash: string }[]>`
                SELECT event_hash FROM audit_events
                 WHERE organization_id = ${actor.organizationId} AND sequence = ${body.fromSequence - 1}
              `
            )[0]?.event_hash ?? GENESIS_HASH);

      return verifyChainAsync(events, startHash);
    });

    return c.json({
      ...verification,
      interpretation: verification.valid
        ? 'Every event in this range hashes to its recorded digest and links to its predecessor. No event has been added, removed, reordered or altered.'
        : 'The chain does not verify. An event has been altered or removed at the reported position. Preserve the database and follow docs/runbooks/audit-preservation.md.',
    });
  },
);

// ---------------------------------------------------------------------------
// Notifications (in-app + delivery channels)
// ---------------------------------------------------------------------------

securityRoutes.get('/notifications', async (c) => {
  const actor = actorOf(c);
  const notifications = await withConnection(c.env, (sql) =>
    sql<
      { id: string; severity: string; title: string; body: string; link_path: string | null; created_at: string }[]
    >`
      SELECT id, severity, title, body, link_path, created_at
        FROM notifications
       WHERE organization_id = ${actor.organizationId} AND read_at IS NULL
       ORDER BY created_at DESC
       LIMIT 50
    `,
  );
  return c.json({ notifications });
});

securityRoutes.post('/notifications/:id/read', async (c) => {
  const actor = actorOf(c);
  const notificationId = c.req.param('id');
  await withConnection(c.env, (sql) =>
    sql`
      UPDATE notifications SET read_at = now(), read_by_user_id = ${actor.userId}
       WHERE id = ${notificationId} AND organization_id = ${actor.organizationId}
    `,
  );
  return c.json({ read: true });
});

const channelSchema = z.object({
  kind: z.enum(['WEBHOOK', 'EMAIL']),
  /** Webhook URL or email address — encrypted at rest, masked thereafter. */
  target: z.string().trim().min(6).max(300),
  minimumSeverity: z.enum(['INFO', 'WARNING', 'CRITICAL']).default('WARNING'),
});

securityRoutes.post(
  '/notifications/channels',
  requirePermissions('admin:security'),
  async (c) => {
    const actor = actorOf(c);
    const body = channelSchema.parse(await c.req.json());
    const correlationId = c.get('correlationId');

    if (body.kind === 'WEBHOOK') {
      try {
        new URL(body.target);
      } catch {
        throw validationError('WEBHOOK_URL_INVALID', 'The webhook target must be a valid https URL');
      }
    }

    const created = await withConnection(c.env, async (sql) => {
      const { encryptSecret } = await import('../services/crypto.js');
      const { secretReference } = await import('../services/secret-store.js');
      const ref = secretReference(actor.organizationId, 'notification', crypto.randomUUID().slice(0, 8));
      await c.env.secrets.put(ref, await encryptSecret(body.target, c.env.SECRET_ENCRYPTION_KEY, 'notification'));

      const rows = await sql<{ id: string }[]>`
        INSERT INTO notification_channels (
          organization_id, kind, target_secret_ref, target_display, minimum_severity, created_by_user_id
        ) VALUES (
          ${actor.organizationId}, ${body.kind}, ${ref},
          ${body.kind === 'EMAIL' ? body.target.replace(/(.{2}).*(@.*)/, '$1•••$2') : `${new URL(body.target).host}/•••`},
          ${body.minimumSeverity}, ${actor.userId}
        )
        RETURNING id
      `;
      return rows[0]!;
    });

    await inTransaction(c.env.sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'ADMINISTRATION',
        action: 'notification.channel.created',
        objectType: 'NotificationChannel',
        objectId: created.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { kind: body.kind, minimumSeverity: body.minimumSeverity },
      }),
    );

    return c.json({ channelId: created.id }, 201);
  },
);

securityRoutes.get('/notifications/channels', requirePermissions('admin:security'), async (c) => {
  const actor = actorOf(c);
  const channels = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        kind: string;
        target_display: string;
        minimum_severity: string;
        enabled: boolean;
        last_delivery_at: string | null;
        last_delivery_ok: boolean | null;
        last_error: string | null;
      }[]
    >`
      SELECT id, kind, target_display, minimum_severity, enabled, last_delivery_at,
             last_delivery_ok, last_error
        FROM notification_channels
       WHERE organization_id = ${actor.organizationId}
       ORDER BY created_at
    `,
  );
  return c.json({
    channels: channels.map((ch) => ({
      channelId: ch.id,
      kind: ch.kind,
      targetDisplay: ch.target_display,
      minimumSeverity: ch.minimum_severity,
      enabled: ch.enabled,
      lastDeliveryAt: ch.last_delivery_at,
      lastDeliveryOk: ch.last_delivery_ok,
      lastError: ch.last_error,
    })),
  });
});

// ---------------------------------------------------------------------------
// Queue diagnostics (spec §10) — the operator's stuck-job view
// ---------------------------------------------------------------------------

securityRoutes.get('/ops/queue', requirePermissions('ops:queue_read'), async (c) => {
  const actor = actorOf(c);

  const summary = await withConnection(c.env, (sql) =>
    sql<{ queue: string; status: string; count: string; oldest: string | null }[]>`
      SELECT queue, status, COUNT(*) AS count, MIN(created_at)::text AS oldest
        FROM job_queue
       WHERE organization_id = ${actor.organizationId}
       GROUP BY queue, status
       ORDER BY queue, status
    `,
  );

  const stuck = await withConnection(c.env, (sql) =>
    sql<
      { id: string; queue: string; status: string; attempts: number; max_attempts: number; last_error: string | null; claimed_by: string | null; claimed_until: string | null; created_at: string; correlation_id: string | null }[]
    >`
      SELECT id, queue, status, attempts, max_attempts, last_error, claimed_by,
             claimed_until::text, created_at::text, correlation_id
        FROM job_queue
       WHERE organization_id = ${actor.organizationId}
         AND (status = 'DEAD_LETTERED'
              OR (status = 'IN_FLIGHT' AND claimed_until < now() + interval '2 minutes')
              OR (status = 'PENDING' AND created_at < now() - interval '10 minutes'))
       ORDER BY created_at
       LIMIT 100
    `,
  );

  return c.json({
    summary: summary.map((s) => ({
      queue: s.queue,
      status: s.status,
      count: Number(s.count),
      oldest: s.oldest,
    })),
    stuckJobs: stuck.map((j) => ({
      jobId: j.id,
      queue: j.queue,
      status: j.status,
      attempts: j.attempts,
      maxAttempts: j.max_attempts,
      lastError: j.last_error,
      claimedBy: j.claimed_by,
      claimedUntil: j.claimed_until,
      createdAt: j.created_at,
      correlationId: j.correlation_id,
    })),
  });
});

/** POST /api/security/ops/queue/:id/requeue — requeue a dead-lettered job for diagnosis. */
securityRoutes.post('/ops/queue/:id/requeue', requirePermissions('admin:security'), async (c) => {
  const actor = actorOf(c);
  const jobId = c.req.param('id');
  const body = z.object({ reason: z.string().trim().min(3).max(500) }).parse(await c.req.json());

  await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      // The guard trigger blocks DEAD_LETTERED→PENDING by design; the operator path is a
      // deliberate clone-with-attempt-reset through a superuser-free flow: re-insert as a
      // fresh job referencing the same body, preserving the dead letter as evidence.
      const rows = await tx<{ id: string; queue: string; body: unknown; organization_id: string; correlation_id: string | null }[]>`
        SELECT id, queue, body, organization_id, correlation_id FROM job_queue
         WHERE id = ${jobId} AND organization_id = ${actor.organizationId} AND status = 'DEAD_LETTERED'
      `;
      if (!rows[0]) {
        throw validationError('JOB_NOT_DEAD_LETTERED', 'Only dead-lettered jobs can be requeued.');
      }

      await tx`
        INSERT INTO job_queue (queue, priority, body, organization_id, correlation_id, max_attempts, run_after)
        VALUES (
          ${rows[0].queue}, 50, ${tx.json(rows[0].body as never)}, ${rows[0].organization_id},
          ${rows[0].correlation_id ?? c.get('correlationId')}, 2, now()
        )
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'ADMINISTRATION',
        action: 'queue.job.requeued',
        objectType: 'JobQueue',
        objectId: jobId,
        outcome: 'SUCCESS',
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason, note: 'Requeued as a new job; the dead letter is retained as evidence.' },
      });
    }),
  );

  return c.json({ requeued: true }, 202);
});
