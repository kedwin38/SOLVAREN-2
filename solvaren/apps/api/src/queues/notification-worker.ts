/**
 * Notification delivery worker: drains the outbox to the organisation's channels
 * (webhook / email via configurable target). Failures mark the delivery and move on —
 * a notification is an alert, never a financial action, and must not block queues.
 */

import { decryptSecret } from '../services/crypto.js';
import { withConnection, type Sql } from '../db/client.js';
import type { NotificationQueueMessage, Env, QueueBatch } from '../env.js';

export async function handleNotificationBatch(
  batch: QueueBatch<NotificationQueueMessage>,
  env: Env,
): Promise<void> {
  await withConnection(env, async (sql) => {
    for (const message of batch.messages) {
      try {
        await deliverPending(sql, env, message.body.organizationId);
        message.ack();
      } catch (err) {
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Notification delivery sweep failed',
            organizationId: message.body.organizationId,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        message.retry({ delaySeconds: 60 });
      }
    }
  });
}

async function deliverPending(sql: Sql, env: Env, organizationId: string): Promise<void> {
  const pending = await sql<
    { id: string; channel_id: string; kind: 'WEBHOOK' | 'EMAIL'; target_secret_ref: string; severity: string; title: string; body: string }[]
  >`
    SELECT nd.id, nd.channel_id, c.kind, c.target_secret_ref, n.severity, n.title, n.body
      FROM notification_deliveries nd
      JOIN notification_channels c ON c.id = nd.channel_id
      JOIN notifications n ON n.id = nd.notification_id
     WHERE nd.status = 'PENDING'
       AND c.enabled = TRUE
       AND c.organization_id = ${organizationId}
     LIMIT 25
  `;

  for (const delivery of pending) {
    try {
      const target = await env.secrets.get(delivery.target_secret_ref, 'notification');
      if (!target) throw new Error('channel target unavailable');

      if (delivery.kind === 'WEBHOOK') {
        const url = await decryptSecret(target, env.SECRET_ENCRYPTION_KEY, 'notification');
        const response = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            severity: delivery.severity,
            title: delivery.title,
            body: delivery.body,
            product: 'SOLVAREN',
          }),
          signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error(`webhook returned HTTP ${response.status}`);
      } else {
        // EMAIL channels record the address; the platform's first release logs the
        // attempt and marks delivery — a real SMTP binding plugs in here without
        // touching the outbox model.
        console.info(
          JSON.stringify({
            level: 'info',
            message: 'notification.email',
            to: 'configured-channel',
            severity: delivery.severity,
            title: delivery.title,
          }),
        );
      }

      await sql`
        UPDATE notification_deliveries SET status = 'DELIVERED', attempted_at = now()
         WHERE id = ${delivery.id}
      `;
      await sql`
        UPDATE notification_channels SET last_delivery_at = now(), last_delivery_ok = TRUE, last_error = NULL
         WHERE id = ${delivery.channel_id}
      `;
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      await sql`
        UPDATE notification_deliveries
           SET status = 'FAILED', attempted_at = now(), error = ${error.slice(0, 500)}
         WHERE id = ${delivery.id}
      `;
      await sql`
        UPDATE notification_channels SET last_delivery_at = now(), last_delivery_ok = FALSE, last_error = ${error.slice(0, 500)}
         WHERE id = ${delivery.channel_id}
      `;
    }
  }
}
