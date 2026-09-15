/**
 * The audit writer — the only code path that inserts into `audit_events`.
 *
 * The application computes the event digest (deterministic key-sorted JSON from
 * @solvaren/core); the database trigger assigns the sequence and the chain link. The
 * write happens inside the caller's transaction, so there is no window in which money
 * moved without a record.
 */

import {
  computeEventHash,
  correlationId as newCorrelationId,
  redactForAudit,
  type AuditDraft,
} from '@solvaren/core';
import { newId } from '@solvaren/core';
import type { Sql } from './client.js';

export interface WriteAuditEventInput {
  organizationId: string;
  actorId: string;
  actorLevel: string | null;
  eventClass: AuditDraft['eventClass'];
  action: string;
  objectType: string;
  objectId: string | null;
  outcome: AuditDraft['outcome'];
  previousState?: unknown;
  newState?: unknown;
  correlationId?: string;
  securityContext?: Record<string, unknown>;
  detail?: Record<string, unknown>;
}

export async function writeAuditEvent(tx: Sql, input: WriteAuditEventInput): Promise<void> {
  const eventId = newId();
  const occurredAt = new Date().toISOString();

  const hashable = {
    eventId,
    organizationId: input.organizationId,
    actorId: input.actorId,
    actorLevel: input.actorLevel,
    eventClass: input.eventClass,
    action: input.action,
    objectType: input.objectType,
    objectId: input.objectId,
    outcome: input.outcome,
    occurredAt,
    previousState: input.previousState ?? null,
    newState: input.newState ?? null,
    securityContext: redactForAudit(input.securityContext ?? {}),
    detail: redactForAudit(input.detail ?? {}),
    correlationId: input.correlationId ?? newCorrelationId(),
  };

  const eventHash = await computeEventHash(hashable);

  await tx`
    INSERT INTO audit_events (
      id, event_reference, organization_id, actor_id, actor_level, event_class, action,
      object_type, object_id, outcome, previous_state, new_state, security_context,
      detail, correlation_id, previous_hash, event_hash, occurred_at
    ) VALUES (
      ${eventId}, ${`EVT-${eventId.slice(0, 8).toUpperCase()}`}, ${input.organizationId},
      ${input.actorId}, ${input.actorLevel}, ${input.eventClass}, ${input.action},
      ${input.objectType}, ${input.objectId}, ${input.outcome},
      ${tx.json(hashable.previousState as never)}, ${tx.json(hashable.newState as never)},
      ${tx.json(hashable.securityContext as never)}, ${tx.json(hashable.detail as never)},
      ${hashable.correlationId},
      'PENDING', ${eventHash}, ${occurredAt}
    )
  `;
}
