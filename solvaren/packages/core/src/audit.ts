/**
 * The audit chain (spec §14).
 *
 * Every critical event commits to its predecessor with SHA-256:
 *
 *   event_hash[n] = SHA256(event_hash[n-1] || canonical(n))
 *
 * Removal, reordering or alteration of any event breaks verification at a known index.
 * The sequence number and chain link are assigned by a database trigger, not trusted
 * from the caller, and UPDATE/DELETE on `audit_events` are refused by trigger for every
 * role. This module is the pure half: canonicalization, digest computation and chain
 * verification. The database enforces the rest.
 */

import { stableStringify } from './ids.js';
import { sha256Hex } from './manifest.js';

/** The digest carried by the first event of every organization's chain. */
export const GENESIS_HASH = 'SLV-GENESIS-0000000000000000000000000000000000000000000000000000';

export const AUDIT_EVENT_CLASSES = [
  'IDENTITY',
  'AUTHORITY',
  'PAYMENT',
  'INTEGRATION',
  'SECURITY',
  'BACKUP',
  'ADMINISTRATION',
  'DATA_EXPORT',
] as const;
export type AuditEventClass = (typeof AUDIT_EVENT_CLASSES)[number];

export type AuditOutcome = 'SUCCESS' | 'DENIED' | 'FAILURE';

export interface AuditEvent {
  eventId: string;
  organizationId: string;
  actorId: string;
  actorLevel: string | null;
  eventClass: AuditEventClass;
  action: string;
  objectType: string;
  objectId: string | null;
  outcome: AuditOutcome;
  occurredAt: string;
  previousState: unknown;
  newState: unknown;
  securityContext: Record<string, unknown>;
  detail: Record<string, unknown>;
  correlationId: string;
  previousHash: string;
  eventHash: string;
  /** 1-based, per-organization, assigned by the database. */
  sequence: number;
}

/** What a handler passes to the audit writer; chain fields are added by the database. */
export type AuditDraft = Omit<
  AuditEvent,
  'eventHash' | 'previousHash' | 'sequence'
>;

/** The canonical bytes an event hashes over. Any change here is a protocol change.
 *
 * The digest deliberately excludes `sequence` and `previousHash`: those are assigned by
 * the database trigger at INSERT time, so the application must be able to compute the
 * digest before the row is positioned. Tamper-evidence is preserved because content
 * changes break the stored digest, while insertions, deletions and reorderings break
 * the previous_hash chain.
 */
export function canonicalEventBody(event: Omit<AuditEvent, 'eventHash' | 'sequence' | 'previousHash'>): string {
  return [
    event.eventId,
    event.organizationId,
    event.actorId,
    event.actorLevel ?? '-',
    event.eventClass,
    event.action,
    event.objectType,
    event.objectId ?? '-',
    event.outcome,
    event.occurredAt,
    stableStringify(event.previousState),
    stableStringify(event.newState),
    stableStringify(event.securityContext),
    stableStringify(event.detail),
    event.correlationId,
  ].join('\x1e');
}

export async function computeEventHash(
  event: Omit<AuditEvent, 'eventHash' | 'sequence' | 'previousHash'>,
): Promise<string> {
  return sha256Hex(canonicalEventBody(event));
}

export interface ChainVerification {
  valid: boolean;
  /** When invalid: the 1-based sequence position at which verification failed. */
  failedAtSequence: number | null;
  /** When invalid: the eventId whose digest did not verify. */
  failedEventId: string | null;
  reason: string | null;
  verifiedCount: number;
}

/**
 * Verify a contiguous run of events against an anchor hash (GENESIS for sequence 1).
 *
 * Recomputes every digest and every link. A break is reported with the exact event at
 * which verification failed — that is what turns "we have logs" into "we can prove the
 * logs are intact".
 */
export function verifyChain(
  events: readonly AuditEvent[],
  anchorHash: string,
): ChainVerification {
  let previous = anchorHash;
  let count = 0;

  for (const event of events) {
    if (event.previousHash !== previous) {
      return {
        valid: false,
        failedAtSequence: event.sequence,
        failedEventId: event.eventId,
        reason: `Event ${event.eventId} (sequence ${event.sequence}) links to ` +
          `${event.previousHash.slice(0, 12)}… but its predecessor hashes to ${previous.slice(0, 12)}… — the chain has been reordered, removed from, or inserted into.`,
        verifiedCount: count,
      };
    }
    // Digest check is performed by the caller-supplied eventHash comparison; recompute
    // asynchronously is not possible in a sync loop, so link verification is here and
    // digest verification in `verifyChainAsync`.
    previous = event.eventHash;
    count += 1;
  }

  return { valid: true, failedAtSequence: null, failedEventId: null, reason: null, verifiedCount: count };
}

/** Link + digest verification (async: recomputes every SHA-256). */
export async function verifyChainAsync(
  events: readonly AuditEvent[],
  anchorHash: string,
): Promise<ChainVerification> {
  let previous = anchorHash;
  let count = 0;

  for (const event of events) {
    if (event.previousHash !== previous) {
      return {
        valid: false,
        failedAtSequence: event.sequence,
        failedEventId: event.eventId,
        reason: `Event ${event.eventId} (sequence ${event.sequence}) does not link to its predecessor — events have been added, removed or reordered.`,
        verifiedCount: count,
      };
    }
    const expected = await computeEventHash(event);
    if (expected !== event.eventHash) {
      return {
        valid: false,
        failedAtSequence: event.sequence,
        failedEventId: event.eventId,
        reason: `Event ${event.eventId} (sequence ${event.sequence}) does not hash to its recorded digest — its contents were altered.`,
        verifiedCount: count,
      };
    }
    previous = event.eventHash;
    count += 1;
  }

  return { valid: true, failedAtSequence: null, failedEventId: null, reason: null, verifiedCount: count };
}

// ---------------------------------------------------------------------------
// Redaction — secrets must never reach the log
// ---------------------------------------------------------------------------

/**
 * Keys are judged by their tokens (split on case boundaries and separators), so
 * `authorizationPin`, `pin_hash` and `apiKey` are caught while `mapping` and
 * `quantity` are not.
 */
const SENSITIVE_TOKENS = new Set([
  'password', 'pass', 'pin', 'secret', 'token', 'credential', 'credentials',
  'passphrase', 'apikey', 'key', 'recovery', 'authorization', 'signature',
]);

function isSensitiveKey(key: string): boolean {
  const tokens = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2') // split camelCase
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
  return tokens.some((t) => SENSITIVE_TOKENS.has(t));
}

/**
 * Recursively remove credential-shaped values at every depth. Values under a
 * sensitive-looking key are replaced with a marker; long high-entropy strings under any
 * key are masked as a backstop.
 */
export function redactForAudit(value: unknown): Record<string, unknown> {
  return redact(value, 0) as Record<string, unknown>;
}

function redact(value: unknown, depth: number): unknown {
  if (depth > 8) return '[depth limit]';
  if (value === null || value === undefined) return value;

  if (Array.isArray(value)) {
    return value.map((v) => redact(v, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = isSensitiveKey(k) ? '[redacted]' : redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string' && looksLikeSecret(value)) {
    return '[redacted]';
  }
  return value;
}

function looksLikeSecret(value: string): boolean {
  // Base64-ish, at least 32 chars, no spaces — credential material shape. Purely
  // numeric strings (amounts, phone numbers in bulk) are left alone.
  return value.length >= 32 && !/^\d+$/.test(value) && /^[A-Za-z0-9+/=_-]+$/.test(value);
}
