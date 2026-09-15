/**
 * The audit chain (spec §14): tamper-evidence. Alteration, deletion and reordering are
 * each detected at the exact event where the chain breaks; redaction removes
 * credential-shaped material at every depth.
 */

import { describe, expect, it } from 'vitest';
import {
  computeEventHash,
  canonicalEventBody,
  verifyChain,
  verifyChainAsync,
  GENESIS_HASH,
  redactForAudit,
  type AuditEvent,
} from './index.js';

async function event(overrides: Partial<AuditEvent> & { sequence: number; previousHash: string }): Promise<AuditEvent> {
  const base = {
    eventId: `evt-${overrides.sequence}`,
    organizationId: 'org-1',
    actorId: 'system:test',
    actorLevel: null,
    eventClass: 'PAYMENT' as const,
    action: 'payment.test',
    objectType: 'Transaction',
    objectId: `txn-${overrides.sequence}`,
    outcome: 'SUCCESS' as const,
    occurredAt: new Date(1_700_000_000_000 + overrides.sequence * 1000).toISOString(),
    previousState: null,
    newState: { seq: overrides.sequence },
    securityContext: { ip: '10.0.0.1' },
    detail: { note: `event ${overrides.sequence}` },
    correlationId: `cor-${overrides.sequence}`,
  };
  const eventHash = await computeEventHash({ ...base, eventId: base.eventId });
  return { ...base, ...overrides, eventHash } as AuditEvent;
}

async function chainOf(n: number): Promise<AuditEvent[]> {
  const events: AuditEvent[] = [];
  let previous = GENESIS_HASH;
  for (let i = 1; i <= n; i++) {
    const e = await event({ sequence: i, previousHash: previous });
    events.push(e);
    previous = e.eventHash;
  }
  return events;
}

describe('canonicalization', () => {
  it('is deterministic for identical content', async () => {
    const e1 = await event({ sequence: 1, previousHash: GENESIS_HASH });
    const e2 = await event({ sequence: 1, previousHash: GENESIS_HASH });
    expect(canonicalEventBody(e1)).toBe(canonicalEventBody(e2));
  });

  it('changes when any signed field changes', async () => {
    const e1 = await event({ sequence: 1, previousHash: GENESIS_HASH });
    const e2 = await event({ sequence: 1, previousHash: GENESIS_HASH });
    e2.detail = { note: 'tampered' };
    expect(canonicalEventBody(e1)).not.toBe(canonicalEventBody(e2));
  });
});

describe('chain verification', () => {
  it('verifies an intact chain from genesis', async () => {
    const chain = await chainOf(5);
    const result = await verifyChainAsync(chain, GENESIS_HASH);
    expect(result.valid).toBe(true);
    expect(result.verifiedCount).toBe(5);
  });

  it('detects content alteration at the exact event', async () => {
    const chain = await chainOf(5);
    chain[2]!.detail = { note: 'rewritten by an attacker' };
    const result = await verifyChainAsync(chain, GENESIS_HASH);
    expect(result.valid).toBe(false);
    expect(result.failedAtSequence).toBe(3);
    expect(result.reason).toMatch(/altered/i);
  });

  it('detects deletion — the successor no longer links', async () => {
    const chain = await chainOf(5);
    chain.splice(2, 1); // delete event 3
    const result = await verifyChainAsync(chain, GENESIS_HASH);
    expect(result.valid).toBe(false);
    // Event 4 still links to the deleted event 3's hash — the break is at event 4.
    expect(result.failedAtSequence).toBe(4);
    expect(result.reason).toMatch(/does not link/i);
  });

  it('detects reordering', async () => {
    const chain = await chainOf(5);
    [chain[1], chain[2]] = [chain[2]!, chain[1]!];
    const result = await verifyChainAsync(chain, GENESIS_HASH);
    expect(result.valid).toBe(false);
  });

  it('detects a forged anchor', async () => {
    const chain = await chainOf(5);
    const result = await verifyChainAsync(chain, 'not-the-real-genesis');
    expect(result.valid).toBe(false);
    expect(result.failedAtSequence).toBe(1);
  });

  it('the synchronous link-check variant agrees on intact chains', async () => {
    const chain = await chainOf(3);
    expect(verifyChain(chain, GENESIS_HASH).valid).toBe(true);
  });
});

describe('redaction (NFR-SEC-003: secrets never reach the log)', () => {
  it('strips credential-shaped keys at the top level', () => {
    const out = redactForAudit({
      password: 'hunter2hunter2',
      note: 'harmless',
    });
    expect(out.password).toBe('[redacted]');
    expect(out.note).toBe('harmless');
  });

  it('strips credential-shaped keys at arbitrary depth', () => {
    const out = redactForAudit({
      request: {
        body: {
          authorizationPin: '123456',
          nested: { consumerSecret: 'very-secret-value' },
        },
      },
    });
    const body = out.request as { body: { authorizationPin: string; nested: { consumerSecret: string } } };
    expect(body.body.authorizationPin).toBe('[redacted]');
    expect(body.body.nested.consumerSecret).toBe('[redacted]');
  });

  it('masks long high-entropy strings under innocent-looking keys as a backstop', () => {
    const out = redactForAudit({
      blob: 'A'.repeat(48) + '+abc123=',
    });
    expect(out.blob).toBe('[redacted]');
  });

  it('leaves ordinary values untouched', () => {
    const out = redactForAudit({
      amountCents: 50000,
      message: 'Batch approved',
      shortHex: 'abc123',
    });
    expect(out.amountCents).toBe(50000);
    expect(out.message).toBe('Batch approved');
    expect(out.shortHex).toBe('abc123');
  });
});
