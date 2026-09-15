/**
 * Idempotency ledger (spec §9.3).
 *
 * Exactly-once payment execution is achieved by the *ordering* of two durable writes:
 *
 *   1. The idempotency claim transitions to SUBMITTED and **commits before** the provider
 *      is called. A worker that dies mid-call leaves a claim that says "a request may have
 *      reached M-PESA — go and find out", not "nothing happened, send it again".
 *   2. The claim carries a fingerprint derived from the instruction's identity *and
 *      content*; the executor re-derives it from live rows and refuses any mismatch, so a
 *      tampered queue message cannot redirect a payment.
 *
 * The state machine here is pure; persistence lives in the `idempotency_claims` table
 * with a unique fingerprint constraint.
 */

import { sha256Hex } from './manifest.js';

export type IdempotencyState = 'CLAIMED' | 'SUBMITTED' | 'SETTLED' | 'ABANDONED';

export interface IdempotencyRecord {
  fingerprint: string;
  state: IdempotencyState;
  originatorConversationId: string | null;
  transactionId: string | null;
  claimedAt: number;
  updatedAt: number;
}

export type ClaimDecision =
  | { action: 'PROCEED' }
  | { action: 'SKIP_ALREADY_SETTLED' }
  | { action: 'RECONCILE_FIRST'; reason: string };

/**
 * What the executor should do when it encounters a claim for this instruction.
 *
 *   no claim            → PROCEED (first attempt)
 *   CLAIMED             → PROCEED is safe only from the same release attempt; the
 *                         fingerprint match plus the one-live-job queue constraint make
 *                         a second claimant impossible in practice, so CLAIMED maps to
 *                         RECONCILE_FIRST — the conservative branch.
 *   SUBMITTED           → RECONCILE_FIRST (a request may have reached M-PESA)
 *   SETTLED / ABANDONED → skip
 */
export function decideOnExistingClaim(claim: IdempotencyRecord | null): ClaimDecision {
  if (!claim) return { action: 'PROCEED' };
  switch (claim.state) {
    case 'CLAIMED':
      return {
        action: 'RECONCILE_FIRST',
        reason: 'A claim exists but no submission was recorded; the outcome must be established before any resend',
      };
    case 'SUBMITTED':
      return {
        action: 'RECONCILE_FIRST',
        reason: 'A request was already submitted to M-PESA and its outcome is not yet known',
      };
    case 'SETTLED':
      return { action: 'SKIP_ALREADY_SETTLED' };
    case 'ABANDONED':
      return { action: 'SKIP_ALREADY_SETTLED' };
  }
}

/**
 * The fingerprint binds an execution attempt to the exact content it was authorized
 * under. If the batch is edited (amount, MSISDN, version) the fingerprint changes and
 * the executor refuses the message.
 */
export async function instructionFingerprint(input: {
  organizationId: string;
  batchId: string;
  instructionId: string;
  batchVersion: number;
  msisdn: string;
  amountCents: number;
  manifestHash: string;
}): Promise<string> {
  const canonical = [
    'SLV-IDEM-1',
    input.organizationId,
    input.batchId,
    input.instructionId,
    String(input.batchVersion),
    input.msisdn,
    String(input.amountCents),
    input.manifestHash,
  ].join('\x1f');
  return (await sha256Hex(canonical)).slice(0, 40);
}
