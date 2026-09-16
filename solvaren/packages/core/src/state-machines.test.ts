/**
 * Batch and transaction state machines (spec §6, §9.2, §24).
 *
 * Properties: no backward mutation by command; system-only edges reject human actors;
 * SUCCESS requires provider evidence; FAILED requires a code; settled states are
 * terminal and unrewritable.
 */

import { describe, expect, it } from 'vitest';
import {
  assertTransition,
  allowedCommands,
  BATCH_EDGES,
  isEditable,
  isTerminal,
  assertTxnTransition,
  isRetryEligible,
  statusTone,
  type BatchCommand,
  type BatchState,
} from './index.js';

const l1 = {
  level: 'L1' as const,
  permissions: new Set<import('./rbac.js').Permission>([
    'batch:create', 'batch:edit', 'batch:validate', 'batch:submit_to_l2', 'batch:cancel',
  ]),
};
const l2 = {
  level: 'L2' as const,
  permissions: new Set<import('./rbac.js').Permission>([
    ...l1.permissions, 'batch:review', 'batch:approve_to_l3', 'batch:reject', 'batch:hold', 'batch:release_hold',
  ]),
};
const l3 = {
  level: 'L3' as const,
  permissions: new Set<import('./rbac.js').Permission>([
    ...l2.permissions, 'payment:authorize', 'payment:release', 'batch:cancel',
  ]),
};

describe('batch state machine (spec §6)', () => {
  it('walks the full L1 → L2 → L3 path', () => {
    let state: BatchState = 'DRAFT';
    type AnyActor = typeof l1 | typeof l2 | typeof l3;
    const step = (command: BatchCommand, actor: AnyActor = l1, system = false) => {
      state = assertTransition(state, command, { actor, system }).to;
    };

    step('VALIDATE');
    expect(state).toBe('VALIDATED');
    step('SUBMIT_TO_L2');
    expect(state).toBe('SUBMITTED_TO_L2');
    step('BEGIN_L2_REVIEW', l2);
    expect(state).toBe('L2_REVIEW');
    step('APPROVE_TO_L3', l2);
    expect(state).toBe('L3_READY');
    step('BEGIN_AUTHORIZATION', l3);
    expect(state).toBe('AUTHORIZATION_PENDING');
    step('AUTHORIZE', l3);
    expect(state).toBe('AUTHORIZED');
    step('ENQUEUE', l1, true);
    expect(state).toBe('QUEUED');
    step('MARK_PROCESSING', l1, true);
    expect(state).toBe('PROCESSING');
    step('SETTLE_SUCCESS', l1, true);
    expect(state).toBe('SUCCESS');
  });

  it('L1 cannot approve (AC-01)', () => {
    expect(() =>
      assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { actor: l1 }),
    ).toThrow(/permission|belongs to/i);
  });

  it('L2 cannot authorize (AC-02)', () => {
    expect(() =>
      assertTransition('L3_READY', 'BEGIN_AUTHORIZATION', { actor: l2 }),
    ).toThrow(/permission|belongs to/i);
  });

  it('L3 may also perform the L2 review/approval edges (overall control)', () => {
    // The state machine has no concept of user identity — a *different* L3 individual
    // reviewing/approving is legitimate two hands. Same-individual self-approval is
    // blocked by `assertNotSelfApproval` at the identity layer (see governance.test.ts),
    // not here.
    expect(() =>
      assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { actor: l3 }),
    ).not.toThrow();
  });

  it('execution edges are system-only — no human can walk a batch to SUCCESS', () => {
    const cases: [BatchState, BatchCommand][] = [
      ['AUTHORIZED', 'ENQUEUE'],
      ['QUEUED', 'MARK_SUBMITTED'],
      ['QUEUED', 'MARK_PROCESSING'],
      ['PROCESSING', 'SETTLE_SUCCESS'],
      ['PROCESSING', 'SETTLE_PARTIAL'],
      ['PROCESSING', 'SETTLE_FAILED'],
      ['PROCESSING', 'SETTLE_TIMEOUT'],
    ];
    for (const [state, command] of cases) {
      expect(() => assertTransition(state, command, { actor: l3 })).toThrow(/system/i);
      expect(() => assertTransition(state, command, { actor: l3, system: true })).not.toThrow();
    }
  });

  it('system:true is not a skeleton key past a human edge', () => {
    expect(() => assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { system: true })).toThrow(/actor/i);
  });

  it('terminal states have no outbound human edges', () => {
    for (const state of ['SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'CANCELLED'] as BatchState[]) {
      const edges = BATCH_EDGES.filter((e) => e.from === state);
      expect(edges).toHaveLength(0);
    }
  });

  it('a settled batch cannot be walked anywhere by any command', () => {
    for (const command of ['VALIDATE', 'SUBMIT_TO_L2', 'BEGIN_AUTHORIZATION', 'AUTHORIZE', 'SETTLE_SUCCESS'] as BatchCommand[]) {
      expect(() => assertTransition('SUCCESS', command, { actor: l3, system: true })).toThrow();
    }
  });

  it('holds can be released — no dead-end workflow states', () => {
    expect(assertTransition('ON_HOLD', 'RELEASE_HOLD', { actor: l2 }).to).toBe('L2_REVIEW');
    expect(assertTransition('ON_HOLD', 'CANCEL', { actor: l3 }).to).toBe('CANCELLED');
  });

  it('returned batches can be resubmitted', () => {
    expect(assertTransition('RETURNED_FOR_CORRECTION', 'INVALIDATE', { actor: l1 }).to).toBe('DRAFT');
    expect(assertTransition('RETURNED_FOR_CORRECTION', 'SUBMIT_TO_L2', { actor: l1 }).to).toBe('SUBMITTED_TO_L2');
  });

  it('L3 can prepare a batch (validate, edit, submit, cancel) without L1 involvement', () => {
    expect(assertTransition('DRAFT', 'VALIDATE', { actor: l3 }).to).toBe('VALIDATED');
    expect(assertTransition('VALIDATED', 'INVALIDATE', { actor: l3 }).to).toBe('DRAFT');
    expect(assertTransition('RETURNED_FOR_CORRECTION', 'INVALIDATE', { actor: l3 }).to).toBe('DRAFT');
    expect(assertTransition('VALIDATED', 'SUBMIT_TO_L2', { actor: l3 }).to).toBe('SUBMITTED_TO_L2');
    expect(assertTransition('RETURNED_FOR_CORRECTION', 'SUBMIT_TO_L2', { actor: l3 }).to).toBe('SUBMITTED_TO_L2');
    expect(assertTransition('DRAFT', 'CANCEL', { actor: l3 }).to).toBe('CANCELLED');
    expect(assertTransition('VALIDATED', 'CANCEL', { actor: l3 }).to).toBe('CANCELLED');
    expect(assertTransition('RETURNED_FOR_CORRECTION', 'CANCEL', { actor: l3 }).to).toBe('CANCELLED');
  });

  it("L1's own preparation access is unaffected by L3 also owning those edges", () => {
    expect(assertTransition('DRAFT', 'VALIDATE', { actor: l1 }).to).toBe('VALIDATED');
    expect(assertTransition('VALIDATED', 'SUBMIT_TO_L2', { actor: l1 }).to).toBe('SUBMITTED_TO_L2');
    expect(assertTransition('DRAFT', 'CANCEL', { actor: l1 }).to).toBe('CANCELLED');
  });

  it('L2 still cannot prepare a batch (unchanged)', () => {
    expect(() => assertTransition('DRAFT', 'VALIDATE', { actor: l2 })).toThrow(/belongs to/i);
    expect(() => assertTransition('VALIDATED', 'SUBMIT_TO_L2', { actor: l2 })).toThrow(/belongs to/i);
  });

  it('an L3-prepared batch still requires a review/approval step before authorization', () => {
    let state: BatchState = 'DRAFT';
    const step = (command: BatchCommand, actor: typeof l1 | typeof l2 | typeof l3) => {
      state = assertTransition(state, command, { actor }).to;
    };
    step('VALIDATE', l3);
    step('SUBMIT_TO_L2', l3);
    expect(state).toBe('SUBMITTED_TO_L2');
    step('BEGIN_L2_REVIEW', l2);
    step('APPROVE_TO_L3', l2);
    expect(state).toBe('L3_READY');
    step('BEGIN_AUTHORIZATION', l3);
    step('AUTHORIZE', l3);
    // The state machine itself has no user identity — whether the authorizing L3 here
    // is or isn't the same person who prepared the batch is decided by the separate
    // identity-based `assertNotSelfAuthorization` check (sod.ts), which by organizational
    // decision exempts L3 entirely (governance.test.ts: "L3 exemption — overall control").
    // L1 and L2 remain fully bound by it; only L3 may go end to end alone.
    expect(state).toBe('AUTHORIZED');
  });

  it('L3 can open and carry out review end-to-end (batch:review, batch:hold, batch:reject, batch:release_hold, batch:approve_to_l3 all reachable at L3)', () => {
    expect(assertTransition('SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', { actor: l3 }).to).toBe('L2_REVIEW');
    expect(assertTransition('SUBMITTED_TO_L2', 'HOLD', { actor: l3 }).to).toBe('ON_HOLD');
    expect(assertTransition('SUBMITTED_TO_L2', 'REJECT', { actor: l3 }).to).toBe('REJECTED');
    expect(assertTransition('L2_REVIEW', 'HOLD', { actor: l3 }).to).toBe('ON_HOLD');
    expect(assertTransition('L2_REVIEW', 'REJECT', { actor: l3 }).to).toBe('REJECTED');
    expect(assertTransition('L2_REVIEW', 'RETURN_TO_L1', { actor: l3 }).to).toBe('RETURNED_FOR_CORRECTION');
    expect(assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { actor: l3 }).to).toBe('L3_READY');
    expect(assertTransition('ON_HOLD', 'RELEASE_HOLD', { actor: l3 }).to).toBe('L2_REVIEW');
  });

  it("L2's own review access is unaffected by L3 also owning those edges", () => {
    expect(assertTransition('SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', { actor: l2 }).to).toBe('L2_REVIEW');
    expect(assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { actor: l2 }).to).toBe('L3_READY');
    expect(assertTransition('ON_HOLD', 'RELEASE_HOLD', { actor: l2 }).to).toBe('L2_REVIEW');
  });

  it('L1 still cannot review or approve (unchanged)', () => {
    expect(() => assertTransition('SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', { actor: l1 })).toThrow(/belongs to/i);
    expect(() => assertTransition('L2_REVIEW', 'APPROVE_TO_L3', { actor: l1 })).toThrow(/belongs to/i);
  });

  it('only editable states are DRAFT, VALIDATED and RETURNED_FOR_CORRECTION', () => {
    expect(isEditable('DRAFT')).toBe(true);
    expect(isEditable('VALIDATED')).toBe(true);
    expect(isEditable('RETURNED_FOR_CORRECTION')).toBe(true);
    expect(isEditable('SUBMITTED_TO_L2')).toBe(false);
    expect(isEditable('L3_READY')).toBe(false);
    expect(isEditable('SUCCESS')).toBe(false);
  });

  it('allowedCommands lists the legal moves for a state', () => {
    expect(allowedCommands('L3_READY')).toContain('BEGIN_AUTHORIZATION');
    expect(allowedCommands('DRAFT')).not.toContain('AUTHORIZE');
  });

  it('isTerminal identifies terminal states', () => {
    expect(isTerminal('SUCCESS')).toBe(true);
    expect(isTerminal('CANCELLED')).toBe(true);
    expect(isTerminal('PROCESSING')).toBe(false);
  });
});

describe('transaction state machine (spec §9.2)', () => {
  it('walks PENDING → SUBMITTED → AWAITING_CALLBACK → SUCCESS with evidence', () => {
    expect(assertTxnTransition({ from: 'PENDING', to: 'SUBMITTED', source: 'SYSTEM' }).to).toBe('SUBMITTED');
    expect(
      assertTxnTransition({ from: 'SUBMITTED', to: 'AWAITING_CALLBACK', source: 'SYNC_ACK' }).to,
    ).toBe('AWAITING_CALLBACK');
    expect(
      assertTxnTransition({
        from: 'AWAITING_CALLBACK',
        to: 'SUCCESS',
        source: 'CALLBACK',
        providerReceipt: 'SG632NMUAB',
      }).to,
    ).toBe('SUCCESS');
  });

  it('SUCCESS from a SYSTEM source is refused — no forged success (§24)', () => {
    expect(() =>
      assertTxnTransition({ from: 'AWAITING_CALLBACK', to: 'SUCCESS', source: 'SYSTEM', providerReceipt: 'X' }),
    ).toThrow(/provider callback or status query/i);
  });

  it('SUCCESS without a receipt is refused — evidence, not assertion', () => {
    expect(() =>
      assertTxnTransition({ from: 'AWAITING_CALLBACK', to: 'SUCCESS', source: 'CALLBACK', providerReceipt: '' }),
    ).toThrow(/receipt/i);
    expect(() =>
      assertTxnTransition({ from: 'AWAITING_CALLBACK', to: 'SUCCESS', source: 'CALLBACK' }),
    ).toThrow(/receipt/i);
  });

  it('FAILED without a failure code is refused (TRK-002)', () => {
    expect(() =>
      assertTxnTransition({ from: 'AWAITING_CALLBACK', to: 'FAILED', source: 'CALLBACK' }),
    ).toThrow(/failure code/i);
  });

  it('settled states refuse every rewrite', () => {
    for (const settled of ['SUCCESS', 'FAILED', 'CANCELLED'] as const) {
      for (const to of ['SUCCESS', 'FAILED', 'TIMEOUT', 'RECONCILING', 'PENDING'] as const) {
        if (to === settled) continue; // the identical re-delivery no-op is tested separately
        expect(() =>
          assertTxnTransition({ from: settled, to, source: 'CALLBACK', providerReceipt: 'X', failureCode: '1' }),
        ).toThrow(/already settled/i);
      }
    }
  });

  it('an identical re-delivery is an idempotent no-op, not an error', () => {
    const result = assertTxnTransition({ from: 'SUCCESS', to: 'SUCCESS', source: 'CALLBACK' });
    expect(result.opensReconciliation).toBe(false);
  });

  it('TIMEOUT opens reconciliation', () => {
    const result = assertTxnTransition({ from: 'AWAITING_CALLBACK', to: 'TIMEOUT', source: 'QUEUE_TIMEOUT', failureCode: 'SLV_TIMEOUT' });
    expect(result.opensReconciliation).toBe(true);
  });

  it('illegal edges are refused with the allowed set', () => {
    try {
      assertTxnTransition({ from: 'PENDING', to: 'SUCCESS', source: 'CALLBACK', providerReceipt: 'X' });
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).toMatch(/cannot move/i);
    }
  });
});

describe('retry eligibility (spec §9.3)', () => {
  it('only FAILED transactions with a code can be retried', () => {
    expect(isRetryEligible('FAILED', '1')).toBe(true); // insufficient balance — transient
    expect(isRetryEligible('FAILED', '17')).toBe(true); // internal failure
    expect(isRetryEligible('SUCCESS', '1')).toBe(false);
    expect(isRetryEligible('TIMEOUT', null)).toBe(false);
    expect(isRetryEligible('FAILED', null)).toBe(false);
  });

  it('permanent failures are not retryable — they fail identically until a human acts', () => {
    const permanent = ['2001', '2040', '8006', '21', '2028', 'SFC_IC0003', '2', '3', '4', '8'];
    for (const code of permanent) {
      expect(isRetryEligible('FAILED', code)).toBe(false);
    }
  });
});

describe('status tone (WCAG 1.4.1 — never colour alone)', () => {
  it('maps every state to a tone', () => {
    const states = ['PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'RECONCILING', 'SUCCESS', 'FAILED', 'TIMEOUT', 'CANCELLED'] as const;
    for (const state of states) {
      const tone = statusTone(state);
      expect(['success', 'danger', 'warning', 'info', 'neutral']).toContain(tone);
    }
  });
});
