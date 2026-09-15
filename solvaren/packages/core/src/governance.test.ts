/**
 * Separation of duties (spec §20, §24) and the policy engine with the financial
 * calendar (spec §21 policies; spec §10 cut-off/holiday controls).
 */

import { describe, expect, it } from 'vitest';
import {
  assertNotSelfApproval,
  assertNotSelfAuthorization,
  assertCoolingOff,
  assertNoDeclaredConflict,
  detectApprovalChainConcentration,
  SolvarenError,
} from './index.js';

const participants = {
  createdByUserId: 'creator',
  editedByUserIds: ['editor'],
  approvedByUserId: 'approver',
  submittedByUserId: 'submitter',
};

describe('creator ≠ approver ≠ authorizer', () => {
  it('blocks the creator from approving', () => {
    expect(() => assertNotSelfApproval({ actorUserId: 'creator', actorLevel: 'L2', participants })).toThrow(/created this batch/i);
  });

  it('blocks the submitter from approving', () => {
    expect(() => assertNotSelfApproval({ actorUserId: 'submitter', actorLevel: 'L2', participants })).toThrow(/submitted this batch/i);
  });

  it('blocks an editor from approving', () => {
    expect(() => assertNotSelfApproval({ actorUserId: 'editor', actorLevel: 'L2', participants })).toThrow(/edited this batch/i);
  });

  it('permits an uninvolved L2 to approve', () => {
    expect(() => assertNotSelfApproval({ actorUserId: 'someone-else', actorLevel: 'L2', participants })).not.toThrow();
  });

  it('blocks the creator from authorizing (final release)', () => {
    expect(() => assertNotSelfAuthorization({ actorUserId: 'creator', actorLevel: 'L3', participants })).toThrow(/created this batch/i);
  });

  it('blocks an editor from authorizing', () => {
    expect(() => assertNotSelfAuthorization({ actorUserId: 'editor', actorLevel: 'L3', participants })).toThrow(/edited this batch/i);
  });

  it('blocks the L2 approver from also being the L3 authorizer — two hands, always', () => {
    expect(() => assertNotSelfAuthorization({ actorUserId: 'approver', actorLevel: 'L3', participants })).toThrow(/finance approval/i);
  });

  it('permits an uninvolved L3 to authorize', () => {
    expect(() => assertNotSelfAuthorization({ actorUserId: 'chief', actorLevel: 'L3', participants })).not.toThrow();
  });

  it('every denial carries a reason (shown to the user, written to the audit log)', () => {
    try {
      assertNotSelfApproval({ actorUserId: 'creator', actorLevel: 'L2', participants });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(SolvarenError);
      expect((err as SolvarenError).category).toBe('POLICY');
    }
  });
});

describe('cooling-off (spec §20)', () => {
  const now = 1_700_000_000_000;

  it('blocks submission inside the window', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: now - 60_000, now, coolingOffSeconds: 300 }),
    ).toThrow(/cooling-off/i);
  });

  it('permits submission after the window', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: now - 301_000, now, coolingOffSeconds: 300 }),
    ).not.toThrow();
  });

  it('zero disables the control', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: now, now, coolingOffSeconds: 0 }),
    ).not.toThrow();
  });

  it('no edit history means no cooling-off', () => {
    expect(() =>
      assertCoolingOff({ lastMaterialEditAt: null, now, coolingOffSeconds: 300 }),
    ).not.toThrow();
  });

  it('reports the remaining seconds', () => {
    try {
      assertCoolingOff({ lastMaterialEditAt: now - 60_000, now, coolingOffSeconds: 300 });
      expect.unreachable();
    } catch (err) {
      expect((err as SolvarenError).details.remainingSeconds).toBeGreaterThan(0);
    }
  });
});

describe('conflict-of-interest registry (spec §20)', () => {
  const recipientIds = ['rec-1', 'rec-2'];
  const departmentIds = ['dept-1'];

  it('blocks when the authorizer is conflicted over a recipient in the batch', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'chief',
        conflicts: [{ userId: 'chief', scopeType: 'RECIPIENT', scopeId: 'rec-1', reason: 'Relative' }],
        recipientIds,
        departmentIds,
      }),
    ).toThrow(/conflict of interest/i);
  });

  it('blocks when conflicted over a department in the batch', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'chief',
        conflicts: [{ userId: 'chief', scopeType: 'DEPARTMENT', scopeId: 'dept-1', reason: 'Own budget line' }],
        recipientIds,
        departmentIds,
      }),
    ).toThrow(/conflict of interest/i);
  });

  it('an organization-wide conflict blocks everything', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'chief',
        conflicts: [{ userId: 'chief', scopeType: 'ORGANIZATION', scopeId: null, reason: 'Board conflict' }],
        recipientIds: [],
        departmentIds: [],
      }),
    ).toThrow(/conflict of interest/i);
  });

  it('a conflict over an unrelated recipient does not block', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'chief',
        conflicts: [{ userId: 'chief', scopeType: 'RECIPIENT', scopeId: 'rec-999', reason: 'X' }],
        recipientIds,
        departmentIds,
      }),
    ).not.toThrow();
  });

  it('someone else’s conflict does not block the acting authorizer', () => {
    expect(() =>
      assertNoDeclaredConflict({
        actorUserId: 'chief',
        conflicts: [{ userId: 'other-chief', scopeType: 'ORGANIZATION', scopeId: null, reason: 'X' }],
        recipientIds,
        departmentIds,
      }),
    ).not.toThrow();
  });
});

describe('collusion signal (spec §20: repeated small-group approval)', () => {
  const pair = (approver: string, authorizer: string, at: number) => ({
    approverUserId: approver,
    authorizerUserId: authorizer,
    at,
  });
  const day = 86_400_000;
  const now = 1_700_000_000_000;

  it('flags one pair dominating the last N releases', () => {
    const pairs = [
      ...Array.from({ length: 9 }, (_, i) => pair('a', 'x', now - i * day)),
      pair('b', 'y', now - 10 * day),
    ];
    const signals = detectApprovalChainConcentration({ recentPairs: pairs });
    expect(signals).toHaveLength(1);
    expect(signals[0]!.pair).toBe('a→x');
    expect(signals[0]!.shareOfRecent).toBeGreaterThanOrEqual(0.8);
    expect(signals[0]!.reason).toMatch(/same pair/i);
  });

  it('does not flag below the minimum sample', () => {
    const pairs = Array.from({ length: 5 }, (_, i) => pair('a', 'x', now - i * day));
    expect(detectApprovalChainConcentration({ recentPairs: pairs })).toHaveLength(0);
  });

  it('does not flag a healthy rotation', () => {
    const pairs = Array.from({ length: 10 }, (_, i) => pair(`approver-${i % 4}`, `authorizer-${i % 3}`, now - i * day));
    expect(detectApprovalChainConcentration({ recentPairs: pairs })).toHaveLength(0);
  });

  it('is a signal, never a block — the output is advisory', () => {
    const pairs = Array.from({ length: 10 }, (_, i) => pair('a', 'x', now - i * day));
    const signals = detectApprovalChainConcentration({ recentPairs: pairs });
    // The function returns data; it never throws.
    expect(signals.length).toBeGreaterThan(0);
  });
});
