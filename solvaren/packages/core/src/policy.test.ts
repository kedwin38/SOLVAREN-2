/**
 * Risk signals (spec §11.1 — every family), policy gates with the financial calendar
 * (spec §10 cut-off/holiday), and the failure dictionary.
 */

import { describe, expect, it } from 'vitest';
import {
  assessBatchRisk,
  DEFAULT_RISK_POLICY,
  DEFAULT_POLICY,
  evaluateReleasePolicy,
  calendarBlockReason,
  type InstructionForRisk,
  type RecipientHistory,
} from './index.js';

const ins = (id: string, recipientId: string, amountCents: number, msisdn = `2547000000${id.length}`, departmentId: string | null = null): InstructionForRisk => ({
  instructionId: id,
  recipientId,
  msisdn,
  amountCents,
  departmentId,
});

const now = new Date('2026-09-14T08:00:00Z').getTime(); // 11:00 EAT — business hours

describe('risk signals (spec §11.1)', () => {
  it('flags an identical duplicate recipient+amount (HIGH/CRITICAL)', () => {
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 50000), ins('b', 'r1', 50000), ins('c', 'r1', 50000)],
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    const dup = result.signals.find((s) => s.type === 'DUPLICATE_INSTRUCTION');
    expect(dup).toBeDefined();
    expect(dup!.severity).toBe('CRITICAL'); // 3 occurrences
    expect(dup!.summary).toMatch(/appears 3 times/i);
  });

  it('flags amount deviation from recipient history', () => {
    const history = new Map<string, RecipientHistory>([
      ['r1', {
        recipientId: 'r1', meanAmountCents: 20_000_00, paymentCount: 6,
        medianIntervalHours: 720, firstPaidAt: now - 2 * 720 * 3.6e6, lastPaidAt: now - 720 * 3.6e6,
        recipientCreatedAt: now - 3 * 720 * 3.6e6, recipientLastModifiedAt: now - 720 * 3.6e6,
      }],
    ]);
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 100_000_00)],
      history,
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    const dev = result.signals.find((s) => s.type === 'AMOUNT_DEVIATION');
    expect(dev).toBeDefined();
    expect(dev!.evidence.ratio).toBe(5);
  });

  it('flags a brand-new recipient (MEDIUM) and a recently-added one (HIGH)', () => {
    const fresh = new Map<string, RecipientHistory>([
      ['r-new', {
        recipientId: 'r-new', meanAmountCents: 0, paymentCount: 0, medianIntervalHours: null,
        firstPaidAt: null, lastPaidAt: null, recipientCreatedAt: now - 2 * 3.6e6, recipientLastModifiedAt: now - 2 * 3.6e6,
      }],
    ]);
    const run = (history: Map<string, RecipientHistory>) =>
      assessBatchRisk({
        instructions: [ins('a', history.keys().next().value ?? 'r-x', 10000)],
        history,
        priorBatchTotalsCents: [],
        departmentBaselines: new Map(),
        departmentTotalsCents: new Map(),
        now,
        lastMaterialEditAt: null,
        submittedAt: null,
        unresolvedReconciliationCount: 0,
        approvalConcentration: [],
        policy: DEFAULT_RISK_POLICY,
      });

    expect(run(new Map()).signals.find((s) => s.type === 'NEW_RECIPIENT')!.severity).toBe('MEDIUM');
    expect(run(fresh).signals.find((s) => s.type === 'NEW_RECIPIENT')!.severity).toBe('HIGH');
  });

  it('flags a recently modified recipient record (HIGH)', () => {
    const history = new Map<string, RecipientHistory>([
      ['r1', {
        recipientId: 'r1', meanAmountCents: 10000, paymentCount: 5, medianIntervalHours: 720,
        firstPaidAt: now - 5 * 720 * 3.6e6, lastPaidAt: now - 720 * 3.6e6,
        recipientCreatedAt: now - 400 * 24 * 3.6e6, recipientLastModifiedAt: now - 1 * 3.6e6, // 1 hour ago
      }],
    ]);
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 10000)],
      history,
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'RECENTLY_MODIFIED_RECIPIENT')).toBeDefined();
  });

  it('flags unusual frequency — paid again within 24h of a prior payment', () => {
    const history = new Map<string, RecipientHistory>([
      ['r1', {
        recipientId: 'r1', meanAmountCents: 10000, paymentCount: 4, medianIntervalHours: 720,
        firstPaidAt: now - 4 * 720 * 3.6e6, lastPaidAt: now - 3 * 3.6e6, // 3 hours ago
        recipientCreatedAt: now - 400 * 24 * 3.6e6, recipientLastModifiedAt: now - 90 * 24 * 3.6e6,
      }],
    ]);
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 10000)],
      history,
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    const freq = result.signals.find((s) => s.type === 'UNUSUAL_FREQUENCY');
    expect(freq).toBeDefined();
    expect(freq!.severity).toBe('HIGH'); // < 6 hours
  });

  it('flags department variance against the trailing baseline', () => {
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 500_000_00, '254700000001', 'dept-1'), ins('b', 'r2', 500_000_00, '254700000002', 'dept-1')],
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map([['dept-1', { departmentId: 'dept-1', meanBatchTotalCents: 500_000_00, settledBatchCount: 4 }]]),
      departmentTotalsCents: new Map([['dept-1', 1_000_000_00]]), // 2× the baseline
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'DEPARTMENT_VARIANCE')).toBeDefined();
  });

  it('flags batch-total deviation against comparable settled batches', () => {
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 200_000_00)],
      history: new Map(),
      priorBatchTotalsCents: [100_000_00, 100_000_00, 100_000_00],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'BATCH_TOTAL_DEVIATION')).toBeDefined();
  });

  it('flags a late edit before submission', () => {
    const submittedAt = now;
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 10000)],
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: now - 2 * 60_000, // 2 minutes before submission
      submittedAt,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'LATE_EDIT')).toBeDefined();
  });

  it('flags processing outside business hours (EAT)', () => {
    const night = new Date('2026-09-14T20:00:00Z').getTime(); // 23:00 EAT
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 10000)],
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now: night,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'UNUSUAL_TIMING')).toBeDefined();
  });

  it('flags unresolved reconciliation anomalies, louder above five', () => {
    const run = (count: number) =>
      assessBatchRisk({
        instructions: [ins('a', 'r1', 10000)],
        history: new Map(),
        priorBatchTotalsCents: [],
        departmentBaselines: new Map(),
        departmentTotalsCents: new Map(),
        now,
        lastMaterialEditAt: null,
        submittedAt: null,
        unresolvedReconciliationCount: count,
        approvalConcentration: [],
        policy: DEFAULT_RISK_POLICY,
      });
    expect(run(1).signals.find((s) => s.type === 'UNRESOLVED_RECONCILIATION')!.severity).toBe('MEDIUM');
    expect(run(7).signals.find((s) => s.type === 'UNRESOLVED_RECONCILIATION')!.severity).toBe('HIGH');
  });

  it('flags approval-chain concentration as a collusion signal', () => {
    const result = assessBatchRisk({
      instructions: [ins('a', 'r1', 10000)],
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [{ pair: 'a→x', shareOfRecent: 0.9, occurrences: 9 }],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'APPROVAL_CHAIN_CONCENTRATION')).toBeDefined();
  });

  it('flags round-number clusters', () => {
    const result = assessBatchRisk({
      instructions: Array.from({ length: 10 }, (_, i) => ins(`i${i}`, `r${i}`, 50_000_00, `25470000000${i}`.slice(0, 12))),
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    expect(result.signals.find((s) => s.type === 'ROUND_NUMBER_CLUSTER')).toBeDefined();
  });

  it('is fully deterministic — same input, same score, always', () => {
    const input = {
      instructions: [ins('a', 'r1', 50000), ins('b', 'r2', 60000)],
      history: new Map() as Map<string, RecipientHistory>,
      priorBatchTotalsCents: [100_000],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: now - 60_000,
      submittedAt: now,
      unresolvedReconciliationCount: 2,
      approvalConcentration: [{ pair: 'a→b', shareOfRecent: 0.85, occurrences: 17 }],
      policy: DEFAULT_RISK_POLICY,
    } as const;
    const first = assessBatchRisk({ ...input });
    const second = assessBatchRisk({ ...input });
    expect(first.score).toBe(second.score);
    expect(first.band).toBe(second.band);
  });

  it('scores with diminishing returns per signal type (50 new recipients ≠ 50 anomaly classes)', () => {
    const manyNew = assessBatchRisk({
      instructions: Array.from({ length: 50 }, (_, i) => ins(`i${i}`, `new-r${i}`, 10_000, `2547000000${String(i).padStart(2, '0')}`.slice(0, 12))),
      history: new Map(),
      priorBatchTotalsCents: [],
      departmentBaselines: new Map(),
      departmentTotalsCents: new Map(),
      now,
      lastMaterialEditAt: null,
      submittedAt: null,
      unresolvedReconciliationCount: 0,
      approvalConcentration: [],
      policy: DEFAULT_RISK_POLICY,
    });
    // Harmonic sum of 50 MEDIUMs must stay well below 50 × 15 = 750.
    expect(manyNew.score).toBeLessThan(100);
  });
});

describe('policy evaluation with the financial calendar (spec §10, §21)', () => {
  const cleanRisk = { score: 0, band: 'LOW' as const, signals: [], requiresAcknowledgement: false };

  const input = (overrides: Partial<Parameters<typeof evaluateReleasePolicy>[0]> = {}) => ({
    policy: DEFAULT_POLICY,
    instructionCount: 10,
    totalAmountCents: 1_000_000_00,
    maxInstructionAmountCents: 200_000_00,
    risk: cleanRisk,
    dispositionedFindingCount: 0,
    disbursedTodayCents: 0,
    now,
    ...overrides,
  });

  it('passes a clean batch', () => {
    const result = evaluateReleasePolicy(input());
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('blocks on per-instruction limit', () => {
    const result = evaluateReleasePolicy(input({ maxInstructionAmountCents: 25_000_000_00 }));
    expect(result.allowed).toBe(false);
    expect(result.violations[0]!.code).toBe('POLICY_INSTRUCTION_LIMIT');
  });

  it('blocks on batch total', () => {
    const result = evaluateReleasePolicy(input({ totalAmountCents: 99_999_999_00 }));
    expect(result.violations.map((v) => v.code)).toContain('POLICY_BATCH_TOTAL');
  });

  it('blocks on the daily ceiling circuit breaker', () => {
    const result = evaluateReleasePolicy(
      input({ policy: { ...DEFAULT_POLICY, dailyDisbursementCeilingCents: 1_500_000_00 }, disbursedTodayCents: 1_000_000_00 }),
    );
    expect(result.violations.map((v) => v.code)).toContain('POLICY_DAILY_CEILING');
  });

  it('blocks on risk band with undispositioned findings', () => {
    const result = evaluateReleasePolicy(
      input({
        policy: { ...DEFAULT_POLICY, blockingRiskBand: 'HIGH' },
        risk: { score: 55, band: 'HIGH', signals: [{}, {}, {}] as never, requiresAcknowledgement: true },
        dispositionedFindingCount: 1,
      }),
    );
    expect(result.violations.map((v) => v.code)).toContain('POLICY_RISK_BLOCK');
  });

  it('requires a high-value acknowledgement', () => {
    const result = evaluateReleasePolicy(
      input({ policy: { ...DEFAULT_POLICY, highValueThresholdCents: 500_000_00 } }),
    );
    expect(result.allowed).toBe(true);
    expect(result.acknowledgementsRequired).toHaveLength(1);
    expect(result.acknowledgementsRequired[0]).toMatch(/high-value/i);
  });

  it('blocks a release after the cut-off time', () => {
    const evening = new Date('2026-09-14T15:30:00Z').getTime(); // 18:30 EAT, cut-off 17:00
    const result = evaluateReleasePolicy(
      input({ policy: { ...DEFAULT_POLICY, releaseCutoffLocalTime: '17:00' }, now: evening }),
    );
    expect(result.violations.map((v) => v.code)).toContain('POLICY_CALENDAR');
    expect(result.violations[0]!.message).toMatch(/cut-off.*17:00/i);
  });

  it('blocks a release on a configured holiday', () => {
    const holiday = new Date('2026-10-20T08:00:00Z').getTime(); // Mashujaa Day, Kenya
    const result = evaluateReleasePolicy(
      input({ policy: { ...DEFAULT_POLICY, holidayDates: ['2026-10-20'] }, now: holiday }),
    );
    expect(result.violations.map((v) => v.code)).toContain('POLICY_CALENDAR');
    expect(result.violations[0]!.message).toMatch(/2026-10-20/);
  });

  it('calendarBlockReason names the holiday directly', () => {
    expect(calendarBlockReason({ ...DEFAULT_POLICY, holidayDates: ['2026-12-25'] }, new Date('2026-12-25T08:00:00Z').getTime())).toMatch(/2026-12-25/);
    expect(calendarBlockReason({ ...DEFAULT_POLICY, holidayDates: [] }, new Date('2026-12-25T08:00:00Z').getTime())).toBeNull();
  });

  it('reports every violation, not just the first', () => {
    const result = evaluateReleasePolicy(
      input({ instructionCount: 99_999, totalAmountCents: 99_999_999_00, maxInstructionAmountCents: 25_000_000_00 }),
    );
    expect(result.violations.length).toBeGreaterThanOrEqual(2);
  });
});
