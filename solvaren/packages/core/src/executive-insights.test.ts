import { describe, expect, it } from 'vitest';
import { classifyMomentum, classifyRiskPosture, type MonthlyPoint } from './index.js';

describe('executive momentum classification', () => {
  const months = (...totalCents: number[]): MonthlyPoint[] =>
    totalCents.map((totalCents, i) => ({ period: `2026-${String(9 - i).padStart(2, '0')}`, totalCents }));

  it('reports insufficient data with fewer than four months', () => {
    expect(classifyMomentum(months(100, 100, 100))).toBe('INSUFFICIENT_DATA');
    expect(classifyMomentum([])).toBe('INSUFFICIENT_DATA');
  });

  it('reports insufficient data when the prior average is zero', () => {
    expect(classifyMomentum(months(100, 100, 0, 0))).toBe('INSUFFICIENT_DATA');
  });

  it('classifies a sustained rise as accelerating', () => {
    // recent avg 1400, prior avg 1000 -> +40%
    expect(classifyMomentum(months(1500, 1300, 1000, 1000))).toBe('ACCELERATING');
  });

  it('classifies a sustained fall as slowing', () => {
    // recent avg 600, prior avg 1000 -> -40%
    expect(classifyMomentum(months(500, 700, 1000, 1000))).toBe('SLOWING');
  });

  it('classifies a small wobble within the noise threshold as steady', () => {
    // recent avg 1030, prior avg 1000 -> +3%, below the 8% threshold
    expect(classifyMomentum(months(1050, 1010, 1000, 1000))).toBe('STEADY');
  });

  it('is not fooled by a single noisy month when the trailing average is flat', () => {
    // one big month (1800) averaged with a quiet one (200) still nets to the same trend
    expect(classifyMomentum(months(1800, 200, 1000, 1000))).toBe('STEADY');
  });
});

describe('executive risk posture classification', () => {
  it('is stable when every counter is zero', () => {
    const posture = classifyRiskPosture({
      openFindings: 0,
      criticalOrHighRiskBatches30d: 0,
      unresolvedReconciliationCases: 0,
    });
    expect(posture.band).toBe('STABLE');
    expect(posture.reasons).toHaveLength(0);
  });

  it('moves to watch on a small, non-alarming backlog', () => {
    const posture = classifyRiskPosture({
      openFindings: 2,
      criticalOrHighRiskBatches30d: 0,
      unresolvedReconciliationCases: 1,
    });
    expect(posture.band).toBe('WATCH');
    expect(posture.reasons.length).toBeGreaterThan(0);
  });

  it('escalates to elevated on any critical/high-risk batch, regardless of other counters', () => {
    const posture = classifyRiskPosture({
      openFindings: 0,
      criticalOrHighRiskBatches30d: 1,
      unresolvedReconciliationCases: 0,
    });
    expect(posture.band).toBe('ELEVATED');
    expect(posture.reasons[0]).toMatch(/critical\/high-risk batch/);
  });

  it('escalates to elevated once the reconciliation backlog passes the threshold', () => {
    const posture = classifyRiskPosture({
      openFindings: 0,
      criticalOrHighRiskBatches30d: 0,
      unresolvedReconciliationCases: 6,
    });
    expect(posture.band).toBe('ELEVATED');
  });

  it('escalates to elevated once open findings pass the threshold even with no batches or cases', () => {
    const posture = classifyRiskPosture({
      openFindings: 11,
      criticalOrHighRiskBatches30d: 0,
      unresolvedReconciliationCases: 0,
    });
    expect(posture.band).toBe('ELEVATED');
    expect(posture.reasons[0]).toMatch(/open risk findings/);
  });
});
