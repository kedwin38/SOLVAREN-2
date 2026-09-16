import { describe, expect, it } from 'vitest';
import { classifyOutcomeHealth, summarizeDurationBuckets } from './index.js';

describe('operational outcome health', () => {
  it('reports a neutral headline with no payments', () => {
    const health = classifyOutcomeHealth({ total: 0, success: 0, failed: 0, timeout: 0, inFlight: 0 });
    expect(health.band).toBe('HEALTHY');
    expect(health.successRate).toBeNull();
  });

  it('classifies a clean run as healthy', () => {
    const health = classifyOutcomeHealth({ total: 1000, success: 995, failed: 3, timeout: 2, inFlight: 0 });
    expect(health.band).toBe('HEALTHY');
    expect(health.successRate).toBeCloseTo(0.995);
    expect(health.headline).toMatch(/operating normally/);
  });

  it('classifies a small trouble share as watch', () => {
    const health = classifyOutcomeHealth({ total: 1000, success: 970, failed: 20, timeout: 10, inFlight: 0 });
    expect(health.band).toBe('WATCH');
    expect(health.headline).toMatch(/worth a look/);
  });

  it('classifies a large trouble share as degraded', () => {
    const health = classifyOutcomeHealth({ total: 1000, success: 900, failed: 70, timeout: 30, inFlight: 0 });
    expect(health.band).toBe('DEGRADED');
    expect(health.headline).toMatch(/needs attention/);
  });

  it('treats timeouts as trouble even when zero payments have hard-failed', () => {
    const health = classifyOutcomeHealth({ total: 100, success: 90, failed: 0, timeout: 10, inFlight: 0 });
    expect(health.band).toBe('DEGRADED');
  });
});

describe('settlement duration distribution', () => {
  it('reports a neutral headline with no settled payments', () => {
    const dist = summarizeDurationBuckets({ fast: 0, typical: 0, slow: 0 });
    expect(dist.total).toBe(0);
    expect(dist.headline).toMatch(/No settled payments/);
  });

  it('leads with the fast-settlement headline when most payments are fast', () => {
    const dist = summarizeDurationBuckets({ fast: 90, typical: 8, slow: 2 });
    expect(dist.fastPercent).toBe(90);
    expect(dist.headline).toMatch(/settle in under 30 seconds/);
  });

  it('flags a slow-settlement headline when a large share is slow', () => {
    const dist = summarizeDurationBuckets({ fast: 30, typical: 45, slow: 25 });
    expect(dist.slowPercent).toBe(25);
    expect(dist.headline).toMatch(/slower than usual/);
  });

  it('percentages sum to 100 for a non-empty distribution', () => {
    const dist = summarizeDurationBuckets({ fast: 33, typical: 33, slow: 34 });
    expect(dist.fastPercent + dist.typicalPercent + dist.slowPercent).toBe(100);
  });
});
