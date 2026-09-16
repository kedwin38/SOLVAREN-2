/**
 * Operational-dashboard insight synthesis (companion to executive-insights.ts).
 *
 * A median-processing-seconds figure and a 95th-percentile figure are exactly the right
 * numbers for capacity planning and exactly the wrong numbers for a payroll operator
 * glancing at a dashboard — "28s" and "112s" answer a question nobody watching this
 * screen asked. What they actually want to know is closer to "is this working" and "is
 * money moving at a normal pace," which is a distribution and a plain sentence, not two
 * isolated statistics. These functions compute both from the same underlying counts the
 * percentile query already produces, so nothing extra has to be fetched.
 */

export interface OutcomeCounts {
  total: number;
  success: number;
  failed: number;
  timeout: number;
  inFlight: number;
}

export type OutcomeHealthBand = 'HEALTHY' | 'WATCH' | 'DEGRADED';

export interface OutcomeHealth {
  band: OutcomeHealthBand;
  successRate: number | null;
  failureRate: number | null;
  timeoutRate: number | null;
  /** One plain-language sentence: the headline a non-technical reader takes away. */
  headline: string;
}

/** Below this failure+timeout share, operations read as normal, not a signal to chase. */
const WATCH_THRESHOLD = 0.02;
/** Above this share, something is actually wrong, not routine payroll noise. */
const DEGRADED_THRESHOLD = 0.08;

/**
 * Turn raw outcome counts into one qualitative read plus the rates behind it. The band
 * is driven by failed+timeout together, not failure alone — a payment stuck in TIMEOUT
 * is exactly as much "not what should be happening" as one that came back FAILED, even
 * though it isn't wrong yet.
 */
export function classifyOutcomeHealth(counts: OutcomeCounts): OutcomeHealth {
  if (counts.total === 0) {
    return { band: 'HEALTHY', successRate: null, failureRate: null, timeoutRate: null, headline: 'No payments in the last 30 days.' };
  }

  const successRate = counts.success / counts.total;
  const failureRate = counts.failed / counts.total;
  const timeoutRate = counts.timeout / counts.total;
  const troubleRate = failureRate + timeoutRate;

  let band: OutcomeHealthBand = 'HEALTHY';
  if (troubleRate >= DEGRADED_THRESHOLD) band = 'DEGRADED';
  else if (troubleRate >= WATCH_THRESHOLD) band = 'WATCH';

  const successPercent = Math.round(successRate * 1000) / 10;
  const headline =
    band === 'HEALTHY'
      ? `${successPercent}% of payments succeed — operating normally.`
      : band === 'WATCH'
        ? `${successPercent}% of payments succeed — a small share are failing or timing out, worth a look.`
        : `${successPercent}% of payments succeed — failures and timeouts are running above normal, this needs attention.`;

  return { band, successRate, failureRate, timeoutRate, headline };
}

export interface DurationBucketCounts {
  /** Settled in under FAST_THRESHOLD_SECONDS. */
  fast: number;
  /** Settled between the fast and slow thresholds. */
  typical: number;
  /** Took SLOW_THRESHOLD_SECONDS or longer to settle. */
  slow: number;
}

export const FAST_THRESHOLD_SECONDS = 30;
export const SLOW_THRESHOLD_SECONDS = 120;

export interface DurationDistribution {
  total: number;
  fast: number;
  typical: number;
  slow: number;
  fastPercent: number;
  typicalPercent: number;
  slowPercent: number;
  /** One plain-language sentence a non-technical reader can act on. */
  headline: string;
}

/**
 * Turn a three-bucket settlement-time histogram into percentages and a sentence.
 * "82% settle in under 30 seconds" is a distribution an operator can reason about;
 * "median 28s, p95 112s" requires already knowing what a percentile is.
 */
export function summarizeDurationBuckets(counts: DurationBucketCounts): DurationDistribution {
  const total = counts.fast + counts.typical + counts.slow;
  if (total === 0) {
    return {
      total: 0,
      fast: 0,
      typical: 0,
      slow: 0,
      fastPercent: 0,
      typicalPercent: 0,
      slowPercent: 0,
      headline: 'No settled payments in the last 30 days.',
    };
  }

  const fastPercent = Math.round((counts.fast / total) * 100);
  const slowPercent = Math.round((counts.slow / total) * 100);
  const typicalPercent = Math.max(0, 100 - fastPercent - slowPercent);

  const headline =
    fastPercent >= 80
      ? `${fastPercent}% of payments settle in under ${FAST_THRESHOLD_SECONDS} seconds.`
      : slowPercent >= 20
        ? `${slowPercent}% of payments are taking ${SLOW_THRESHOLD_SECONDS >= 60 ? `${Math.round(SLOW_THRESHOLD_SECONDS / 60)} minute${SLOW_THRESHOLD_SECONDS >= 120 ? 's' : ''}` : `${SLOW_THRESHOLD_SECONDS}s`}+ to settle — slower than usual.`
        : `Most payments settle within ${Math.round(SLOW_THRESHOLD_SECONDS / 60)} minutes.`;

  return { total, fast: counts.fast, typical: counts.typical, slow: counts.slow, fastPercent, typicalPercent, slowPercent, headline };
}
