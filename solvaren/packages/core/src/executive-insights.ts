/**
 * Executive dashboard insight synthesis.
 *
 * The executive briefing's raw numbers (this month's total, a count of open findings, a
 * count of unresolved cases) don't answer the question an executive actually has —
 * "should I be worried, and about what." These functions turn a handful of independent
 * counters into the small set of synthesized, board-readable signals that do: is
 * disbursement volume accelerating or slowing, and what band is the organisation's risk
 * posture in right now. Both are pure and deterministic — same input, same output — so
 * the dashboard, the AI briefing context and a test suite all agree on what they mean.
 */

export type Momentum = 'ACCELERATING' | 'STEADY' | 'SLOWING' | 'INSUFFICIENT_DATA';

export interface MonthlyPoint {
  period: string;
  totalCents: number;
}

/** How far the trailing two-month average must move to call it a trend, not noise. */
const MOMENTUM_THRESHOLD = 0.08;

/**
 * Classify disbursement momentum from a trailing monthly series (most recent first).
 *
 * A single month-over-month percentage is noisy — one oversized payroll cycle or one
 * short month skews it in either direction. Comparing the average of the last two months
 * against the average of the two before that smooths exactly that noise out, at the cost
 * of needing four data points before it will commit to a direction.
 */
export function classifyMomentum(monthsDesc: readonly MonthlyPoint[]): Momentum {
  if (monthsDesc.length < 4) return 'INSUFFICIENT_DATA';
  const recentAvg = (monthsDesc[0]!.totalCents + monthsDesc[1]!.totalCents) / 2;
  const priorAvg = (monthsDesc[2]!.totalCents + monthsDesc[3]!.totalCents) / 2;
  if (priorAvg <= 0) return 'INSUFFICIENT_DATA';

  const change = (recentAvg - priorAvg) / priorAvg;
  if (change > MOMENTUM_THRESHOLD) return 'ACCELERATING';
  if (change < -MOMENTUM_THRESHOLD) return 'SLOWING';
  return 'STEADY';
}

export type RiskPostureBand = 'STABLE' | 'WATCH' | 'ELEVATED';

export interface RiskPostureInput {
  openFindings: number;
  criticalOrHighRiskBatches30d: number;
  unresolvedReconciliationCases: number;
}

export interface RiskPosture {
  band: RiskPostureBand;
  /** Human-readable reasons behind the band, empty when STABLE. */
  reasons: string[];
}

/** Above this many unresolved cases, a backlog stops looking like normal operating noise. */
const RECONCILIATION_BACKLOG_THRESHOLD = 5;
/** Above this many open findings, the review queue itself becomes a risk. */
const OPEN_FINDINGS_ELEVATED_THRESHOLD = 10;

/**
 * Synthesize one board-readable risk band from three counters that, read in isolation,
 * each look survivable — "3 open findings," "2 unresolved cases," "1 high-risk batch" —
 * but read together may not be. The band is the headline; `reasons` is the "why."
 */
export function classifyRiskPosture(input: RiskPostureInput): RiskPosture {
  const reasons: string[] = [];

  if (input.criticalOrHighRiskBatches30d > 0) {
    reasons.push(
      `${input.criticalOrHighRiskBatches30d} critical/high-risk batch${input.criticalOrHighRiskBatches30d === 1 ? '' : 'es'} in the last 30 days`,
    );
  }
  if (input.unresolvedReconciliationCases > 0) {
    reasons.push(
      `${input.unresolvedReconciliationCases} unresolved reconciliation case${input.unresolvedReconciliationCases === 1 ? '' : 's'}`,
    );
  }
  if (input.openFindings > OPEN_FINDINGS_ELEVATED_THRESHOLD) {
    reasons.push(`${input.openFindings} open risk findings awaiting review`);
  }

  let band: RiskPostureBand = 'STABLE';
  if (
    input.criticalOrHighRiskBatches30d > 0 ||
    input.unresolvedReconciliationCases > RECONCILIATION_BACKLOG_THRESHOLD ||
    input.openFindings > OPEN_FINDINGS_ELEVATED_THRESHOLD
  ) {
    band = 'ELEVATED';
  } else if (input.openFindings > 0 || input.unresolvedReconciliationCases > 0) {
    band = 'WATCH';
  }

  return { band, reasons };
}
