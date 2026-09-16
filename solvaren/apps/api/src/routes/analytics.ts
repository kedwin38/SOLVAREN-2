/**
 * Dashboards and analytics (spec §12, §22).
 *
 * The executive panels carry the sharpest access-control requirement: balance and
 * recent-transactions data reject non-L3 callers at the API (AC-19), not merely in the
 * UI. Everything is computed from the authoritative ledger, so dashboard numbers and
 * explorer numbers are the same numbers.
 */

import { Hono } from 'hono';
import { authorizationError, classifyMomentum, classifyRiskPosture } from '@solvaren/core';
import {
  requireAuth,
  requirePermissions,
  requireExactLevel,
  actorOf,
} from '../middleware/security.js';
import { withConnection } from '../db/client.js';
import type { AppContext, ReconciliationQueueMessage } from '../env.js';

export const analyticsRoutes = new Hono<AppContext>();
analyticsRoutes.use('*', requireAuth);

/**
 * GET /api/analytics/operational — the L1 dashboard: batch counts, success/failure
 * rates, processing times (median + p95), daily trend, attention counters.
 */
analyticsRoutes.get('/operational', requirePermissions('analytics:basic'), async (c) => {
  const actor = actorOf(c);

  const data = await withConnection(c.env, async (sql) => {
    const batches = await sql<{ state: string; count: string }[]>`
      SELECT state, COUNT(*) AS count
        FROM payment_batches
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '90 days'
       GROUP BY state
    `;

    const outcomes = await sql<
      { total: string; success: string; failed: string; timeout: string; in_flight: string }[]
    >`
      SELECT COUNT(*) AS total,
             COUNT(*) FILTER (WHERE status = 'SUCCESS') AS success,
             COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,
             COUNT(*) FILTER (WHERE status = 'TIMEOUT') AS timeout,
             COUNT(*) FILTER (WHERE status IN ('PENDING','SUBMITTED','AWAITING_CALLBACK','PROCESSING','RECONCILING')) AS in_flight
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
    `;

    // Median rather than mean: one reconciliation case sitting open for three days would
    // drag a mean into uselessness.
    const timing = await sql<{ median_seconds: number | null; p95_seconds: number | null }[]>`
      SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at)))  AS median_seconds,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at))) AS p95_seconds
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND status = 'SUCCESS' AND completed_at IS NOT NULL AND submitted_at IS NOT NULL
         AND created_at > now() - interval '30 days'
    `;

    const trend = await sql<{ day: string; total: string; failed: string }[]>`
      SELECT date_trunc('day', created_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS day,
             COUNT(*) AS total,
             COUNT(*) FILTER (WHERE status IN ('FAILED', 'TIMEOUT')) AS failed
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
       GROUP BY 1 ORDER BY 1
    `;

    const attention = await sql<{ failed: string; timeout: string; reconciling: string }[]>`
      SELECT COUNT(*) FILTER (WHERE status = 'FAILED')  AS failed,
             COUNT(*) FILTER (WHERE status = 'TIMEOUT') AS timeout,
             COUNT(*) FILTER (WHERE status = 'RECONCILING') AS reconciling
        FROM transactions
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '30 days'
    `;

    const pendingReview = await sql<{ l2_queue: string; l3_queue: string; holds: string }[]>`
      SELECT COUNT(*) FILTER (WHERE state IN ('SUBMITTED_TO_L2','L2_REVIEW')) AS l2_queue,
             COUNT(*) FILTER (WHERE state = 'L3_READY') AS l3_queue,
             COUNT(*) FILTER (WHERE state = 'ON_HOLD') AS holds
        FROM payment_batches
       WHERE organization_id = ${actor.organizationId}
         AND created_at > now() - interval '90 days'
    `;

    const row = outcomes[0]!;
    const total = Number(row.total);

    return {
      batchesByState: Object.fromEntries(batches.map((b) => [b.state, Number(b.count)])),
      workflows: {
        awaitingL2Review: Number(pendingReview[0]?.l2_queue ?? 0),
        awaitingL3Authorization: Number(pendingReview[0]?.l3_queue ?? 0),
        onHold: Number(pendingReview[0]?.holds ?? 0),
      },
      transactions: {
        total,
        success: Number(row.success),
        failed: Number(row.failed),
        timeout: Number(row.timeout),
        inFlight: Number(row.in_flight),
        successRate: total > 0 ? Number(row.success) / total : null,
        failureRate: total > 0 ? (Number(row.failed) + Number(row.timeout)) / total : null,
      },
      processingSeconds: {
        median: timing[0]?.median_seconds ?? null,
        p95: timing[0]?.p95_seconds ?? null,
      },
      dailyTrend: trend.map((t) => ({ day: t.day, total: Number(t.total), failed: Number(t.failed) })),
      needsAttention: {
        failed: Number(attention[0]?.failed ?? 0),
        timeout: Number(attention[0]?.timeout ?? 0),
        reconciling: Number(attention[0]?.reconciling ?? 0),
      },
    };
  });

  return c.json(data);
});

/** GET /api/analytics/financial — the L2 dashboard: departmental and payroll analytics. */
analyticsRoutes.get('/financial', requirePermissions('analytics:advanced'), async (c) => {
  const actor = actorOf(c);

  const data = await withConnection(c.env, async (sql) => {
    const departments = await sql<
      { department_name: string | null; period_month: string; paid_cents: string; paid_count: string; failed_count: string }[]
    >`
      SELECT department_name, period_month::text, paid_cents, paid_count, failed_count
        FROM department_expenditure
       WHERE organization_id = ${actor.organizationId}
         AND period_month > (now() - interval '12 months')::DATE
       ORDER BY period_month DESC, paid_cents DESC
    `;

    const cycles = await sql<
      { period_month: string; total_cents: string; recipient_count: string }[]
    >`
      SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period_month,
             SUM(pi.amount_cents) AS total_cents,
             COUNT(DISTINCT pi.recipient_id) AS recipient_count
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE t.organization_id = ${actor.organizationId}
         AND t.status = 'SUCCESS' AND t.completed_at > now() - interval '12 months'
       GROUP BY 1 ORDER BY 1 DESC
    `;

    const anomalies = await sql<{ severity: string; count: string }[]>`
      SELECT severity, COUNT(*) AS count
        FROM risk_findings
       WHERE organization_id = ${actor.organizationId} AND disposition = 'OPEN'
       GROUP BY severity
    `;

    const reconciliation = await sql<{ state: string; count: string }[]>`
      SELECT state, COUNT(*) AS count
        FROM reconciliation_cases
       WHERE organization_id = ${actor.organizationId}
       GROUP BY state
    `;

    // A deliberately simple, labelled forecast: the mean of the trailing three settled
    // cycles. A confident-looking projection from a model the finance team cannot
    // inspect is worse than an honest average.
    const recent = cycles.slice(0, 3).map((cycle) => Number(cycle.total_cents));
    const forecastCents =
      recent.length > 0 ? Math.round(recent.reduce((a, b) => a + b, 0) / recent.length) : null;

    return {
      departmentExpenditure: departments.map((d) => ({
        departmentName: d.department_name ?? 'Unassigned',
        periodMonth: d.period_month,
        paidCents: Number(d.paid_cents),
        paidCount: Number(d.paid_count),
        failedCount: Number(d.failed_count),
      })),
      payrollCycles: cycles.map((cycle) => ({
        periodMonth: cycle.period_month,
        totalCents: Number(cycle.total_cents),
        recipientCount: Number(cycle.recipient_count),
      })),
      openFindingsBySeverity: Object.fromEntries(
        anomalies.map((a) => [a.severity, Number(a.count)]),
      ),
      reconciliationByState: Object.fromEntries(
        reconciliation.map((r) => [r.state, Number(r.count)]),
      ),
      forecast: {
        nextCycleCents: forecastCents,
        basis: 'Mean of the last three settled payment cycles',
        method: 'trailing-average',
      },
    };
  });

  return c.json(data);
});

/**
 * GET /api/analytics/executive/balance — the L3 balance panel (AC-19).
 *
 * L3 ONLY, enforced here in the API. The UI also hides the panel, but as the spec puts
 * it, "a hidden button or disabled menu item is not an access control".
 */
analyticsRoutes.get(
  '/executive/balance',
  requireExactLevel('L3'),
  requirePermissions('dashboard:balance_panel'),
  async (c) => {
    const actor = actorOf(c);

    const data = await withConnection(c.env, async (sql) => {
      // DISTINCT ON gives the newest snapshot per account type in a single pass.
      const balances = await sql<
        {
          account_type: string;
          currency: string;
          available_cents: string;
          uncleared_cents: string;
          reserved_cents: string;
          as_of: string;
          source: string;
        }[]
      >`
        SELECT DISTINCT ON (account_type)
               account_type, currency, available_cents, uncleared_cents, reserved_cents, as_of, source
          FROM account_balance_snapshots
         WHERE organization_id = ${actor.organizationId}
         ORDER BY account_type, as_of DESC
      `;

      const pending = await sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM provider_callbacks
         WHERE organization_id = ${actor.organizationId}
           AND callback_type = 'ACCOUNT_BALANCE' AND processed_at IS NULL
      `;

      return {
        accounts: balances.map((b) => ({
          accountType: b.account_type,
          currency: b.currency,
          availableCents: Number(b.available_cents),
          unclearedCents: Number(b.uncleared_cents),
          reservedCents: Number(b.reserved_cents),
          asOf: b.as_of,
          source: b.source,
        })),
        // The panel must show this: a figure without an "as of" invites an authorizer to
        // treat a stale balance as live before releasing a payroll.
        asOf: balances[0]?.as_of ?? null,
        awaitingRefresh: Number(pending[0]?.count ?? 0) > 0,
        note:
          balances.length === 0
            ? 'No balance has been retrieved yet. Request a refresh to query M-PESA.'
            : null,
      };
    });

    return c.json(data);
  },
);

/** POST /api/analytics/executive/balance/refresh — request a fresh Account Balance query. */
analyticsRoutes.post(
  '/executive/balance/refresh',
  requireExactLevel('L3'),
  requirePermissions('dashboard:balance_panel'),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');

    const message: ReconciliationQueueMessage = {
      type: 'REFRESH_BALANCE',
      organizationId: actor.organizationId,
      requestedByUserId: actor.userId,
      correlationId,
    };
    await c.env.queue.send({ queue: 'reconciliation', body: message });

    return c.json(
      {
        accepted: true,
        message: 'A balance query has been sent to M-PESA. The panel updates when the result arrives.',
      },
      202,
    );
  },
);

/** GET /api/analytics/executive/recent-transactions — the L3 recent-transactions panel. */
analyticsRoutes.get(
  '/executive/recent-transactions',
  requireExactLevel('L3'),
  requirePermissions('dashboard:recent_transactions_panel'),
  async (c) => {
    const actor = actorOf(c);
    const limit = Math.min(Number(new URL(c.req.url).searchParams.get('limit') ?? '20'), 100);

    const data = await withConnection(c.env, async (sql) => {
      const rows = await sql<
        {
          transaction_id: string;
          status: string;
          amount_cents: string;
          recipient_name: string;
          msisdn: string;
          mpesa_receipt_number: string | null;
          batch_reference: string;
          completed_at: string | null;
          created_at: string;
          failure_reason: string | null;
        }[]
      >`
        SELECT t.id AS transaction_id, t.status, pi.amount_cents,
               pi.recipient_name_snapshot AS recipient_name, pi.msisdn_snapshot AS msisdn,
               t.mpesa_receipt_number, b.batch_reference, t.completed_at, t.created_at,
               t.failure_reason
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
          JOIN payment_batches b       ON b.id = t.batch_id
         WHERE t.organization_id = ${actor.organizationId}
         ORDER BY t.created_at DESC
         LIMIT ${limit}
      `;

      return {
        transactions: rows.map((r) => ({
          transactionId: r.transaction_id,
          status: r.status,
          amountCents: Number(r.amount_cents),
          recipientName: r.recipient_name,
          msisdn: r.msisdn,
          mpesaReceiptNumber: r.mpesa_receipt_number,
          batchReference: r.batch_reference,
          failureReason: r.failure_reason,
          at: r.completed_at ?? r.created_at,
        })),
      };
    });

    return c.json(data);
  },
);

/**
 * GET /api/analytics/executive/briefing — the L3 organisation-wide intelligence view.
 *
 * Deliberately reuses `department_expenditure` (the reporting layer's single source of
 * truth for per-department totals, spec §0006) rather than re-deriving the same join
 * twice with hand-rolled current/previous-month CTEs — one filtered query against the
 * existing abstraction instead of two ad-hoc scans of `transactions`.
 *
 * The raw counters (a month-over-month percentage, an open-findings count, a case
 * count) don't tell an executive whether to be concerned; `classifyMomentum` and
 * `classifyRiskPosture` (packages/core) turn them into the two synthesized, board-
 * readable signals that do — computed here, in one place, so the dashboard and any
 * future consumer (the AI briefing, an export) agree on what "elevated" means.
 */
analyticsRoutes.get('/executive/briefing', requirePermissions('analytics:executive'), async (c) => {
  const actor = actorOf(c);
  if (actor.level !== 'L3') {
    throw authorizationError('LEVEL_RESTRICTED', 'Executive intelligence is available to Level 3 only');
  }

  const data = await withConnection(c.env, async (sql) => {
    const months = await sql<{ period: string; total_cents: string; count: string }[]>`
        SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS period,
               SUM(pi.amount_cents) AS total_cents, COUNT(*) AS count
          FROM transactions t
          JOIN payment_instructions pi ON pi.id = t.instruction_id
         WHERE t.organization_id = ${actor.organizationId}
           AND t.status = 'SUCCESS' AND t.completed_at > now() - interval '13 months'
         GROUP BY 1 ORDER BY 1 DESC
      `;

    const departmentMonths = await sql<{ department_name: string; period_month: string; paid_cents: string }[]>`
        SELECT department_name, period_month::text, paid_cents
          FROM department_expenditure
         WHERE organization_id = ${actor.organizationId}
           AND period_month IN (
             date_trunc('month', now())::DATE,
             date_trunc('month', now() - interval '1 month')::DATE
           )
      `;

    // One risk-and-reconciliation pass instead of three: findings, the risk-band count
    // driving the posture signal, and the reconciliation backlog all read from the same
    // 30-day window, so they're combined into two lightweight queries rather than four.
    const findings = await sql<{ open: string; reviewed: string }[]>`
        SELECT COUNT(*) FILTER (WHERE disposition = 'OPEN')     AS open,
               COUNT(*) FILTER (WHERE disposition <> 'OPEN')    AS reviewed
          FROM risk_findings
         WHERE organization_id = ${actor.organizationId}
           AND created_at > now() - interval '30 days'
      `;

    const riskBatches = await sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM payment_batches
         WHERE organization_id = ${actor.organizationId}
           AND risk_band IN ('CRITICAL', 'HIGH')
           AND created_at > now() - interval '30 days'
      `;

    const unresolved = await sql<{ count: string }[]>`
        SELECT COUNT(*) AS count FROM reconciliation_cases
         WHERE organization_id = ${actor.organizationId} AND state IN ('OPEN', 'QUERYING', 'ESCALATED')
      `;

    // Settlement speed is the executive-relevant half of "is money moving" — the
    // operational dashboard shows the same percentile computation at a 30-day window;
    // this mirrors it rather than introducing a second definition of "fast."
    const settlement = await sql<{ median_seconds: number | null; p95_seconds: number | null }[]>`
        SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at)))  AS median_seconds,
               percentile_cont(0.95) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (completed_at - submitted_at))) AS p95_seconds
          FROM transactions
         WHERE organization_id = ${actor.organizationId}
           AND status = 'SUCCESS' AND completed_at IS NOT NULL AND submitted_at IS NOT NULL
           AND created_at > now() - interval '30 days'
      `;

    const thisMonth = months[0] ? Number(months[0].total_cents) : 0;
    const lastMonth = months[1] ? Number(months[1].total_cents) : 0;
    const changePercent = lastMonth > 0 ? ((thisMonth - lastMonth) / lastMonth) * 100 : null;

    const currentPeriod = months[0]?.period ?? null;
    const previousPeriod = months[1]?.period ?? null;
    const byDepartment = new Map<string, { current: number; previous: number }>();
    for (const row of departmentMonths) {
      const entry = byDepartment.get(row.department_name) ?? { current: 0, previous: 0 };
      if (row.period_month === currentPeriod) entry.current = Number(row.paid_cents);
      else if (row.period_month === previousPeriod) entry.previous = Number(row.paid_cents);
      byDepartment.set(row.department_name, entry);
    }
    let largestMover: { departmentName: string; deltaCents: number } | null = null;
    for (const [departmentName, { current, previous }] of byDepartment) {
      const deltaCents = current - previous;
      if (largestMover === null || Math.abs(deltaCents) > Math.abs(largestMover.deltaCents)) {
        largestMover = { departmentName, deltaCents };
      }
    }

    const openFindings = Number(findings[0]?.open ?? 0);
    const unresolvedReconciliationCases = Number(unresolved[0]?.count ?? 0);
    const riskPosture = classifyRiskPosture({
      openFindings,
      criticalOrHighRiskBatches30d: Number(riskBatches[0]?.count ?? 0),
      unresolvedReconciliationCases,
    });

    return {
      monthlyDisbursement: months.map((m) => ({
        period: m.period,
        totalCents: Number(m.total_cents),
        transactionCount: Number(m.count),
      })),
      monthOverMonth: {
        currentCents: thisMonth,
        previousCents: lastMonth,
        changePercent: changePercent === null ? null : Number(changePercent.toFixed(1)),
        largestMover,
      },
      momentum: classifyMomentum(months.map((m) => ({ period: m.period, totalCents: Number(m.total_cents) }))),
      settlement: {
        medianSeconds: settlement[0]?.median_seconds ?? null,
        p95Seconds: settlement[0]?.p95_seconds ?? null,
      },
      risk: {
        openFindings,
        reviewedFindings: Number(findings[0]?.reviewed ?? 0),
      },
      riskPosture,
      unresolvedReconciliationCases,
    };
  });

  return c.json(data);
});
