/**
 * Report row builders (spec §12.1: twelve report families).
 *
 * Every builder reads the authoritative ledger (transactions / audit_events /
 * reconciliation_cases …) so report numbers, explorer numbers and dashboard numbers are
 * the same numbers. Columns come from the REPORT_CATALOG in @solvaren/core — the single
 * contract shared with the UI's report picker.
 *
 * Dynamic date-range clauses use `sql.unsafe` with bind parameters ($1, $2, …) — the
 * filter values never touch the SQL text.
 */

import {
  formatCents,
  reportDefinition,
  type ReportFamily,
  type TransactionExportRow,
} from '@solvaren/core';
import type { Sql } from '../db/client.js';

export interface BuiltReport {
  columns: readonly string[];
  rows: readonly (readonly (string | number | null)[])[];
  filterDescription: string;
}

export interface ReportFilters {
  dateFrom?: string;
  dateTo?: string;
  departmentId?: string;
}

interface RowShape {
  period: string | null;
  recipient: string;
  department: string;
  amount_cents: string;
  batch_reference: string;
  mpesa_receipt_number: string | null;
  completed_at: unknown;
}

interface DepartmentShape {
  period: string;
  department_name: string;
  paid_cents: string;
  paid_count: string;
  failed_count: string;
}

interface FinancialShape {
  month: string;
  total: string;
  count: string;
  recipients: string;
}

interface ReconciliationShape {
  case_reference: string;
  opened_at: unknown;
  state: string;
  opened_reason: string;
  query_attempts: number;
  discrepancy: boolean;
  resolved_at: unknown;
  resolution_note: string | null;
  transaction_id: string;
}

interface RiskShape {
  batch_reference: string;
  signal_type: string;
  severity: string;
  summary: string;
  disposition: string;
  dispositioned_by: string;
  created_at: unknown;
}

interface AuditShape {
  sequence: string;
  occurred_at: unknown;
  event_class: string;
  action: string;
  actor_id: string;
  outcome: string;
  object_type: string;
  object_id: string | null;
  correlation_id: string;
}

interface UserActivityShape {
  full_name: string;
  authority_level: string;
  sign_ins: string;
  privileged: string;
  exports: string;
  releases: string;
  last_seen: unknown;
}

interface SystemShape {
  created_at: unknown;
  event_type: string;
  severity: string;
  description: string;
  detail: string;
}

interface DarajaShape {
  occurred_at: unknown;
  action: string;
  outcome: string;
  environment: string;
  detail: string;
}

interface AiShape {
  created_at: unknown;
  user_name: string;
  capability: string;
  prompt_summary: string;
  model: string;
  degraded: boolean;
  response_summary: string | null;
}

const asIso = (value: unknown): string =>
  value instanceof Date ? value.toISOString() : String(value ?? '');

/**
 * Build a report's rows. Returns parallel arrays (columns from the catalog, rows as
 * arrays of cell values) ready for `renderCsv`.
 */
export async function buildReportRows(
  sql: Sql,
  organizationId: string,
  family: ReportFamily,
  filters: ReportFilters,
): Promise<BuiltReport> {
  const definition = reportDefinition(family);
  const filterDescription =
    [
      filters.dateFrom ? `from ${filters.dateFrom}` : null,
      filters.dateTo ? `to ${filters.dateTo}` : null,
      filters.departmentId ? `department ${filters.departmentId}` : null,
    ]
      .filter(Boolean)
      .join(' · ') || 'all data';

  // The organisation is always the first bind parameter; the range follows.
  const rangeParams: (string | null)[] = [];
  let rangeSql = '';
  if (filters.dateFrom) {
    rangeParams.push(`${filters.dateFrom}T00:00:00Z`);
    rangeSql += ` AND $${rangeParams.length + 1}::timestamptz IS NOT NULL`;
  }
  if (filters.dateTo) {
    rangeParams.push(`${filters.dateTo}T23:59:59Z`);
    rangeSql += ` AND $${rangeParams.length + 1}::timestamptz IS NOT NULL`;
  }

  switch (family) {
    case 'payment': {
      const rows = await queryPaymentRows(sql, organizationId, filters);
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.batchReference, r.recipientName, r.msisdn, r.departmentName,
          formatCents(r.amountCents), r.status, r.failureCode, r.failureReason,
          r.mpesaReceiptNumber, r.originatorConversationId, r.submittedAt ?? '', r.completedAt ?? '',
        ]),
        filterDescription,
      };
    }    case 'payroll': {
      const rows = await sql.unsafe<RowShape[]>(
        `SELECT b.payment_period AS period, pi.recipient_name_snapshot AS recipient,
                COALESCE(d.name, 'Unassigned') AS department, pi.amount_cents,
                b.batch_reference, t.mpesa_receipt_number, t.completed_at
           FROM transactions t
           JOIN payment_instructions pi ON pi.id = t.instruction_id
           JOIN payment_batches b ON b.id = t.batch_id
           LEFT JOIN departments d ON d.id = pi.department_id
          WHERE t.organization_id = $1 AND t.status = 'SUCCESS'
            AND ($2::timestamptz IS NULL OR t.completed_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR t.completed_at <= $3::timestamptz)
          ORDER BY t.completed_at DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.period ?? '—', r.recipient, r.department, formatCents(Number(r.amount_cents)),
          r.batch_reference, r.mpesa_receipt_number ?? '', asIso(r.completed_at),
        ]),
        filterDescription,
      };
    }
    case 'department': {
      const rows = await sql<DepartmentShape[]>`
        SELECT period_month::text AS period, department_name,
               paid_cents, paid_count, failed_count
          FROM department_expenditure
         WHERE organization_id = ${organizationId}
           AND (${filters.dateFrom ?? null}::date IS NULL OR period_month >= ${filters.dateFrom ?? null}::date)
           AND (${filters.dateTo ?? null}::date IS NULL OR period_month <= ${filters.dateTo ?? null}::date)
         ORDER BY period_month DESC, paid_cents DESC
      `;
      return {
        columns: definition.columns,
        rows: rows.map((r) => {
          const paid = Number(r.paid_count);
          const failed = Number(r.failed_count);
          return [
            r.period, r.department_name, formatCents(Number(r.paid_cents)), paid, failed,
            paid + failed,
            paid + failed > 0 ? Math.round((failed / (paid + failed)) * 100) : 0,
          ];
        }),
        filterDescription,
      };
    }
    case 'financial': {
      const rows = await sql.unsafe<FinancialShape[]>(
        `SELECT date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE::text AS month,
                SUM(pi.amount_cents) AS total, COUNT(*) AS count,
                COUNT(DISTINCT pi.recipient_id) AS recipients
           FROM transactions t
           JOIN payment_instructions pi ON pi.id = t.instruction_id
          WHERE t.organization_id = $1 AND t.status = 'SUCCESS'
            AND ($2::timestamptz IS NULL OR t.completed_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR t.completed_at <= $3::timestamptz)
          GROUP BY 1 ORDER BY 1 DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      const withChange = rows.map((row, i) => {
        const prev = rows[i + 1];
        const change = prev ? Number(row.total) - Number(prev.total) : null;
        const changePct = prev && Number(prev.total) > 0 ? ((change ?? 0) / Number(prev.total)) * 100 : null;
        return { row, change, changePct };
      });
      return {
        columns: definition.columns,
        rows: withChange.map(({ row, change, changePct }) => [
          row.month, formatCents(Number(row.total)), Number(row.count), Number(row.recipients),
          change !== null ? formatCents(change) : '—',
          changePct !== null ? `${changePct.toFixed(1)}%` : '—',
        ]),
        filterDescription,
      };
    }
    case 'executive': {
      const [thisMonth, lastMonth, risk, unresolved] = await Promise.all([
        monthTotal(sql, organizationId, 0),
        monthTotal(sql, organizationId, 1),
        sql<{ open: string; reviewed: string }[]>`
          SELECT COUNT(*) FILTER (WHERE disposition = 'OPEN') AS open,
                 COUNT(*) FILTER (WHERE disposition <> 'OPEN') AS reviewed
            FROM risk_findings WHERE organization_id = ${organizationId}
        `,
        sql<{ count: string }[]>`
          SELECT COUNT(*) AS count FROM reconciliation_cases
           WHERE organization_id = ${organizationId} AND state IN ('OPEN', 'QUERYING', 'ESCALATED')
        `,
      ]);
      const pct = (a: number, b: number): string => (b > 0 ? `${(((a - b) / b) * 100).toFixed(1)}%` : '—');
      return {
        columns: definition.columns,
        rows: [
          ['Disbursed (KES)', formatCents(thisMonth.total), formatCents(lastMonth.total), pct(thisMonth.total, lastMonth.total), 'Successful transactions only'],
          ['Transaction count', thisMonth.count, lastMonth.count, pct(thisMonth.count, lastMonth.count), ''],
          ['Open risk findings', Number(risk[0]?.open ?? 0), '', '', 'Awaiting disposition'],
          ['Reviewed risk findings', Number(risk[0]?.reviewed ?? 0), '', '', ''],
          ['Unresolved reconciliation cases', Number(unresolved[0]?.count ?? 0), '', '', 'Open, querying or escalated'],
        ],
        filterDescription: 'current + previous month',
      };
    }
    case 'reconciliation': {
      const rows = await sql.unsafe<ReconciliationShape[]>(
        `SELECT rc.case_reference, rc.opened_at, rc.state, rc.opened_reason, rc.query_attempts,
                rc.discrepancy, rc.resolved_at, rc.resolution_note, rc.transaction_id
           FROM reconciliation_cases rc
          WHERE rc.organization_id = $1
            AND ($2::timestamptz IS NULL OR rc.opened_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR rc.opened_at <= $3::timestamptz)
          ORDER BY rc.opened_at DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.case_reference, asIso(r.opened_at), r.state, r.opened_reason, r.query_attempts,
          r.discrepancy ? 'yes' : 'no', r.resolved_at ? asIso(r.resolved_at) : '', r.resolution_note ?? '', r.transaction_id,
        ]),
        filterDescription,
      };
    }
    case 'risk': {
      const rows = await sql.unsafe<RiskShape[]>(
        `SELECT rf.signal_type, rf.severity, rf.summary, rf.disposition,
                COALESCE(u.full_name, rf.dispositioned_by_user_id::text, '') AS dispositioned_by,
                rf.created_at, b.batch_reference
           FROM risk_findings rf
           JOIN payment_batches b ON b.id = rf.batch_id
           LEFT JOIN users u ON u.id = rf.dispositioned_by_user_id
          WHERE rf.organization_id = $1
            AND ($2::timestamptz IS NULL OR rf.created_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR rf.created_at <= $3::timestamptz)
          ORDER BY rf.created_at DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.batch_reference, r.signal_type, r.severity, r.summary, r.disposition,
          r.dispositioned_by, asIso(r.created_at),
        ]),
        filterDescription,
      };
    }
    case 'audit': {
      const rows = await sql.unsafe<AuditShape[]>(
        `SELECT sequence, occurred_at, event_class, action, actor_id, outcome,
                object_type, object_id, correlation_id
           FROM audit_events
          WHERE organization_id = $1
            AND ($2::timestamptz IS NULL OR occurred_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR occurred_at <= $3::timestamptz)
          ORDER BY sequence DESC
          LIMIT 50000`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.sequence, asIso(r.occurred_at), r.event_class, r.action, r.actor_id, r.outcome,
          r.object_type, r.object_id ?? '', r.correlation_id,
        ]),
        filterDescription,
      };
    }
    case 'user_activity': {
      const rows = await sql.unsafe<UserActivityShape[]>(
        `SELECT u.full_name, u.authority_level,
                COUNT(*) FILTER (WHERE a.action LIKE 'auth.login%') AS sign_ins,
                COUNT(*) FILTER (WHERE a.event_class IN ('PAYMENT','ADMINISTRATION','BACKUP','AUTHORITY')) AS privileged,
                COUNT(*) FILTER (WHERE a.event_class = 'DATA_EXPORT') AS exports,
                COUNT(*) FILTER (WHERE a.action = 'payment.release.authorized') AS releases,
                MAX(a.occurred_at) AS last_seen
           FROM users u
           LEFT JOIN audit_events a ON a.actor_id = u.id::text
            AND a.occurred_at >= COALESCE($2::timestamptz, now() - interval '90 days')
          WHERE u.organization_id = $1
          GROUP BY u.id, u.full_name, u.authority_level
          ORDER BY u.authority_level, u.full_name`,
        [organizationId, filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          r.full_name, r.authority_level, Number(r.sign_ins), Number(r.privileged),
          Number(r.exports), Number(r.releases), r.last_seen ? asIso(r.last_seen) : 'never',
        ]),
        filterDescription,
      };
    }
    case 'system_activity': {
      const rows = await sql.unsafe<SystemShape[]>(
        `SELECT created_at, event_type, severity, description, detail::text
           FROM security_events
          WHERE (organization_id = $1 OR organization_id IS NULL)
            AND ($2::timestamptz IS NULL OR created_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR created_at <= $3::timestamptz)
          ORDER BY created_at DESC
          LIMIT 20000`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [asIso(r.created_at), r.event_type, r.severity, r.description, r.detail]),
        filterDescription,
      };
    }
    case 'daraja_integration': {
      const rows = await sql.unsafe<DarajaShape[]>(
        `SELECT occurred_at, action, outcome,
                COALESCE((SELECT environment FROM daraja_configurations dc WHERE dc.organization_id = a.organization_id LIMIT 1), 'unknown') AS environment,
                detail::text
           FROM audit_events a
          WHERE a.organization_id = $1 AND a.event_class = 'INTEGRATION'
            AND ($2::timestamptz IS NULL OR occurred_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR occurred_at <= $3::timestamptz)
          ORDER BY occurred_at DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [asIso(r.occurred_at), r.action, r.environment, r.outcome, r.detail]),
        filterDescription,
      };
    }
    case 'ai_intelligence': {
      const rows = await sql.unsafe<AiShape[]>(
        `SELECT ai.created_at, COALESCE(u.full_name, ai.user_id::text) AS user_name,
                ai.capability, ai.prompt_summary, ai.model, ai.degraded, ai.response_summary
           FROM ai_interactions ai
           LEFT JOIN users u ON u.id = ai.user_id
          WHERE ai.organization_id = $1
            AND ($2::timestamptz IS NULL OR ai.created_at >= $2::timestamptz)
            AND ($3::timestamptz IS NULL OR ai.created_at <= $3::timestamptz)
          ORDER BY ai.created_at DESC`,
        [
          organizationId,
          filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
          filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
        ],
      );
      return {
        columns: definition.columns,
        rows: rows.map((r) => [
          asIso(r.created_at), r.user_name, r.capability, r.prompt_summary, r.model,
          r.degraded ? 'yes' : 'no', r.response_summary ?? '',
        ]),
        filterDescription,
      };
    }
  }
}

async function monthTotal(
  sql: Sql,
  organizationId: string,
  monthsAgo: number,
): Promise<{ total: number; count: number }> {
  const rows = await sql<{ total: string | null; count: string }[]>`
    SELECT SUM(pi.amount_cents) AS total, COUNT(*) AS count
      FROM transactions t
      JOIN payment_instructions pi ON pi.id = t.instruction_id
     WHERE t.organization_id = ${organizationId} AND t.status = 'SUCCESS'
       AND t.completed_at >= date_trunc('month', now() - (${monthsAgo} * interval '1 month'))
       AND t.completed_at < date_trunc('month', now() - (${monthsAgo - 1} * interval '1 month'))
  `;
  return { total: Number(rows[0]?.total ?? 0), count: Number(rows[0]?.count ?? 0) };
}

interface PaymentExplorerShape {
  batch_reference: string;
  recipient_name: string;
  msisdn: string;
  department_name: string;
  amount_cents: string;
  status: string;
  failure_code: string | null;
  failure_reason: string | null;
  mpesa_receipt_number: string | null;
  originator_conversation_id: string;
  submitted_at: unknown;
  completed_at: unknown;
}

async function queryPaymentRows(
  sql: Sql,
  organizationId: string,
  filters: ReportFilters,
): Promise<TransactionExportRow[]> {
  const rows = await sql.unsafe<PaymentExplorerShape[]>(
    `SELECT b.batch_reference, pi.recipient_name_snapshot AS recipient_name,
            pi.msisdn_snapshot AS msisdn, COALESCE(d.name, 'Unassigned') AS department_name,
            pi.amount_cents, t.status, t.failure_code, t.failure_reason,
            t.mpesa_receipt_number, t.originator_conversation_id, t.submitted_at, t.completed_at
       FROM transactions t
       JOIN payment_instructions pi ON pi.id = t.instruction_id
       JOIN payment_batches b ON b.id = t.batch_id
       LEFT JOIN departments d ON d.id = pi.department_id
      WHERE t.organization_id = $1
        AND ($2::timestamptz IS NULL OR t.created_at >= $2::timestamptz)
        AND ($3::timestamptz IS NULL OR t.created_at <= $3::timestamptz)
      ORDER BY t.created_at DESC`,
    [
      organizationId,
      filters.dateFrom ? `${filters.dateFrom}T00:00:00Z` : null,
      filters.dateTo ? `${filters.dateTo}T23:59:59Z` : null,
    ],
  );
  return rows.map((r) => ({
    batchReference: r.batch_reference,
    batchId: '',
    instructionId: '',
    recipientName: r.recipient_name,
    msisdn: r.msisdn,
    departmentName: r.department_name,
    amountCents: Number(r.amount_cents),
    status: r.status,
    failureCode: r.failure_code,
    failureReason: r.failure_reason,
    operatorAction: null,
    providerResultDescription: null,
    mpesaReceiptNumber: r.mpesa_receipt_number,
    conversationId: null,
    originatorConversationId: r.originator_conversation_id,
    submittedAt: r.submitted_at ? asIso(r.submitted_at) : null,
    completedAt: r.completed_at ? asIso(r.completed_at) : null,
    lastUpdatedAt: '',
    lastStatusCheckAt: null,
    statusSource: null,
  }));
}
