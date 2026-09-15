/**
 * Report catalogue (spec §12.1: twelve report families).
 *
 * This module defines *what a report is*; the API layer supplies *rows from the
 * authoritative ledger*. Keeping the catalogue here means roles, filters and column
 * contracts are testable without a database, and the UI can render its report picker
 * from the same source of truth.
 */

import { z } from 'zod';

export const REPORT_FAMILIES = [
  'executive',
  'financial',
  'payroll',
  'payment',
  'audit',
  'reconciliation',
  'risk',
  'ai_intelligence',
  'department',
  'user_activity',
  'system_activity',
  'daraja_integration',
] as const;
export type ReportFamily = (typeof REPORT_FAMILIES)[number];

export interface ReportDefinition {
  family: ReportFamily;
  title: string;
  description: string;
  /** Minimum permission required to generate. */
  requiredPermission:
    | 'reports:operational'
    | 'reports:management'
    | 'reports:executive';
  /** The CSV column headers — the contract between core and the API row builders. */
  columns: readonly string[];
  /** Whether the report honours the date-range filter. */
  supportsDateRange: boolean;
  /** Whether the report honours the department filter. */
  supportsDepartmentFilter: boolean;
}

export const REPORT_CATALOG: readonly ReportDefinition[] = [
  {
    family: 'payment',
    title: 'Payment Report',
    description: 'Every transaction with provider references, statuses and failure reasons.',
    requiredPermission: 'reports:operational',
    columns: [
      'Batch Reference', 'Recipient Name', 'Phone', 'Department', 'Amount (KES)', 'Status',
      'Failure Code', 'Failure Reason', 'M-PESA Receipt', 'Originator Conversation ID',
      'Submitted At (UTC)', 'Completed At (UTC)',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: true,
  },
  {
    family: 'payroll',
    title: 'Payroll Report',
    description: 'Successful disbursements grouped by payment period and recipient.',
    requiredPermission: 'reports:operational',
    columns: [
      'Payment Period', 'Recipient Name', 'Department', 'Amount (KES)', 'Batch Reference',
      'M-PESA Receipt', 'Completed At (UTC)',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: true,
  },
  {
    family: 'department',
    title: 'Department Report',
    description: 'Expenditure, transaction counts and failure rates per department per month.',
    requiredPermission: 'reports:operational',
    columns: [
      'Month', 'Department', 'Paid (KES)', 'Paid Count', 'Failed Count', 'Timeout Count',
      'Recipient Count', 'Failure Rate %',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: true,
  },
  {
    family: 'financial',
    title: 'Financial Report',
    description: 'Monthly disbursement totals, month-over-month movement and largest departments.',
    requiredPermission: 'reports:management',
    columns: [
      'Month', 'Total Disbursed (KES)', 'Transaction Count', 'Recipient Count',
      'Change vs Previous Month (KES)', 'Change %',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'executive',
    title: 'Executive Report',
    description: 'Organisation-wide summary: volumes, values, risk position, unresolved cases.',
    requiredPermission: 'reports:executive',
    columns: [
      'Metric', 'This Month', 'Last Month', 'Change %', 'Notes',
    ],
    supportsDateRange: false,
    supportsDepartmentFilter: false,
  },
  {
    family: 'reconciliation',
    title: 'Reconciliation Report',
    description: 'Every reconciliation case with its opening reason, attempts and resolution.',
    requiredPermission: 'reports:operational',
    columns: [
      'Case Reference', 'Opened At (UTC)', 'State', 'Opened Reason', 'Query Attempts',
      'Discrepancy', 'Resolved At (UTC)', 'Resolution Note', 'Transaction ID',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'risk',
    title: 'Risk Report',
    description: 'Risk findings by signal type and severity, with dispositions.',
    requiredPermission: 'reports:management',
    columns: [
      'Batch Reference', 'Signal Type', 'Severity', 'Summary', 'Disposition',
      'Dispositioned By', 'Raised At (UTC)',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'audit',
    title: 'Audit Report',
    description: 'Audit events with actor, action, object and outcome, in chain order.',
    requiredPermission: 'reports:management',
    columns: [
      'Sequence', 'Occurred At (UTC)', 'Class', 'Action', 'Actor', 'Outcome',
      'Object Type', 'Object ID', 'Correlation ID',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'user_activity',
    title: 'User Activity Report',
    description: 'Sign-ins, privileged actions and exports per user.',
    requiredPermission: 'reports:management',
    columns: [
      'User', 'Authority Level', 'Sign-Ins', 'Privileged Actions', 'Exports',
      'Releases Authorized', 'Last Seen (UTC)',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'system_activity',
    title: 'System Activity Report',
    description: 'Security events, queue throughput and worker outcomes.',
    requiredPermission: 'reports:management',
    columns: [
      'Occurred At (UTC)', 'Kind', 'Severity', 'Description', 'Detail',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'daraja_integration',
    title: 'Daraja Integration Report',
    description: 'Credential versions, connection tests, submission outcomes and callback health.',
    requiredPermission: 'reports:management',
    columns: [
      'Occurred At (UTC)', 'Event', 'Environment', 'Outcome', 'Detail',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
  {
    family: 'ai_intelligence',
    title: 'AI Intelligence Report',
    description: 'AI interactions: capability, prompt summary, model, degraded status.',
    requiredPermission: 'reports:management',
    columns: [
      'At (UTC)', 'User', 'Capability', 'Prompt Summary', 'Model', 'Degraded', 'Response Summary',
    ],
    supportsDateRange: true,
    supportsDepartmentFilter: false,
  },
];

export function reportDefinition(family: ReportFamily): ReportDefinition {
  const def = REPORT_CATALOG.find((r) => r.family === family);
  if (!def) {
    throw new Error(`Unknown report family: ${family}`);
  }
  return def;
}

export const reportRequestSchema = z.object({
  family: z.enum(REPORT_FAMILIES),
  dateFrom: z.string().regex(/^\d{4}-\d{2}-\d{2}/).optional(),
  dateTo: z.string().regex(/^\d{4}-\d{2}-\d{2}/).optional(),
  departmentId: z.string().uuid().optional(),
  format: z.enum(['csv']).default('csv'),
});

export type ReportRequest = z.infer<typeof reportRequestSchema>;

export function reportFilename(family: ReportFamily, organizationSlug: string, generatedAt: string): string {
  const stamp = generatedAt.replace(/[:.]/g, '-').slice(0, 19);
  return `${organizationSlug}-${family}-report-${stamp}.csv`;
}
