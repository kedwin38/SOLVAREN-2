/**
 * CSV export rendering (spec §12: exports from authoritative records, provider
 * references preserved, every export audited).
 *
 * Rules encoded here:
 *  - Cell values are CSV-escaped and formula-neutralised (`=`, `+`, `-`, `@` prefixes get
 *    a leading apostrophe) so a payroll export opened in Excel cannot execute anything.
 *  - The header block records who exported what, under which filter, when — an export is
 *    evidence, and evidence carries its own provenance.
 */

import { formatCents } from './money.js';

function escapeCell(value: string | number | null | undefined): string {
  const raw = value === null || value === undefined ? '' : String(value);
  // Formula injection neutralisation: a leading =, +, -, @ or tab becomes text.
  const neutralised = /^[=+\-@\t\r]/.test(raw) ? `'${raw}` : raw;
  if (/[",\n\r]/.test(neutralised)) {
    return `"${neutralised.replace(/"/g, '""')}"`;
  }
  return neutralised;
}

export function renderCsv(header: readonly string[], rows: readonly (readonly (string | number | null | undefined)[])[]): string {
  const lines = [header.map(escapeCell).join(',')];
  for (const row of rows) lines.push(row.map(escapeCell).join(','));
  return `${lines.join('\r\n')}\r\n`;
}

export interface ExportProvenance {
  exportId: string;
  organizationId: string;
  generatedAt: string;
  generatedByUserId: string;
  generatedByLevel: string;
  filterDescription: string;
  rowCount: number;
}

/** A provenance header block prefixed to every export SOLVAREN produces. */
export function provenanceComment(p: ExportProvenance): string {
  return [
    `# SOLVAREN export ${p.exportId}`,
    `# Generated ${p.generatedAt} by ${p.generatedByLevel} user ${p.generatedByUserId}`,
    `# Filter: ${p.filterDescription}`,
    `# Rows: ${p.rowCount} — from the authoritative transaction ledger; provider references preserved.`,
  ].join('\r\n');
}

export interface TransactionExportRow {
  batchReference: string;
  batchId: string;
  instructionId: string;
  recipientName: string;
  msisdn: string;
  departmentName: string | null;
  amountCents: number;
  status: string;
  failureCode: string | null;
  failureReason: string | null;
  operatorAction: string | null;
  providerResultDescription: string | null;
  mpesaReceiptNumber: string | null;
  conversationId: string | null;
  originatorConversationId: string | null;
  submittedAt: string | null;
  completedAt: string | null;
  lastUpdatedAt: string;
  lastStatusCheckAt: string | null;
  statusSource: string | null;
}

export function renderFailedTransactionsCsv(
  rows: readonly TransactionExportRow[],
  provenance: ExportProvenance,
): string {
  const header = [
    'Batch Reference',
    'Recipient Name',
    'Phone',
    'Department',
    'Amount (KES)',
    'Status',
    'Failure Code',
    'Failure Reason',
    'Operator Action',
    'Provider Description',
    'M-PESA Receipt',
    'Conversation ID',
    'Originator Conversation ID',
    'Submitted At (UTC)',
    'Last Updated (UTC)',
    'Last Status Check (UTC)',
    'Status Source',
    'Batch ID',
    'Instruction ID',
  ];
  const body = rows.map((r) => [
    r.batchReference,
    r.recipientName,
    r.msisdn,
    r.departmentName,
    formatCents(r.amountCents),
    r.status,
    r.failureCode ?? '',
    r.failureReason ?? '',
    r.operatorAction ?? '',
    r.providerResultDescription ?? '',
    r.mpesaReceiptNumber ?? '',
    r.conversationId ?? '',
    r.originatorConversationId ?? '',
    r.submittedAt ?? '',
    r.lastUpdatedAt,
    r.lastStatusCheckAt ?? '',
    r.statusSource ?? '',
    r.batchId,
    r.instructionId,
  ]);
  return `${provenanceComment(provenance)}\r\n${renderCsv(header, body)}`;
}

export function exportFilename(kind: string, organizationSlug: string, generatedAt: string): string {
  const stamp = generatedAt.replace(/[:.]/g, '-').slice(0, 19);
  return `${organizationSlug}-${kind}-${stamp}.csv`;
}
