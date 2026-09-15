/**
 * Transaction Explorer query model (spec §12: filtering by date, department, recipient,
 * batch, status, payment type; server-side sort and pagination).
 *
 * The security-relevant detail: the user picks a sort column, which means user input
 * reaching SQL *text*. It passes through this closed allowlist, so the only strings that
 * can ever appear in an ORDER BY are the ones this platform authored.
 */

import { z } from 'zod';
import { validationError } from './errors.js';
import type { TxnState } from './txn-state.js';

export const SORT_COLUMNS = [
  'created_desc',
  'created_asc',
  'amount_desc',
  'amount_asc',
  'status',
  'completed_desc',
  'recipient',
] as const;
export type SortColumn = (typeof SORT_COLUMNS)[number];

const ORDER_BY: Record<SortColumn, string> = {
  created_desc: 't.created_at DESC, t.id DESC',
  created_asc: 't.created_at ASC, t.id ASC',
  amount_desc: 'pi.amount_cents DESC, t.created_at DESC',
  amount_asc: 'pi.amount_cents ASC, t.created_at DESC',
  status: 't.status ASC, t.created_at DESC',
  completed_desc: 't.completed_at DESC NULLS LAST, t.created_at DESC',
  recipient: 'pi.recipient_name_snapshot ASC, t.created_at DESC',
};

export function buildOrderBy(query: { sort?: SortColumn }): string {
  return ORDER_BY[query.sort ?? 'created_desc'];
}

const TXN_STATE_ENUM = [
  'PENDING',
  'SUBMITTED',
  'AWAITING_CALLBACK',
  'PROCESSING',
  'RECONCILING',
  'SUCCESS',
  'FAILED',
  'TIMEOUT',
  'CANCELLED',
] as const;

export const explorerQuerySchema = z.object({
  status: z.array(z.enum(TXN_STATE_ENUM)).max(9).optional(),
  batchId: z.string().uuid().optional(),
  departmentId: z.string().uuid().optional(),
  recipientId: z.string().uuid().optional(),
  search: z.string().trim().max(120).optional(),
  dateFrom: z.string().datetime().optional(),
  dateTo: z.string().datetime().optional(),
  failureCode: z.string().trim().max(40).optional(),
  amountMinCents: z.number().int().min(0).max(1e12).optional(),
  amountMaxCents: z.number().int().min(0).max(1e12).optional(),
  sort: z.enum(SORT_COLUMNS).optional(),
  direction: z.enum(['asc', 'desc']).optional(),
  page: z.number().int().min(1).max(100_000).default(1),
  pageSize: z.number().int().min(1).max(200).default(50),
});

export type ExplorerQuery = z.infer<typeof explorerQuerySchema>;

/** Range coherence — "min > max" is a client bug, but it must not become a SQL problem. */
export function assertCoherentRange(query: ExplorerQuery): string[] {
  const problems: string[] = [];
  if (
    query.amountMinCents !== undefined &&
    query.amountMaxCents !== undefined &&
    query.amountMinCents > query.amountMaxCents
  ) {
    problems.push('The minimum amount filter is greater than the maximum');
  }
  if (query.dateFrom && query.dateTo && new Date(query.dateFrom) > new Date(query.dateTo)) {
    problems.push('The start of the date range is after its end');
  }
  return problems;
}

export function parseExplorerQuerySafe(input: unknown): ExplorerQuery {
  const parsed = explorerQuerySchema.safeParse(input);
  if (!parsed.success) {
    throw validationError('FILTER_INVALID', parsed.error.issues[0]?.message ?? 'The filter was not valid');
  }
  const problems = assertCoherentRange(parsed.data);
  if (problems.length > 0) {
    throw validationError('FILTER_INCOHERENT', problems[0]!, { problems });
  }
  return parsed.data;
}

export function offsetFor(query: ExplorerQuery): number {
  return (query.page - 1) * query.pageSize;
}

export interface PageInfo {
  page: number;
  pageSize: number;
  totalRows: number;
  totalPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export function pageInfo(query: ExplorerQuery, totalRows: number): PageInfo {
  const totalPages = Math.max(1, Math.ceil(totalRows / query.pageSize));
  return {
    page: query.page,
    pageSize: query.pageSize,
    totalRows,
    totalPages,
    hasNext: query.page < totalPages,
    hasPrevious: query.page > 1,
  };
}

/** A human-readable filter description for the export header and audit record. */
export function describeFilter(query: ExplorerQuery): { text: string; parts: string[] } {
  const parts: string[] = [];
  if (query.status?.length) parts.push(`status: ${query.status.join(', ')}`);
  if (query.batchId) parts.push(`batch: ${query.batchId}`);
  if (query.departmentId) parts.push(`department: ${query.departmentId}`);
  if (query.recipientId) parts.push(`recipient: ${query.recipientId}`);
  if (query.failureCode) parts.push(`failure code: ${query.failureCode}`);
  if (query.dateFrom) parts.push(`from: ${query.dateFrom}`);
  if (query.dateTo) parts.push(`to: ${query.dateTo}`);
  if (query.amountMinCents !== undefined) parts.push(`min amount: ${query.amountMinCents}`);
  if (query.amountMaxCents !== undefined) parts.push(`max amount: ${query.amountMaxCents}`);
  if (query.search) parts.push(`search: "${query.search}"`);
  return { text: parts.length > 0 ? parts.join(' · ') : 'all transactions', parts };
}
