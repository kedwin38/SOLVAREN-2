/**
 * Transactions Explorer, payment detail, on-demand refresh, the retry workflow, and CSV
 * exports (spec §9.3, §12; the record-keeping core of the product).
 *
 * The promise this file keeps: every transaction's live status, filterable and
 * server-side sortable; a failure code and a human-readable reason on every failure,
 * never blank; a one-click CSV of exactly what is on screen, built from ledger rows; and
 * every export audited with actor, filter and row count.
 *
 * The retry workflow creates a NEW instruction in a correction batch — never a resend of
 * the same one — gated by `isRetryEligible` and organization policy.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  explorerQuerySchema,
  buildOrderBy,
  describeFilter,
  pageInfo,
  offsetFor,
  parseExplorerQuerySafe,
  renderFailedTransactionsCsv,
  exportFilename,
  canExportFailedTransactions,
  resolveFailure,
  statusTone,
  isRetryEligible,
  reference,
  validationError,
  authorizationError,
  notFoundError,
  type TransactionExportRow,
  type TxnState,
} from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf, rateLimit } from '../middleware/security.js';
import { withConnection, inTransaction, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadPolicy } from '../services/policy-store.js';
import { loadFailureOverrides } from '../services/failure-map.js';
import { toActor } from '../services/auth.js';
import type { AppContext, ReconciliationQueueMessage } from '../env.js';

export const transactionRoutes = new Hono<AppContext>();
export const exportRoutes = new Hono<AppContext>();

transactionRoutes.use('*', requireAuth);
exportRoutes.use('*', requireAuth);

/** Parse the explorer query from the URL. */
function parseExplorerQuery(url: URL) {
  const params = url.searchParams;
  const statuses = params.getAll('status').filter(Boolean);

  return parseExplorerQuerySafe({
    ...(statuses.length > 0 ? { status: statuses } : {}),
    ...(params.get('batchId') ? { batchId: params.get('batchId') } : {}),
    ...(params.get('departmentId') ? { departmentId: params.get('departmentId') } : {}),
    ...(params.get('recipientId') ? { recipientId: params.get('recipientId') } : {}),
    ...(params.get('search') ? { search: params.get('search') } : {}),
    ...(params.get('dateFrom') ? { dateFrom: params.get('dateFrom') } : {}),
    ...(params.get('dateTo') ? { dateTo: params.get('dateTo') } : {}),
    ...(params.get('failureCode') ? { failureCode: params.get('failureCode') } : {}),
    ...(params.get('amountMinCents') ? { amountMinCents: Number(params.get('amountMinCents')) } : {}),
    ...(params.get('amountMaxCents') ? { amountMaxCents: Number(params.get('amountMaxCents')) } : {}),
    ...(params.get('sort') ? { sort: params.get('sort') } : {}),
    ...(params.get('page') ? { page: Number(params.get('page')) } : {}),
    ...(params.get('pageSize') ? { pageSize: Number(params.get('pageSize')) } : {}),
  });
}

interface ExplorerDbRow {
  transaction_id: string;
  instruction_id: string;
  batch_id: string;
  batch_reference: string;
  recipient_id: string;
  recipient_name: string;
  msisdn: string;
  department_id: string | null;
  department_name: string | null;
  amount_cents: string;
  status: TxnState;
  failure_code: string | null;
  failure_reason: string | null;
  failure_class: string | null;
  provider_result_description: string | null;
  mpesa_receipt_number: string | null;
  conversation_id: string | null;
  originator_conversation_id: string | null;
  status_source: string | null;
  last_status_check_at: string | null;
  created_at: string;
  submitted_at: string | null;
  completed_at: string | null;
  updated_at: string;
  total_count: string;
}

/**
 * Build the filtered query. Every value is a bind parameter; the only interpolated
 * *text* is the ORDER BY clause, which `buildOrderBy` produces from the allowlist.
 */
async function queryExplorer(
  sql: Sql,
  organizationId: string,
  query: ReturnType<typeof parseExplorerQuery>,
  limitOverride?: number,
): Promise<{ rows: ExplorerDbRow[]; total: number }> {
  const limit = limitOverride ?? query.pageSize;
  const offset = limitOverride ? 0 : offsetFor(query);
  const orderBy = buildOrderBy(query);

  const rows: ExplorerDbRow[] = await sql.unsafe(
    `
    SELECT t.id                            AS transaction_id,
           pi.id                           AS instruction_id,
           b.id                            AS batch_id,
           b.batch_reference,
           r.id                            AS recipient_id,
           pi.recipient_name_snapshot      AS recipient_name,
           pi.msisdn_snapshot              AS msisdn,
           d.id                            AS department_id,
           d.name                          AS department_name,
           pi.amount_cents,
           t.status,
           t.failure_code,
           t.failure_reason,
           t.failure_class,
           t.provider_result_description,
           t.mpesa_receipt_number,
           t.conversation_id,
           t.originator_conversation_id,
           t.status_source,
           t.last_status_check_at,
           t.created_at,
           t.submitted_at,
           t.completed_at,
           t.updated_at,
           COUNT(*) OVER () AS total_count
      FROM transactions t
      JOIN payment_instructions pi ON pi.id = t.instruction_id
      JOIN payment_batches b       ON b.id = t.batch_id
      JOIN recipients r            ON r.id = pi.recipient_id
      LEFT JOIN departments d      ON d.id = pi.department_id
     WHERE t.organization_id = $1
       AND ($2::text IS NULL OR t.status = ANY(string_to_array($2::text, ',')))
       AND ($3::uuid   IS NULL OR t.batch_id = $3::uuid)
       AND ($4::uuid   IS NULL OR pi.department_id = $4::uuid)
       AND ($5::uuid   IS NULL OR pi.recipient_id = $5::uuid)
       AND ($6::timestamptz IS NULL OR t.created_at >= $6::timestamptz)
       AND ($7::timestamptz IS NULL OR t.created_at <= $7::timestamptz)
       AND ($8::bigint IS NULL OR pi.amount_cents >= $8::bigint)
       AND ($9::bigint IS NULL OR pi.amount_cents <= $9::bigint)
       AND ($10::text  IS NULL OR t.failure_code = $10::text)
       AND ($11::text  IS NULL OR (
             pi.recipient_name_snapshot ILIKE '%' || $11 || '%'
          OR t.mpesa_receipt_number      ILIKE '%' || $11 || '%'
          OR t.conversation_id           ILIKE '%' || $11 || '%'
          OR t.originator_conversation_id ILIKE '%' || $11 || '%'
          OR b.batch_reference           ILIKE '%' || $11 || '%'))
     ORDER BY ${orderBy}
     LIMIT $12 OFFSET $13
    `,
    [
      organizationId,
      query.status && query.status.length > 0 ? query.status.join(',') : null,
      query.batchId ?? null,
      query.departmentId ?? null,
      query.recipientId ?? null,
      query.dateFrom ?? null,
      query.dateTo ?? null,
      query.amountMinCents ?? null,
      query.amountMaxCents ?? null,
      query.failureCode ?? null,
      query.search ?? null,
      limit,
      offset,
    ],
  );

  return { rows, total: rows.length > 0 ? Number(rows[0]!.total_count) : 0 };
}

/**
 * GET /api/transactions — the explorer.
 *
 * Available to every authority level: spec §4.4 grants transaction visibility to L1, L2
 * and L3 alike. Visibility is not the privileged part; acting on it is.
 */
transactionRoutes.get('/transactions', requirePermissions('transactions:read'), async (c) => {
  const actor = actorOf(c);
  const query = parseExplorerQuery(new URL(c.req.url));

  const result = await withConnection(c.env, async (sql) => {
    const overrides = await loadFailureOverrides(sql, actor.organizationId);
    const { rows, total } = await queryExplorer(sql, actor.organizationId, query);

    return {
      transactions: rows.map((row) => {
        // Resolve the reason again on read, so a dictionary improvement retrospectively
        // explains older failures without rewriting the immutable ledger row.
        const resolved =
          row.status === 'FAILED' || row.status === 'TIMEOUT'
            ? resolveFailure(row.failure_code, row.provider_result_description, overrides)
            : null;

        return {
          transactionId: row.transaction_id,
          instructionId: row.instruction_id,
          batchId: row.batch_id,
          batchReference: row.batch_reference,
          recipientId: row.recipient_id,
          recipientName: row.recipient_name,
          msisdn: row.msisdn,
          departmentId: row.department_id,
          departmentName: row.department_name,
          amountCents: Number(row.amount_cents),
          status: row.status,
          statusTone: statusTone(row.status),
          failureCode: row.failure_code,
          failureReason: row.failure_reason ?? resolved?.failureReason ?? null,
          failureClass: row.failure_class ?? resolved?.failureClass ?? null,
          operatorAction: resolved?.operatorAction ?? null,
          providerResultDescription: row.provider_result_description,
          mpesaReceiptNumber: row.mpesa_receipt_number,
          conversationId: row.conversation_id,
          originatorConversationId: row.originator_conversation_id,
          statusSource: row.status_source,
          lastStatusCheckAt: row.last_status_check_at,
          createdAt: row.created_at,
          submittedAt: row.submitted_at,
          completedAt: row.completed_at,
          updatedAt: row.updated_at,
          retryEligible: isRetryEligible(row.status, row.failure_code),
        };
      }),
      page: pageInfo(query, total),
      filter: describeFilter(query),
    };
  });

  return c.json(result);
});

/** GET /api/transactions/:id — the payment detail page (spec §22). */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

transactionRoutes.get('/transactions/:id', requirePermissions('transactions:read'), async (c) => {
  const actor = actorOf(c);
  const transactionId = c.req.param('id');
  // Validated before it reaches a query: a malformed id is a 404, not a 500.
  if (!UUID_PATTERN.test(transactionId)) {
    throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
  }

  const result = await withConnection(c.env, async (sql) => {
    const rows = await sql<ExplorerDbRow[]>`
      SELECT t.id AS transaction_id, pi.id AS instruction_id, b.id AS batch_id,
             b.batch_reference, r.id AS recipient_id,
             pi.recipient_name_snapshot AS recipient_name, pi.msisdn_snapshot AS msisdn,
             d.id AS department_id, d.name AS department_name, pi.amount_cents, t.status,
             t.failure_code, t.failure_reason, t.failure_class, t.provider_result_description,
             t.mpesa_receipt_number, t.conversation_id, t.originator_conversation_id,
             t.status_source, t.last_status_check_at, t.created_at, t.submitted_at,
             t.completed_at, t.updated_at, '1' AS total_count
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
        JOIN payment_batches b       ON b.id = t.batch_id
        JOIN recipients r            ON r.id = pi.recipient_id
        LEFT JOIN departments d      ON d.id = pi.department_id
       WHERE t.id = ${transactionId} AND t.organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const row = rows[0];
    if (!row) throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');

    const overrides = await loadFailureOverrides(sql, actor.organizationId);
    const resolved = resolveFailure(row.failure_code, row.provider_result_description, overrides);

    // The immutable activity trail for this transaction (spec §22, Payment Detail).
    const activity = await sql<
      { action: string; outcome: string; occurred_at: string; actor_id: string; detail: unknown }[]
    >`
      SELECT action, outcome, occurred_at, actor_id, detail
        FROM audit_events
       WHERE organization_id = ${actor.organizationId}
         AND object_type = 'Transaction' AND object_id = ${transactionId}
       ORDER BY sequence ASC
    `;

    const reconciliation = await sql<
      {
        case_reference: string;
        state: string;
        opened_reason: string;
        discrepancy: boolean;
        query_attempts: number;
        evidence: unknown;
      }[]
    >`
      SELECT case_reference, state, opened_reason, discrepancy, query_attempts, evidence
        FROM reconciliation_cases
       WHERE transaction_id = ${transactionId}
       ORDER BY opened_at DESC
    `;

    return {
      transaction: {
        transactionId: row.transaction_id,
        instructionId: row.instruction_id,
        batchId: row.batch_id,
        batchReference: row.batch_reference,
        recipientName: row.recipient_name,
        msisdn: row.msisdn,
        departmentName: row.department_name,
        amountCents: Number(row.amount_cents),
        status: row.status,
        statusTone: statusTone(row.status),
        failureCode: row.failure_code,
        failureReason: row.failure_reason ?? resolved.failureReason,
        failureClass: row.failure_class ?? resolved.failureClass,
        operatorAction: row.failure_code ? resolved.operatorAction : null,
        providerResultDescription: row.provider_result_description,
        mpesaReceiptNumber: row.mpesa_receipt_number,
        conversationId: row.conversation_id,
        originatorConversationId: row.originator_conversation_id,
        statusSource: row.status_source,
        lastStatusCheckAt: row.last_status_check_at,
        createdAt: row.created_at,
        submittedAt: row.submitted_at,
        completedAt: row.completed_at,
        retryEligible: isRetryEligible(row.status, row.failure_code),
      },
      activity,
      reconciliationCases: reconciliation,
    };
  });

  return c.json(result);
});

/**
 * POST /api/transactions/:id/retry — reissue an eligible failed payment.
 *
 * Never a resend of the same instruction: the retry creates a NEW instruction in a
 * correction batch that travels the full approval chain again (spec §9.3: "explicit
 * do-not-retry rules for non-idempotent failures"; §4.4: retry subject to policy).
 */
transactionRoutes.post(
  '/transactions/:id/retry',
  requirePermissions('transactions:retry'),
  rateLimit('actor', { ratePerSecond: 0.2, burst: 10 }),
  async (c) => {
    const actor = actorOf(c);
    const transactionId = c.req.param('id');
    const correlationId = c.get('correlationId');
    if (!UUID_PATTERN.test(transactionId)) {
      throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
    }

    const result = await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const policy = await loadPolicy(tx, actor.organizationId);
        if (actor.level === 'L1' && !policy.allowL1Retry) {
          throw authorizationError(
            'RETRY_NOT_PERMITTED',
            'Your organisation does not permit Level 1 to reissue failed payments. Ask Finance Control to retry it.',
          );
        }

        const rows = await tx<
          {
            id: string;
            status: TxnState;
            failure_code: string | null;
            instruction_id: string;
            batch_id: string;
          }[]
        >`
          SELECT id, status, failure_code, instruction_id, batch_id
            FROM transactions
           WHERE id = ${transactionId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const transaction = rows[0];
        if (!transaction) {
          throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
        }

        if (!isRetryEligible(transaction.status, transaction.failure_code)) {
          throw validationError(
            'RETRY_NOT_ELIGIBLE',
            `This transaction is ${transaction.status}${transaction.failure_code ? ` (code ${transaction.failure_code})` : ''} and is not eligible for reissue. ${transaction.failure_code ? 'The failure is permanent until its cause is corrected.' : ''}`,
          );
        }

        const originals = await tx<
          {
            id: string;
            batch_reference: string;
            recipient_id: string;
            recipient_name_snapshot: string;
            msisdn_snapshot: string;
            department_id: string | null;
            amount_cents: string;
            remarks: string;
            occasion: string | null;
          }[]
        >`
          SELECT pi.id, b.batch_reference, pi.recipient_id, pi.recipient_name_snapshot,
                 pi.msisdn_snapshot, pi.department_id, pi.amount_cents, pi.remarks, pi.occasion
            FROM payment_instructions pi
            JOIN payment_batches b ON b.id = pi.batch_id
           WHERE pi.id = ${transaction.instruction_id}
             AND pi.organization_id = ${actor.organizationId}
           LIMIT 1
        `;
        const original = originals[0];
        if (!original) {
          throw notFoundError('INSTRUCTION_NOT_FOUND', 'The original instruction could not be found');
        }

        // Find or create this user's open correction batch for the source batch.
        const existing = await tx<{ id: string; batch_reference: string }[]>`
          SELECT id, batch_reference FROM payment_batches
           WHERE organization_id = ${actor.organizationId}
             AND state IN ('DRAFT', 'VALIDATED', 'RETURNED_FOR_CORRECTION')
             AND purpose = ${`Retry correction for ${original.batch_reference}`}
           LIMIT 1
          FOR UPDATE
        `;

        let correctionBatchId: string;
        let correctionReference: string;
        if (existing[0]) {
          correctionBatchId = existing[0].id;
          correctionReference = existing[0].batch_reference;
        } else {
          const created = await tx<{ id: string; batch_reference: string }[]>`
            INSERT INTO payment_batches (
              organization_id, batch_reference, purpose, payment_period, state, created_by_user_id
            ) VALUES (
              ${actor.organizationId}, ${reference('batch')},
              ${`Retry correction for ${original.batch_reference}`}, NULL, 'DRAFT', ${actor.userId}
            )
            RETURNING id, batch_reference
          `;
          correctionBatchId = created[0]!.id;
          correctionReference = created[0]!.batch_reference;
        }

        const inserted = await tx<{ id: string }[]>`
          INSERT INTO payment_instructions (
            organization_id, batch_id, recipient_id, recipient_name_snapshot, msisdn_snapshot,
            department_id, amount_cents, remarks, occasion, retry_of_instruction_id
          ) VALUES (
            ${actor.organizationId}, ${correctionBatchId}, ${original.recipient_id},
            ${original.recipient_name_snapshot}, ${original.msisdn_snapshot},
            ${original.department_id}, ${original.amount_cents}, ${original.remarks},
            ${original.occasion}, ${original.id}
          )
          RETURNING id
        `;

        // The correction batch is a new version of work; mark it edited.
        await tx`
          UPDATE payment_batches
             SET version = version + 1, last_material_edit_at = now(), state = 'DRAFT'
           WHERE id = ${correctionBatchId}
        `;
        await tx`
          INSERT INTO batch_editors (batch_id, user_id)
          VALUES (${correctionBatchId}, ${actor.userId})
          ON CONFLICT (batch_id, user_id) DO UPDATE
            SET last_edited_at = now(), edit_count = batch_editors.edit_count + 1
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'PAYMENT',
          action: 'payment.retry.issued',
          objectType: 'Transaction',
          objectId: transactionId,
          outcome: 'SUCCESS',
          previousState: { status: transaction.status, failureCode: transaction.failure_code },
          newState: { correctionBatchId, newInstructionId: inserted[0]!.id },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            originalInstructionId: original.id,
            correctionBatchReference: correctionReference,
            note: 'Reissued as a NEW instruction that must travel the full approval chain.',
          },
        });

        return {
          retried: true as const,
          correctionBatchId,
          correctionBatchReference: correctionReference,
          newInstructionId: inserted[0]!.id,
          message: `A new instruction was created in correction batch ${correctionReference}. It must be validated, approved and authorized before payment — a retry never bypasses the chain.`,
        };
      }),
    );

    return c.json(result, 202);
  },
);

/** POST /api/transactions/:id/refresh — on-demand status refresh (L2/L3). */
transactionRoutes.post(
  '/transactions/:id/refresh',
  requirePermissions('transactions:refresh_status'),
  async (c) => {
    const actor = actorOf(c);
    const transactionId = c.req.param('id');
    const correlationId = c.get('correlationId');

    if (!UUID_PATTERN.test(transactionId)) {
      throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
    }

    await withConnection(c.env, async (sql) => {
      const rows = await sql<{ id: string; status: TxnState }[]>`
        SELECT id, status FROM transactions
         WHERE id = ${transactionId} AND organization_id = ${actor.organizationId}
         LIMIT 1
      `;
      const transaction = rows[0];
      if (!transaction) {
        throw notFoundError('TRANSACTION_NOT_FOUND', 'That transaction could not be found');
      }
      if (['SUCCESS', 'FAILED', 'CANCELLED'].includes(transaction.status)) {
        throw validationError(
          'TRANSACTION_ALREADY_SETTLED',
          `This transaction is already settled as ${transaction.status}. Its outcome will not change.`,
        );
      }

      const message: ReconciliationQueueMessage = {
        type: 'RECONCILE_TRANSACTION',
        organizationId: actor.organizationId,
        transactionId,
        requestedByUserId: actor.userId,
        correlationId,
      };
      await c.env.queue.send({ queue: 'reconciliation', body: message });

      await inTransaction(sql, (tx) =>
        writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'transaction.status_refresh.requested',
          objectType: 'Transaction',
          objectId: transactionId,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: { currentStatus: transaction.status },
        }),
      );
    });

    return c.json(
      {
        accepted: true,
        message:
          'A status query has been sent to M-PESA. The result arrives asynchronously; this page will update when it does.',
      },
      202,
    );
  },
);

/** GET /api/transactions/batches/:id/rollup — the batch outcome header. */
transactionRoutes.get('/batches/:id/rollup', requirePermissions('transactions:read'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  if (!UUID_PATTERN.test(batchId)) {
    throw notFoundError('BATCH_NOT_FOUND', 'That payment batch could not be found');
  }

  const rollup = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        batch_reference: string;
        state: string;
        instruction_count: number;
        total_amount_cents: string;
        success_count: string;
        failed_count: string;
        timeout_count: string;
        in_flight_count: string;
        disbursed_cents: string;
        failed_cents: string;
      }[]
    >`
      SELECT batch_reference, state, instruction_count, total_amount_cents, success_count,
             failed_count, timeout_count, in_flight_count, disbursed_cents, failed_cents
        FROM batch_outcome_rollup
       WHERE batch_id = ${batchId} AND organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const row = rows[0];
    if (!row) throw notFoundError('BATCH_NOT_FOUND', 'That payment batch could not be found');

    return {
      batchReference: row.batch_reference,
      state: row.state,
      instructionCount: row.instruction_count,
      totalAmountCents: Number(row.total_amount_cents),
      successCount: Number(row.success_count),
      failedCount: Number(row.failed_count),
      timeoutCount: Number(row.timeout_count),
      inFlightCount: Number(row.in_flight_count),
      disbursedCents: Number(row.disbursed_cents),
      failedCents: Number(row.failed_cents),
    };
  });

  return c.json(rollup);
});

/** GET /api/transactions/failure-summary — failures grouped by reason, for triage. */
transactionRoutes.get('/failure-summary', requirePermissions('transactions:read'), async (c) => {
  const actor = actorOf(c);
  const batchId = z
    .string()
    .uuid()
    .optional()
    .parse(new URL(c.req.url).searchParams.get('batchId') ?? undefined);

  const summary = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      { failure_code: string; failure_reason: string; failure_class: string; count: string; total_cents: string }[]
    >`
      SELECT t.failure_code, t.failure_reason, t.failure_class,
             COUNT(*) AS count, SUM(pi.amount_cents) AS total_cents
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE t.organization_id = ${actor.organizationId}
         AND t.status IN ('FAILED', 'TIMEOUT')
         AND (${batchId ?? null}::uuid IS NULL OR t.batch_id = ${batchId ?? null}::uuid)
       GROUP BY t.failure_code, t.failure_reason, t.failure_class
       ORDER BY COUNT(*) DESC
       LIMIT 50
    `;

    const overrides = await loadFailureOverrides(sql, actor.organizationId);
    return rows.map((row) => {
      const resolved = resolveFailure(row.failure_code, null, overrides);
      return {
        failureCode: row.failure_code,
        failureReason: row.failure_reason ?? resolved.failureReason,
        failureClass: row.failure_class ?? resolved.failureClass,
        operatorAction: resolved.operatorAction,
        count: Number(row.count),
        totalCents: Number(row.total_cents),
      };
    });
  });

  return c.json({ failures: summary });
});

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/**
 * GET /api/exports/transactions/failed — the one-click failed-transactions CSV.
 *
 * Honours the current filter, builds from ledger rows, preserves provider identifiers,
 * is role-scoped by policy, and writes an audit event carrying actor, filter, row count.
 */
exportRoutes.get(
  '/transactions/failed',
  requirePermissions('transactions:export_failed'),
  rateLimit('actor', { ratePerSecond: 0.05, burst: 5 }),
  async (c) => {
    const actor = actorOf(c);
    const correlationId = c.get('correlationId');
    const url = new URL(c.req.url);
    const includeAmbiguous = url.searchParams.get('includeAmbiguous') === 'true';

    const csv = await withConnection(c.env, async (sql) => {
      const policy = await loadPolicy(sql, actor.organizationId);

      // L1 export access is organisation-configurable (spec §4.4).
      if (!canExportFailedTransactions(toActor(actor), policy, c.get('permissionMatrix'))) {
        await inTransaction(sql, (tx) =>
          writeAuditEvent(tx, {
            organizationId: actor.organizationId,
            actorId: actor.userId,
            actorLevel: actor.level,
            eventClass: 'DATA_EXPORT',
            action: 'export.failed_transactions.denied',
            objectType: 'Export',
            objectId: null,
            outcome: 'DENIED',
            correlationId,
            securityContext: c.get('securityContext'),
            detail: { reason: 'Organisation policy does not permit this level to export failures' },
          }),
        );
        throw authorizationError(
          'EXPORT_NOT_PERMITTED',
          'Your organisation does not permit Level 1 to download failed-transaction exports. Ask Finance Control to generate it.',
        );
      }

      const requested = parseExplorerQuery(url);
      // The export is *of failures*: the status filter is fixed here rather than trusted
      // from the query string, so this endpoint can never be used to export everything.
      const statuses: TxnState[] = includeAmbiguous
        ? (['FAILED', 'TIMEOUT', 'AWAITING_CALLBACK', 'RECONCILING'] as TxnState[])
        : (['FAILED'] as TxnState[]);
      const query = { ...requested, status: statuses, page: 1 };

      const { rows, total } = await queryExplorer(
        sql,
        actor.organizationId,
        query,
        Math.min(policy.maxExportRows, 100_000),
      );

      const filter = describeFilter(query);
      const exportReference = reference('export');
      const generatedAt = new Date().toISOString();
      const overrides = await loadFailureOverrides(sql, actor.organizationId);

      const exportRows: TransactionExportRow[] = rows.map((row) => {
        const resolved = resolveFailure(
          row.failure_code,
          row.provider_result_description,
          overrides,
        );
        return {
          batchReference: row.batch_reference,
          batchId: row.batch_id,
          instructionId: row.instruction_id,
          recipientName: row.recipient_name,
          msisdn: row.msisdn,
          departmentName: row.department_name,
          amountCents: Number(row.amount_cents),
          status: row.status,
          failureCode: row.failure_code ?? resolved.failureCode,
          failureReason: row.failure_reason ?? resolved.failureReason,
          operatorAction: resolved.operatorAction,
          providerResultDescription: row.provider_result_description,
          mpesaReceiptNumber: row.mpesa_receipt_number,
          conversationId: row.conversation_id,
          originatorConversationId: row.originator_conversation_id,
          submittedAt: row.submitted_at,
          completedAt: row.completed_at,
          lastUpdatedAt: row.updated_at,
          lastStatusCheckAt: row.last_status_check_at,
          statusSource: row.status_source,
        };
      });

      const body = renderFailedTransactionsCsv(exportRows, {
        exportId: exportReference,
        organizationId: actor.organizationId,
        generatedAt,
        generatedByUserId: actor.userId,
        generatedByLevel: actor.level,
        filterDescription: filter.text,
        rowCount: exportRows.length,
      });

      await inTransaction(sql, async (tx) => {
        await tx`
          INSERT INTO export_records (
            organization_id, export_reference, export_type, requested_by_user_id,
            requested_by_level, filter_description, filter_json, row_count, byte_size,
            status, completed_at, correlation_id
          ) VALUES (
            ${actor.organizationId}, ${exportReference}, 'FAILED_TRANSACTIONS', ${actor.userId},
            ${actor.level}, ${filter.text}, ${tx.json(query as never)}, ${exportRows.length},
            ${body.length}, 'COMPLETED', now(), ${correlationId}
          )
        `;
        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'DATA_EXPORT',
          action: 'export.failed_transactions',
          objectType: 'Export',
          objectId: exportReference,
          outcome: 'SUCCESS',
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            exportReference,
            filter: filter.text,
            rowCount: exportRows.length,
            byteSize: body.length,
            truncated: total > exportRows.length,
            includeAmbiguous,
          },
        });
      });

      const slug = await sql<{ slug: string }[]>`
        SELECT slug FROM organizations WHERE id = ${actor.organizationId}
      `;

      return {
        body,
        filename: exportFilename('failed-transactions', slug[0]?.slug ?? 'org', generatedAt),
        truncated: total > exportRows.length,
        total,
      };
    });

    return new Response(csv.body, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${csv.filename}"`,
        'Cache-Control': 'no-store',
        'X-Solvaren-Row-Truncated': String(csv.truncated),
        'X-Solvaren-Total-Matching': String(csv.total),
      },
    });
  },
);

