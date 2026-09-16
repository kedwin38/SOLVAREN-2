/**
 * Directory: recipients (employee/supplier/contractor master data), departments, and
 * reconciliation case management (spec §5.1 recipients, §9.5 reconciliation, §4.4
 * "Reconciliation: Limited (L1) / Yes (L2/L3)").
 *
 * The reconciliation surface completes the loop the executor opens: ESCALATED and
 * discrepant cases get a human resolution workflow here, with the ledger untouched —
 * a manual resolution records a decision and evidence; it never rewrites a transaction.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import { normalizeMsisdn, maskMsisdn, notFoundError, validationError, stateError } from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { AppContext } from '../env.js';

export const directoryRoutes = new Hono<AppContext>();
directoryRoutes.use('*', requireAuth);

export const departmentRoutes = new Hono<AppContext>();
departmentRoutes.use('*', requireAuth);

export const reconciliationRoutes = new Hono<AppContext>();
reconciliationRoutes.use('*', requireAuth);

// ---------------------------------------------------------------------------
// Recipients
// ---------------------------------------------------------------------------

const recipientSchema = z.object({
  fullName: z.string().trim().min(1).max(140),
  msisdn: z.string().trim().min(9).max(20),
  externalReference: z.string().trim().max(100).optional(),
  departmentId: z.string().uuid().optional(),
  notes: z.string().trim().max(500).optional(),
  role: z.string().trim().max(80).optional(),
  territory: z.string().trim().max(80).optional(),
  region: z.string().trim().max(80).optional(),
});

directoryRoutes.post('/recipients', requirePermissions('recipients:write'), async (c) => {  const actor = actorOf(c);
  const body = recipientSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const created = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const rows = await tx<{ id: string }[]>`
        INSERT INTO recipients (
          organization_id, full_name, msisdn, external_reference, department_id, notes,
          role, territory, region, created_by_user_id
        ) VALUES (
          ${actor.organizationId}, ${body.fullName}, ${normalizeMsisdn(body.msisdn)},
          ${body.externalReference ?? null}, ${body.departmentId ?? null}, ${body.notes ?? null},
          ${body.role ?? null}, ${body.territory ?? null}, ${body.region ?? null},
          ${actor.userId}
        )
        ON CONFLICT (organization_id, msisdn) DO UPDATE
          SET full_name = EXCLUDED.full_name,
              external_reference = COALESCE(EXCLUDED.external_reference, recipients.external_reference),
              department_id = COALESCE(EXCLUDED.department_id, recipients.department_id),
              role = COALESCE(EXCLUDED.role, recipients.role),
              territory = COALESCE(EXCLUDED.territory, recipients.territory),
              region = COALESCE(EXCLUDED.region, recipients.region)
        RETURNING id
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'recipient.upserted',
        objectType: 'Recipient',
        objectId: rows[0]!.id,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { msisdnMasked: maskMsisdn(normalizeMsisdn(body.msisdn)) },
      });
      return rows[0]!;
    }),
  );

  return c.json({ recipientId: created.id }, 201);
});

directoryRoutes.get('/recipients', requirePermissions('recipients:read'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const search = url.searchParams.get('search')?.trim();
  const status = url.searchParams.get('status');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '50'), 200);
  const offset = Math.max(Number(url.searchParams.get('offset') ?? '0'), 0);

  const data = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        id: string;
        full_name: string;
        msisdn: string;
        external_reference: string | null;
        department_name: string | null;
        status: string;
        notes: string | null;
        created_at: string;
        paid_count: string;
        total_paid_cents: string;
        role: string | null;
        territory: string | null;
        region: string | null;
      }[]
    >`
      SELECT r.id, r.full_name, r.msisdn, r.external_reference,
             d.name AS department_name, r.status, r.notes, r.created_at,
             COALESCE(h.successful_payment_count, 0) AS paid_count,
             COALESCE(h.mean_amount_cents, 0) AS total_paid_cents,
             r.role, r.territory, r.region
        FROM recipients r
        LEFT JOIN departments d ON d.id = r.department_id
        LEFT JOIN recipient_payment_history h ON h.recipient_id = r.id
       WHERE r.organization_id = ${actor.organizationId}
         AND (${status ?? null}::text IS NULL OR r.status = ${status ?? null}::text)
         AND (${search ?? null}::text IS NULL
              OR r.full_name ILIKE '%' || ${search ?? null} || '%'
              OR r.msisdn ILIKE '%' || ${search ?? null} || '%'
              OR r.external_reference ILIKE '%' || ${search ?? null} || '%')
       ORDER BY r.full_name
       LIMIT ${limit} OFFSET ${offset}
    `;
    const total = await sql<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM recipients
       WHERE organization_id = ${actor.organizationId}
         AND (${status ?? null}::text IS NULL OR status = ${status ?? null}::text)
    `;
    return { rows, total: Number(total[0]?.count ?? 0) };
  });

  return c.json({
    recipients: data.rows.map((r) => ({
      recipientId: r.id,
      fullName: r.full_name,
      msisdn: r.msisdn,
      departmentName: r.department_name,
      externalReference: r.external_reference,
      status: r.status,
      notes: r.notes,
      createdAt: r.created_at,
      paymentCount: Number(r.paid_count),
      meanAmountCents: Number(r.total_paid_cents),
      role: r.role,
      territory: r.territory,
      region: r.region,
    })),
    total: data.total,
    limit,
    offset,
  });
});

directoryRoutes.patch('/recipients/:id', requirePermissions('recipients:write'), async (c) => {
  const actor = actorOf(c);
  const recipientId = c.req.param('id');
  const body = z
    .object({
      fullName: z.string().trim().min(1).max(140).optional(),
      msisdn: z.string().trim().min(9).max(20).optional(),
      departmentId: z.string().uuid().nullable().optional(),
      status: z.enum(['ACTIVE', 'INACTIVE', 'BLOCKED']).optional(),
      notes: z.string().trim().max(500).nullable().optional(),
      role: z.string().trim().max(80).nullable().optional(),
      territory: z.string().trim().max(80).nullable().optional(),
      region: z.string().trim().max(80).nullable().optional(),
    })
    .refine((v) => Object.keys(v).length > 0, { message: 'Nothing to change' })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const existing = await tx<{ full_name: string; msisdn: string; status: string }[]>`
        SELECT full_name, msisdn, status FROM recipients
         WHERE id = ${recipientId} AND organization_id = ${actor.organizationId}
         FOR UPDATE
      `;
      if (!existing[0]) throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');

      await tx`
        UPDATE recipients SET
          full_name = COALESCE(${body.fullName ?? null}, full_name),
          msisdn = COALESCE(${body.msisdn ? normalizeMsisdn(body.msisdn) : null}, msisdn),
          department_id = COALESCE(${body.departmentId ?? null}, department_id),
          status = COALESCE(${body.status ?? null}, status),
          notes = COALESCE(${body.notes ?? null}, notes),
          role = COALESCE(${body.role ?? null}, role),
          territory = COALESCE(${body.territory ?? null}, territory),
          region = COALESCE(${body.region ?? null}, region),
          updated_at = now()
        WHERE id = ${recipientId}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'recipient.updated',
        objectType: 'Recipient',
        objectId: recipientId,
        outcome: 'SUCCESS',
        previousState: { status: existing[0].status },
        newState: { status: body.status ?? existing[0].status, fields: Object.keys(body) },
        correlationId,
        securityContext: c.get('securityContext'),
        // A recently modified recipient raises a HIGH risk signal on the next payment.
        detail: { modifiedBy: actor.userId, note: 'Master-data change; risk engine will flag recent modification.' },
      });

      return { updated: true as const };
    }),
  );

  return c.json(result);
});

/** GET /api/recipients/:id/history — payment history matched to the individual (spec §12). */
directoryRoutes.get('/recipients/:id/history', requirePermissions('recipients:read'), async (c) => {
  const actor = actorOf(c);
  const recipientId = c.req.param('id');

  const data = await withConnection(c.env, async (sql) => {
    const recipients = await sql<{ id: string; full_name: string; msisdn: string }[]>`
      SELECT id, full_name, msisdn FROM recipients
       WHERE id = ${recipientId} AND organization_id = ${actor.organizationId}
    `;
    if (!recipients[0]) throw notFoundError('RECIPIENT_NOT_FOUND', 'That recipient could not be found');

    const history = await sql<
      {
        batch_reference: string;
        amount_cents: string;
        status: string;
        failure_code: string | null;
        mpesa_receipt_number: string | null;
        completed_at: string | null;
      }[]
    >`
      SELECT b.batch_reference, pi.amount_cents, t.status, t.failure_code,
             t.mpesa_receipt_number, t.completed_at
        FROM transactions t
        JOIN payment_instructions pi ON pi.id = t.instruction_id
        JOIN payment_batches b ON b.id = t.batch_id
       WHERE pi.recipient_id = ${recipientId} AND t.organization_id = ${actor.organizationId}
       ORDER BY t.created_at DESC
       LIMIT 200
    `;

    return {
      recipient: {
        recipientId: recipients[0].id,
        fullName: recipients[0].full_name,
        msisdnMasked: maskMsisdn(recipients[0].msisdn),
      },
      history: history.map((h) => ({
        batchReference: h.batch_reference,
        amountCents: Number(h.amount_cents),
        status: h.status,
        failureCode: h.failure_code,
        mpesaReceipt: h.mpesa_receipt_number,
        completedAt: h.completed_at,
      })),
    };
  });

  return c.json(data);
});

// ---------------------------------------------------------------------------
// Departments
// ---------------------------------------------------------------------------

departmentRoutes.post('/', requirePermissions('departments:write'), async (c) => {
  const actor = actorOf(c);
  const body = z
    .object({ name: z.string().trim().min(1).max(100) })
    .parse(await c.req.json());

  const created = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const rows = await tx<{ id: string }[]>`
        INSERT INTO departments (organization_id, name)
        VALUES (${actor.organizationId}, ${body.name})
        ON CONFLICT (organization_id, name) DO UPDATE SET name = EXCLUDED.name
        RETURNING id
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'department.upserted',
        objectType: 'Department',
        objectId: rows[0]!.id,
        outcome: 'SUCCESS',
        correlationId: c.get('correlationId'),
        securityContext: c.get('securityContext'),
        detail: { name: body.name },
      });
      return rows[0]!;
    }),
  );

  return c.json({ departmentId: created.id }, 201);
});

departmentRoutes.get('/', requirePermissions('departments:read'), async (c) => {
  const actor = actorOf(c);
  const departments = await withConnection(c.env, (sql) =>
    sql<{ id: string; name: string; status: string; recipient_count: string }[]>`
      SELECT d.id, d.name, d.status,
             (SELECT COUNT(*) FROM recipients r WHERE r.department_id = d.id) AS recipient_count
        FROM departments d
       WHERE d.organization_id = ${actor.organizationId}
       ORDER BY d.name
    `,
  );
  return c.json({
    departments: departments.map((d) => ({
      departmentId: d.id,
      name: d.name,
      status: d.status,
      recipientCount: Number(d.recipient_count),
    })),
  });
});

// ---------------------------------------------------------------------------
// Reconciliation cases (spec §9.5, §23)
// ---------------------------------------------------------------------------

reconciliationRoutes.get('/', requirePermissions('reconciliation:read'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const state = url.searchParams.get('state');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '100'), 200);

  const cases = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        case_reference: string;
        state: string;
        opened_reason: string;
        discrepancy: boolean;
        query_attempts: number;
        opened_at: string;
        resolved_at: string | null;
        resolution_note: string | null;
        transaction_id: string;
        batch_reference: string | null;
        recipient_name: string | null;
        amount_cents: string | null;
        txn_status: string | null;
      }[]
    >`
      SELECT rc.id, rc.case_reference, rc.state, rc.opened_reason, rc.discrepancy,
             rc.query_attempts, rc.opened_at, rc.resolved_at, rc.resolution_note,
             rc.transaction_id, b.batch_reference,
             pi.recipient_name_snapshot AS recipient_name, pi.amount_cents, t.status AS txn_status
        FROM reconciliation_cases rc
        JOIN transactions t ON t.id = rc.transaction_id
        LEFT JOIN payment_batches b ON b.id = t.batch_id
        LEFT JOIN payment_instructions pi ON pi.id = t.instruction_id
       WHERE rc.organization_id = ${actor.organizationId}
         AND (${state ?? null}::text IS NULL OR rc.state = ${state ?? null}::text)
       ORDER BY rc.opened_at DESC
       LIMIT ${limit}
    `,
  );

  return c.json({
    cases: cases.map((k) => ({
      caseId: k.id,
      caseReference: k.case_reference,
      state: k.state,
      openedReason: k.opened_reason,
      discrepancy: k.discrepancy,
      queryAttempts: k.query_attempts,
      openedAt: k.opened_at,
      resolvedAt: k.resolved_at,
      resolutionNote: k.resolution_note,
      transactionId: k.transaction_id,
      batchReference: k.batch_reference,
      recipientName: k.recipient_name,
      amountCents: k.amount_cents ? Number(k.amount_cents) : null,
      transactionStatus: k.txn_status,
    })),
  });
});

/**
 * POST /api/reconciliation/:id/resolve — record the human decision on an escalated or
 * discrepant case (spec §23 "Timeout → manual reconciliation workflow").
 *
 * The ledger is never rewritten here. The resolution records what the operator
 * established (e.g. "confirmed paid on the M-PESA portal, receipt SG…") as evidence
 * attached to the case; if the provider's own status query later contradicts it, the
 * existing discrepancy machinery handles that.
 */
reconciliationRoutes.post(
  '/:id/resolve',
  requirePermissions('reconciliation:resolve'),
  async (c) => {
    const actor = actorOf(c);
    const caseId = c.req.param('id');
    const body = z
      .object({
        outcome: z.enum(['RESOLVED_MANUAL', 'RESOLVED_SUCCESS', 'RESOLVED_FAILED']),
        note: z.string().trim().min(10).max(1000),
        /** The receipt observed on the M-PESA portal, when the outcome is SUCCESS. */
        portalReceipt: z.string().trim().max(30).optional(),
      })
      .parse(await c.req.json());
    const correlationId = c.get('correlationId');

    await withConnection(c.env, (sql) =>
      inTransaction(sql, async (tx) => {
        const rows = await tx<{ id: string; state: string; transaction_id: string }[]>`
          SELECT id, state, transaction_id FROM reconciliation_cases
           WHERE id = ${caseId} AND organization_id = ${actor.organizationId}
           FOR UPDATE
        `;
        const kase = rows[0];
        if (!kase) throw notFoundError('CASE_NOT_FOUND', 'That reconciliation case could not be found');
        if (['RESOLVED_SUCCESS', 'RESOLVED_FAILED', 'RESOLVED_MANUAL'].includes(kase.state)) {
          throw stateError('CASE_ALREADY_RESOLVED', `This case is already ${kase.state}`);
        }
        if (body.outcome === 'RESOLVED_SUCCESS' && !body.portalReceipt) {
          throw validationError(
            'RECEIPT_REQUIRED',
            'Recording a manual success requires the M-PESA receipt observed on the organisation portal',
          );
        }

        await tx`
          UPDATE reconciliation_cases
             SET state = ${body.outcome}, resolved_at = now(),
                 resolution_note = ${`Manual resolution by ${actor.fullName}: ${body.note}${body.portalReceipt ? ` (portal receipt ${body.portalReceipt})` : ''}`},
                 resolved_by_user_id = ${actor.userId},
                 evidence = evidence || ${tx.json([
                   {
                     at: new Date().toISOString(),
                     kind: 'MANUAL_RESOLUTION',
                     outcome: body.outcome,
                     note: body.note,
                     portalReceipt: body.portalReceipt ?? null,
                     resolvedBy: actor.userId,
                   },
                 ] as never)}
           WHERE id = ${caseId}
        `;

        await writeAuditEvent(tx, {
          organizationId: actor.organizationId,
          actorId: actor.userId,
          actorLevel: actor.level,
          eventClass: 'INTEGRATION',
          action: 'reconciliation.resolved_manually',
          objectType: 'ReconciliationCase',
          objectId: caseId,
          outcome: 'SUCCESS',
          previousState: { state: kase.state },
          newState: { state: body.outcome, portalReceipt: body.portalReceipt ?? null },
          correlationId,
          securityContext: c.get('securityContext'),
          detail: {
            note: body.note,
            transactionId: kase.transaction_id,
            ledgerModified: false,
            note2: 'The transaction record was NOT modified; this records a human decision with evidence.',
          },
        });
      }),
    );

    return c.json({ resolved: true });
  },
);
