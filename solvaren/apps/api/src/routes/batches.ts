/**
 * Payment batch lifecycle (spec §6). Every state change goes through `assertTransition`
 * in @solvaren/core, so the set of legal moves is the state machine and nothing else.
 * The separation-of-duties checks live at the approval and submission boundaries.
 *
 * The complete command surface the spec's state machine defines is actually wired here —
 * including CANCEL, RELEASE_HOLD and RETURN_TO_L1, so no workflow state is a dead end.
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  parsePaymentCsv,
  assertTransition,
  assertNotSelfApproval,
  assertCoolingOff,
  normalizeMsisdn,
  reference,
  isEditable,
  allowedCommands,
  effectivePermissionsOf,
  notFoundError,
  validationError,
  stateError,
  MAX_CSV_BYTES,
  type BatchState,
} from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction, requireLock } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import { loadPolicy } from '../services/policy-store.js';
import { assessBatch, persistFindings } from '../services/risk-service.js';
import { loadBatch } from '../services/authorization.js';
import type { AppContext } from '../env.js';

export const batchRoutes = new Hono<AppContext>();
batchRoutes.use('*', requireAuth);

const createBatchSchema = z.object({
  purpose: z.string().trim().min(3).max(200),
  departmentId: z.string().uuid().optional(),
  paymentPeriod: z.string().trim().max(60).optional(),
});

/** POST /api/payment-batches — create a draft batch (L1 preparation). */
batchRoutes.post('/', requirePermissions('batch:create'), async (c) => {
  const actor = actorOf(c);
  const body = createBatchSchema.parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const batch = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      const batchReference = reference('batch');
      const rows = await tx<{ id: string; batch_reference: string; state: BatchState }[]>`
        INSERT INTO payment_batches (
          organization_id, batch_reference, purpose, department_id, payment_period,
          created_by_user_id, state
        ) VALUES (
          ${actor.organizationId}, ${batchReference}, ${body.purpose},
          ${body.departmentId ?? null}, ${body.paymentPeriod ?? null}, ${actor.userId}, 'DRAFT'
        )
        RETURNING id, batch_reference, state
      `;
      const created = rows[0]!;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.created',
        objectType: 'PaymentBatch',
        objectId: created.id,
        outcome: 'SUCCESS',
        newState: { state: 'DRAFT', purpose: body.purpose },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { batchReference },
      });

      return created;
    }),
  );

  return c.json(
    { batchId: batch.id, batchReference: batch.batch_reference, state: batch.state },
    201,
  );
});

/**
 * POST /api/payment-batches/:id/upload — ingest a CSV into an editable batch.
 *
 * Returns valid rows *and* per-row errors rather than rejecting the whole file, so an
 * operator fixes six bad rows instead of re-exporting a payroll of two thousand.
 */
batchRoutes.post('/:id/upload', requirePermissions('batch:edit'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const correlationId = c.get('correlationId');

  const contentLength = Number(c.req.header('Content-Length') ?? '0');
  if (contentLength > MAX_CSV_BYTES) {
    throw validationError('CSV_TOO_LARGE', 'The uploaded file exceeds the 8 MB limit');
  }

  const form = await c.req.formData();
  const file = form.get('file');
  if (!file || typeof file === 'string' || typeof (file as Blob).text !== 'function') {
    throw validationError('CSV_FILE_REQUIRED', 'Attach a CSV file under the field name "file"');
  }
  const upload = file as Blob & { name?: string };
  const text = await upload.text();

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      if (!isEditable(batch.state)) {
        throw stateError(
          'BATCH_NOT_EDITABLE',
          `This batch is in state ${batch.state} and can no longer be edited. Its instructions are part of the financial record.`,
          { state: batch.state, allowed: allowedCommands(batch.state) },
        );
      }

      const policy = await loadPolicy(tx, actor.organizationId);
      const parsed = parsePaymentCsv(text, { maxRows: policy.maxBatchInstructions });

      // Replace the instruction set wholesale: a partial merge between two uploads is how
      // an operator ends up paying a row they thought they had removed.
      await tx`DELETE FROM payment_instructions WHERE batch_id = ${batch.id}`;

      let inserted = 0;
      const unresolved: { lineNumber: number; reason: string }[] = [];

      for (const row of parsed.rows) {
        // Upsert the recipient master record. A brand-new recipient is fine; it simply
        // raises a NEW_RECIPIENT risk signal for the reviewer.
        const recipients = await tx<{ id: string; status: string; department_id: string | null }[]>`
          INSERT INTO recipients (organization_id, full_name, msisdn, external_reference, created_by_user_id)
          VALUES (${actor.organizationId}, ${row.recipientName}, ${normalizeMsisdn(row.msisdn)},
                  ${row.reference}, ${actor.userId})
          ON CONFLICT (organization_id, msisdn) DO UPDATE
            SET external_reference = COALESCE(EXCLUDED.external_reference, recipients.external_reference)
          RETURNING id, status, department_id
        `;
        const recipient = recipients[0]!;

        if (recipient.status !== 'ACTIVE') {
          unresolved.push({
            lineNumber: row.lineNumber,
            reason: `${row.recipientName} is marked ${recipient.status} and cannot be paid until reactivated`,
          });
          continue;
        }

        let departmentId = recipient.department_id;
        if (row.department) {
          const departments = await tx<{ id: string }[]>`
            INSERT INTO departments (organization_id, name)
            VALUES (${actor.organizationId}, ${row.department})
            ON CONFLICT (organization_id, name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
          `;
          departmentId = departments[0]!.id;
        }

        await tx`
          INSERT INTO payment_instructions (
            organization_id, batch_id, recipient_id, recipient_name_snapshot, msisdn_snapshot,
            department_id, amount_cents, remarks, source_line_number
          ) VALUES (
            ${actor.organizationId}, ${batch.id}, ${recipient.id}, ${row.recipientName},
            ${normalizeMsisdn(row.msisdn)}, ${departmentId}, ${row.amountCents},
            ${(row.remarks ?? 'Business payment').slice(0, 100)}, ${row.lineNumber}
          )
        `;
        inserted += 1;
      }

      // Any edit invalidates prior validation and any approval bound to the old version.
      await tx`
        UPDATE payment_batches
           SET state = 'DRAFT', version = version + 1, last_material_edit_at = now()
         WHERE id = ${batch.id}
      `;
      await tx`
        INSERT INTO batch_editors (batch_id, user_id)
        VALUES (${batch.id}, ${actor.userId})
        ON CONFLICT (batch_id, user_id) DO UPDATE
          SET last_edited_at = now(), edit_count = batch_editors.edit_count + 1
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.csv_uploaded',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state, version: batch.version },
        newState: { state: 'DRAFT', version: batch.version + 1 },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          fileName: upload.name ?? 'upload.csv',
          rowsAccepted: inserted,
          rowsRejected: parsed.errors.length + unresolved.length,
          duplicateWarnings: parsed.duplicateWarnings.length,
        },
      });

      return {
        accepted: inserted,
        rejected: [
          ...parsed.errors,
          ...unresolved.map((u) => ({ ...u, column: 'row' as const, value: '' })),
        ],
        duplicateWarnings: parsed.duplicateWarnings,
        totalAmountCents: parsed.totalAmountCents,
        state: 'DRAFT' as BatchState,
      };
    }),
  );

  return c.json(result);
});

/** POST /api/payment-batches/:id/validate — run validation and risk screening (§6.1). */
batchRoutes.post('/:id/validate', requirePermissions('batch:validate'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'VALIDATE', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      if (batch.instruction_count === 0) {
        throw validationError('BATCH_EMPTY', 'This batch has no payment instructions to validate');
      }

      const policy = await loadPolicy(tx, actor.organizationId);
      if (batch.instruction_count > policy.maxBatchInstructions) {
        throw validationError(
          'BATCH_TOO_LARGE',
          `This batch has ${batch.instruction_count} instructions; organisation policy permits ${policy.maxBatchInstructions}`,
        );
      }

      const risk = await assessBatch(tx, batch, policy);
      await persistFindings(tx, batch, risk);

      await tx`
        UPDATE payment_batches
           SET state = 'VALIDATED', risk_score = ${risk.score}, risk_band = ${risk.band}
         WHERE id = ${batch.id}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.validated',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'VALIDATED' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          instructionCount: batch.instruction_count,
          totalAmountCents: Number(batch.total_amount_cents),
          riskScore: risk.score,
          riskBand: risk.band,
          findingCount: risk.signals.length,
        },
      });

      return { state: 'VALIDATED' as BatchState, risk };
    }),
  );

  return c.json(result);
});

/** POST /api/payment-batches/:id/submit — submit to Finance Control (L1). */
batchRoutes.post('/:id/submit', requirePermissions('batch:submit_to_l2'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'SUBMIT_TO_L2', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      // Cooling-off: an edit moments before submission is the "approve the clean version,
      // pay the dirty one" pattern (spec §20).
      const policy = await loadPolicy(tx, actor.organizationId);
      assertCoolingOff({
        lastMaterialEditAt: batch.last_material_edit_at
          ? new Date(batch.last_material_edit_at).getTime()
          : null,
        now: Date.now(),
        coolingOffSeconds: policy.coolingOffSeconds,
      });

      const submissionReference = reference('submission');
      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action
        ) VALUES (
          ${actor.organizationId}, ${submissionReference}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'SUBMIT'
        )
      `;
      await tx`
        UPDATE payment_batches
           SET state = 'SUBMITTED_TO_L2', submitted_by_user_id = ${actor.userId}, submitted_at = now()
         WHERE id = ${batch.id}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.submitted',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'SUBMITTED_TO_L2' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          // The version is frozen here: this is the exact content Finance Control reviews.
          batchVersion: batch.version,
          instructionCount: batch.instruction_count,
          totalAmountCents: Number(batch.total_amount_cents),
          submissionReference,
        },
      });

      return { state: 'SUBMITTED_TO_L2' as BatchState, batchVersion: batch.version };
    }),
  );

  return c.json(result);
});

const decisionSchema = z.object({
  reason: z.string().trim().max(1000).optional(),
  acknowledgeFindings: z.boolean().optional(),
});

/**
 * POST /api/payment-batches/:id/approve — L2 approval for executive authorization (§6.2).
 * This is where the two-person rule is enforced on the approval side.
 */
batchRoutes.post('/:id/approve', requirePermissions('batch:approve_to_l3'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = decisionSchema.parse(await c.req.json().catch(() => ({})));
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      // A batch may be approved directly from SUBMITTED_TO_L2 or after review is opened.
      if (batch.state === 'SUBMITTED_TO_L2') {
        assertTransition('SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', {
          actor: {
            level: actor.level,
            permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
          },
        });
      }
      const from: BatchState = batch.state === 'SUBMITTED_TO_L2' ? 'L2_REVIEW' : batch.state;
      assertTransition(from, 'APPROVE_TO_L3', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      // ---- Separation of duties ------------------------------------------
      const editors = await tx<{ user_id: string }[]>`
        SELECT user_id FROM batch_editors WHERE batch_id = ${batch.id}
      `;
      assertNotSelfApproval({
        actorUserId: actor.userId,
        actorLevel: actor.level,
        participants: {
          createdByUserId: batch.created_by_user_id,
          editedByUserIds: editors.map((e) => e.user_id),
          approvedByUserId: batch.approved_by_user_id,
          submittedByUserId: batch.submitted_by_user_id,
        },
      });

      // ---- Risk gate -------------------------------------------------------
      const openFindings = await tx<{ count: string; max_severity: string | null }[]>`
        SELECT COUNT(*) AS count, MAX(severity) AS max_severity
          FROM risk_findings
         WHERE batch_id = ${batch.id} AND batch_version = ${batch.version} AND disposition = 'OPEN'
      `;
      const open = Number(openFindings[0]?.count ?? 0);
      if (open > 0 && !body.acknowledgeFindings) {
        throw stateError(
          'RISK_FINDINGS_OPEN',
          `This batch has ${open} open risk finding(s). Review each one and confirm before approving.`,
          { openFindings: open },
        );
      }
      if (open > 0) {
        await tx`
          UPDATE risk_findings
             SET disposition = 'ACKNOWLEDGED', dispositioned_by_user_id = ${actor.userId},
                 dispositioned_at = now(), disposition_note = ${body.reason ?? 'Acknowledged at approval'}
           WHERE batch_id = ${batch.id} AND batch_version = ${batch.version} AND disposition = 'OPEN'
        `;
      }

      const approvalReference = reference('approval');
      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason, risk_acknowledged
        ) VALUES (
          ${actor.organizationId}, ${approvalReference}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'APPROVE', ${body.reason ?? null}, ${open > 0}
        )
      `;
      await tx`
        UPDATE payment_batches
           SET state = 'L3_READY', approved_by_user_id = ${actor.userId}, approved_at = now()
         WHERE id = ${batch.id}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.approved',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'L3_READY' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: {
          approvalReference,
          // Binding the approval to a version is what makes a later edit detectable.
          batchVersion: batch.version,
          findingsAcknowledged: open,
          reason: body.reason,
        },
      });

      return { state: 'L3_READY' as BatchState, approvalReference, batchVersion: batch.version };
    }),
  );

  return c.json(result);
});

/** POST /api/payment-batches/:id/reject — reject with preserved evidence. */
batchRoutes.post('/:id/reject', requirePermissions('batch:reject'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = decisionSchema.parse(await c.req.json().catch(() => ({})));
  const correlationId = c.get('correlationId');

  if (!body.reason) {
    throw validationError(
      'REJECTION_REASON_REQUIRED',
      'Give a reason so Payment Operations can correct the batch',
    );
  }
  // Narrowed here so the closures below see a plain string.
  const rejectionReason: string = body.reason;

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'REJECT', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason
        ) VALUES (
          ${actor.organizationId}, ${reference('rejection')}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'REJECT', ${rejectionReason}
        )
      `;
      await tx`
        UPDATE payment_batches SET state = 'REJECTED'
         WHERE id = ${batch.id}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.rejected',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'REJECTED' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason },
      });

      return { state: 'REJECTED' as BatchState };
    }),
  );

  return c.json(result);
});

/**
 * POST /api/payment-batches/:id/return — return to Level 1 for correction.
 * Preserves the batch and its evidence; the corrected content starts a new version.
 */
batchRoutes.post('/:id/return', requirePermissions('batch:reject'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = decisionSchema.parse(await c.req.json().catch(() => ({})));
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'RETURN_TO_L1', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason
        ) VALUES (
          ${actor.organizationId}, ${reference('hold')}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'RETURN', ${body.reason ?? null}
        )
      `;
      await tx`
        UPDATE payment_batches SET state = 'RETURNED_FOR_CORRECTION'
         WHERE id = ${batch.id}
      `;

      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.returned',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'RETURNED_FOR_CORRECTION' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason },
      });

      return { state: 'RETURNED_FOR_CORRECTION' as BatchState };
    }),
  );

  return c.json(result);
});

/** POST /api/payment-batches/:id/hold — place a batch on hold pending clarification. */
batchRoutes.post('/:id/hold', requirePermissions('batch:hold'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = decisionSchema.parse(await c.req.json().catch(() => ({})));
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'HOLD', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      await tx`UPDATE payment_batches SET state = 'ON_HOLD' WHERE id = ${batch.id}`;
      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason
        ) VALUES (
          ${actor.organizationId}, ${reference('hold')}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'HOLD', ${body.reason ?? null}
        )
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.held',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'ON_HOLD' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason },
      });
      return { state: 'ON_HOLD' as BatchState };
    }),
  );

  return c.json(result);
});

/**
 * POST /api/payment-batches/:id/release-hold — lift a hold and return the batch to the
 * review queue. Without this route a held batch is stranded forever.
 */
batchRoutes.post('/:id/release-hold', requirePermissions('batch:release_hold'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = decisionSchema.parse(await c.req.json().catch(() => ({})));
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'RELEASE_HOLD', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason
        ) VALUES (
          ${actor.organizationId}, ${reference('hold')}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'RELEASE_HOLD', ${body.reason ?? null}
        )
      `;
      await tx`
        UPDATE payment_batches SET state = 'L2_REVIEW' WHERE id = ${batch.id}
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.hold_released',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'L2_REVIEW' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason },
      });
      return { state: 'L2_REVIEW' as BatchState };
    }),
  );

  return c.json(result);
});

/** POST /api/payment-batches/:id/cancel — abandon an eligible unreleased batch. */
batchRoutes.post('/:id/cancel', requirePermissions('batch:cancel'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const body = z
    .object({ reason: z.string().trim().min(3).max(500) })
    .parse(await c.req.json());
  const correlationId = c.get('correlationId');

  const result = await withConnection(c.env, (sql) =>
    inTransaction(sql, async (tx) => {
      await requireLock(tx, 'batch', batchId);
      const batch = await loadBatch(tx, actor.organizationId, batchId);

      assertTransition(batch.state, 'CANCEL', {
        actor: {
          level: actor.level,
          permissions: effectivePermissionsOf(actor, c.get('permissionMatrix')),
        },
      });

      await tx`
        UPDATE payment_batches
           SET state = 'CANCELLED', cancelled_at = now(), cancel_reason = ${body.reason}
         WHERE id = ${batch.id}
      `;
      await tx`
        INSERT INTO approvals (
          organization_id, approval_reference, batch_id, batch_version, actor_user_id,
          actor_level, action, reason
        ) VALUES (
          ${actor.organizationId}, ${reference('hold')}, ${batch.id}, ${batch.version},
          ${actor.userId}, ${actor.level}, 'CANCEL', ${body.reason}
        )
      `;
      await writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'PAYMENT',
        action: 'batch.cancelled',
        objectType: 'PaymentBatch',
        objectId: batch.id,
        outcome: 'SUCCESS',
        previousState: { state: batch.state },
        newState: { state: 'CANCELLED' },
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { reason: body.reason },
      });
      return { state: 'CANCELLED' as BatchState };
    }),
  );

  return c.json(result);
});

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/** GET /api/payment-batches — list batches with their outcome roll-ups. */
batchRoutes.get('/', requirePermissions('batch:read'), async (c) => {
  const actor = actorOf(c);
  const url = new URL(c.req.url);
  const state = url.searchParams.get('state');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '50'), 200);
  const offset = Math.max(Number(url.searchParams.get('offset') ?? '0'), 0);

  const data = await withConnection(c.env, async (sql) => {
    const rows = await sql<
      {
        batch_id: string;
        batch_reference: string;
        state: string;
        purpose: string;
        instruction_count: number;
        total_amount_cents: string;
        created_at: string;
        success_count: string;
        failed_count: string;
        timeout_count: string;
        in_flight_count: string;
      }[]
    >`
      SELECT r.batch_id, r.batch_reference, r.state, b.purpose, r.instruction_count,
             r.total_amount_cents, b.created_at, r.success_count, r.failed_count,
             r.timeout_count, r.in_flight_count
        FROM batch_outcome_rollup r
        JOIN payment_batches b ON b.id = r.batch_id
       WHERE r.organization_id = ${actor.organizationId}
         AND (${state ?? null}::text IS NULL OR r.state = ${state ?? null}::text)
       ORDER BY b.created_at DESC
       LIMIT ${limit} OFFSET ${offset}
    `;

    return {
      batches: rows.map((r) => ({
        batchId: r.batch_id,
        batchReference: r.batch_reference,
        state: r.state,
        purpose: r.purpose,
        createdAt: r.created_at,
        instructionCount: r.instruction_count,
        totalAmountCents: Number(r.total_amount_cents),
        outcomes: {
          success: Number(r.success_count),
          failed: Number(r.failed_count),
          timeout: Number(r.timeout_count),
          inFlight: Number(r.in_flight_count),
        },
      })),
    };
  });

  return c.json(data);
});

/** GET /api/payment-batches/:id — full batch detail: instructions, approvals, findings. */
batchRoutes.get('/:id', requirePermissions('batch:read'), async (c) => {
  const actor = actorOf(c);
  const batchId = c.req.param('id');
  const data = await withConnection(c.env, async (sql) => {
    const batches = await sql<
      {
        id: string;
        batch_reference: string;
        purpose: string;
        state: BatchState;
        version: number;
        instruction_count: number;
        total_amount_cents: string;
        created_at: string;
        created_by_name: string;
        submitted_at: string | null;
        approved_at: string | null;
        authorized_at: string | null;
        risk_score: number | null;
        risk_band: string | null;
      }[]
    >`
      SELECT b.id, b.batch_reference, b.purpose, b.state, b.version, b.instruction_count,
             b.total_amount_cents, b.created_at,
             COALESCE(u.full_name, 'unknown') AS created_by_name,
             b.submitted_at, b.approved_at, b.authorized_at, b.risk_score, b.risk_band
        FROM payment_batches b
        LEFT JOIN users u ON u.id = b.created_by_user_id
       WHERE b.id = ${batchId} AND b.organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const batch = batches[0];
    if (!batch) throw notFoundError('BATCH_NOT_FOUND', 'That payment batch could not be found');

    // Paginated instructions: large payrolls stay fully inspectable.
    const url = new URL(c.req.url);
    const offset = Math.max(Number(url.searchParams.get('instructionOffset') ?? '0'), 0);
    const limit = Math.min(Number(url.searchParams.get('instructionLimit') ?? '500'), 1000);

    const instructions = await sql<
      {
        id: string;
        recipient_name_snapshot: string;
        msisdn_snapshot: string;
        amount_cents: string;
        status: string;
        source_line_number: number | null;
      }[]
    >`
      SELECT id, recipient_name_snapshot, msisdn_snapshot, amount_cents, status, source_line_number
        FROM payment_instructions
       WHERE batch_id = ${batchId}
       ORDER BY source_line_number NULLS LAST, id
       LIMIT ${limit} OFFSET ${offset}
    `;

    const totalInstructions = await sql<{ count: string }[]>`
      SELECT COUNT(*) AS count FROM payment_instructions WHERE batch_id = ${batchId}
    `;

    const approvals = await sql<
      {
        approval_reference: string;
        action: string;
        actor_level: string;
        actor_name: string;
        reason: string | null;
        batch_version: number;
        created_at: string;
      }[]
    >`
      SELECT a.approval_reference, a.action, a.actor_level,
             COALESCE(u.full_name, a.actor_user_id::text) AS actor_name,
             a.reason, a.batch_version, a.created_at
        FROM approvals a
        LEFT JOIN users u ON u.id = a.actor_user_id
       WHERE a.batch_id = ${batchId} ORDER BY a.created_at ASC
    `;

    const findings = await sql<
      {
        signal_type: string;
        severity: string;
        summary: string;
        evidence: unknown;
        disposition: string;
        batch_version: number;
      }[]
    >`
      SELECT signal_type, severity, summary, evidence, disposition, batch_version
        FROM risk_findings WHERE batch_id = ${batchId}
       ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                              WHEN 'LOW' THEN 3 ELSE 4 END
    `;

    return {
      batch: {
        batchId: batch.id,
        batchReference: batch.batch_reference,
        purpose: batch.purpose,
        state: batch.state,
        version: batch.version,
        instructionCount: batch.instruction_count,
        totalAmountCents: Number(batch.total_amount_cents),
        createdAt: batch.created_at,
        createdBy: batch.created_by_name,
        submittedAt: batch.submitted_at,
        approvedAt: batch.approved_at,
        authorizedAt: batch.authorized_at,
        riskScore: batch.risk_score,
        riskBand: batch.risk_band,
        editable: isEditable(batch.state),
        availableCommands: allowedCommands(batch.state),
      },
      instructions: {
        rows: instructions.map((i) => ({
          instructionId: i.id,
          recipientName: i.recipient_name_snapshot,
          msisdn: i.msisdn_snapshot,
          amountCents: Number(i.amount_cents),
          status: i.status,
          sourceLineNumber: i.source_line_number,
        })),
        offset,
        limit,
        total: Number(totalInstructions[0]?.count ?? 0),
      },
      approvals,
      // Findings from superseded versions are shown but marked, so a reviewer can see
      // that an earlier version raised a concern an edit has since changed.
      riskFindings: findings.map((f) => ({
        ...f,
        currentVersion: f.batch_version === batch.version,
      })),
    };
  });

  return c.json(data);
});

