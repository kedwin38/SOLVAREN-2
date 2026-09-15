/**
 * Reports (spec §12): the catalogue for the UI picker, async generation via the report
 * worker, and download of completed jobs (inline or staged).
 */

import { Hono } from 'hono';
import { z } from 'zod';
import {
  REPORT_CATALOG,
  reportDefinition,
  reportRequestSchema,
  notFoundError,
  validationError,
} from '@solvaren/core';
import { requireAuth, requirePermissions, actorOf } from '../middleware/security.js';
import { withConnection, inTransaction } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { AppContext, ReportQueueMessage } from '../env.js';

export const reportRoutes = new Hono<AppContext>();
reportRoutes.use('*', requireAuth);

/** GET /api/reports/catalogue — what can be generated, and who may generate it. */
reportRoutes.get('/catalogue', async (c) => {
  const actor = actorOf(c);
  const matrix = c.get('permissionMatrix');
  return c.json({
    reports: REPORT_CATALOG.map((r) => ({
      family: r.family,
      title: r.title,
      description: r.description,
      requiredPermission: r.requiredPermission,
      available: matrix[actor.level].has(r.requiredPermission),
      supportsDateRange: r.supportsDateRange,
      supportsDepartmentFilter: r.supportsDepartmentFilter,
      columns: r.columns,
    })),
  });
});

/** POST /api/reports — queue a report generation job. */
reportRoutes.post('/', async (c) => {
  const actor = actorOf(c);
  const body = reportRequestSchema.parse(await c.req.json());
  const definition = reportDefinition(body.family);
  const correlationId = c.get('correlationId');

  // The report's required permission is enforced against the live matrix here.
  const matrix = c.get('permissionMatrix');
  if (!matrix[actor.level].has(definition.requiredPermission)) {
    throw validationError(
      'REPORT_NOT_PERMITTED',
      `Your authority level may not generate ${definition.title}`,
      { requiredPermission: definition.requiredPermission },
    );
  }

  const created = await withConnection(c.env, async (sql) => {
    const rows = await sql<{ id: string }[]>`
      INSERT INTO report_jobs (organization_id, family, requested_by_user_id, filters, status, correlation_id)
      VALUES (
        ${actor.organizationId}, ${body.family}, ${actor.userId},
        ${sql.json({ dateFrom: body.dateFrom ?? null, dateTo: body.dateTo ?? null, departmentId: body.departmentId ?? null } as never)},
        'QUEUED', ${correlationId}
      )
      RETURNING id
    `;
    const jobId = rows[0]!.id;

    const message: ReportQueueMessage = {
      type: 'GENERATE_REPORT',
      reportJobId: jobId,
      organizationId: actor.organizationId,
      requestedByUserId: actor.userId,
      correlationId,
    };
    await c.env.queue.send({ queue: 'reports', body: message });

    await inTransaction(sql, (tx) =>
      writeAuditEvent(tx, {
        organizationId: actor.organizationId,
        actorId: actor.userId,
        actorLevel: actor.level,
        eventClass: 'DATA_EXPORT',
        action: 'report.requested',
        objectType: 'ReportJob',
        objectId: jobId,
        outcome: 'SUCCESS',
        correlationId,
        securityContext: c.get('securityContext'),
        detail: { family: body.family, filters: { dateFrom: body.dateFrom, dateTo: body.dateTo } },
      }),
    );

    return jobId;
  });

  return c.json(
    {
      reportJobId: created,
      message: 'The report is being generated. It will appear in your report history when complete.',
    },
    202,
  );
});

/** GET /api/reports/history — the requester's recent report jobs. */
reportRoutes.get('/history', async (c) => {
  const actor = actorOf(c);
  const jobs = await withConnection(c.env, (sql) =>
    sql<
      {
        id: string;
        family: string;
        status: string;
        row_count: number | null;
        error_message: string | null;
        requested_at: string;
        completed_at: string | null;
        staged: boolean;
      }[]
    >`
      SELECT id, family, status, row_count, error_message, requested_at, completed_at,
             (object_key IS NOT NULL) AS staged
        FROM report_jobs
       WHERE organization_id = ${actor.organizationId}
       ORDER BY requested_at DESC
       LIMIT 50
    `,
  );
  return c.json({
    jobs: jobs.map((j) => ({
      reportJobId: j.id,
      family: j.family,
      status: j.status,
      rowCount: j.row_count,
      errorMessage: j.error_message,
      requestedAt: j.requested_at,
      completedAt: j.completed_at,
      staged: j.staged,
    })),
  });
});

/** GET /api/reports/:id/download — the completed CSV (inline or staged). */
reportRoutes.get('/:id/download', async (c) => {
  const actor = actorOf(c);
  const jobId = c.req.param('id');
  const uuid = z.string().uuid();
  if (!uuid.safeParse(jobId).success) {
    throw notFoundError('REPORT_NOT_FOUND', 'That report could not be found');
  }

  const result = await withConnection(c.env, async (sql) => {
    const jobs = await sql<
      { id: string; family: string; status: string; csv_inline: string | null; object_key: string | null }[]
    >`
      SELECT id, family, status, csv_inline, object_key
        FROM report_jobs
       WHERE id = ${jobId} AND organization_id = ${actor.organizationId}
       LIMIT 1
    `;
    const job = jobs[0];
    if (!job) throw notFoundError('REPORT_NOT_FOUND', 'That report could not be found');
    if (job.status !== 'COMPLETED') {
      throw validationError('REPORT_NOT_READY', `This report is ${job.status}`);
    }

    if (job.csv_inline) {
      return { csv: job.csv_inline, filename: `${job.family}-report.csv` };
    }
    if (job.object_key) {
      const csv = await c.env.objects.get(job.object_key);
      if (!csv) throw notFoundError('REPORT_OBJECT_MISSING', 'The staged report object is no longer available');
      return { csv, filename: `${job.family}-report.csv` };
    }
    throw notFoundError('REPORT_NOT_FOUND', 'That report has no downloadable artefact');
  });

  return new Response(result.csv, {
    status: 200,
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${result.filename}"`,
      'Cache-Control': 'no-store',
    },
  });
});
