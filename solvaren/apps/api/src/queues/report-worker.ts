/**
 * Report generation worker (spec §12): executes ReportJob rows asynchronously so a
 * browser request never holds a large aggregation open.
 *
 * Small reports are stored inline (`csv_inline`) for immediate download; reports beyond
 * the inline threshold are staged to the backup bucket as objects. Every completed job
 * records its row count, and every export leaves an `export_records` audit row with
 * actor, filter and size.
 */

import { renderCsv, provenanceComment, exportFilename, reference, type ReportFamily } from '@solvaren/core';
import { buildReportRows } from '../services/report-builder.js';
import { withConnection, inTransaction, type Sql } from '../db/client.js';
import { writeAuditEvent } from '../db/audit-writer.js';
import type { ReportQueueMessage, Env, QueueBatch } from '../env.js';

/** Reports up to this size are returned inline; larger ones stage to object storage. */
const INLINE_LIMIT_BYTES = 2 * 1024 * 1024;

export async function handleReportBatch(
  batch: QueueBatch<ReportQueueMessage>,
  env: Env,
): Promise<void> {
  await withConnection(env, async (sql) => {
    for (const message of batch.messages) {
      try {
        await generateReport(sql, env, message.body);
        message.ack();
      } catch (err) {
        console.error(
          JSON.stringify({
            level: 'error',
            message: 'Report generation failed',
            reportJobId: message.body.reportJobId,
            error: err instanceof Error ? err.message : String(err),
          }),
        );
        await inTransaction(sql, async (tx) => {
          await tx`
            UPDATE report_jobs
               SET status = 'FAILED', error_message = ${err instanceof Error ? err.message : String(err)},
                   completed_at = now()
             WHERE id = ${message.body.reportJobId}
          `;
          await writeAuditEvent(tx, {
            organizationId: message.body.organizationId,
            actorId: message.body.requestedByUserId,
            actorLevel: null,
            eventClass: 'DATA_EXPORT',
            action: 'report.failed',
            objectType: 'ReportJob',
            objectId: message.body.reportJobId,
            outcome: 'FAILURE',
            correlationId: message.body.correlationId,
            detail: { error: err instanceof Error ? err.message : String(err) },
          });
        });
        message.ack(); // the job row carries the failure; nothing useful in a retry
      }
    }
  });
}

async function generateReport(sql: Sql, env: Env, message: ReportQueueMessage): Promise<void> {
  const jobs = await sql<
    { id: string; family: ReportFamily; filters: Record<string, unknown>; organization_id: string }[]
  >`
    SELECT id, family, filters, organization_id
      FROM report_jobs
     WHERE id = ${message.reportJobId} AND status = 'QUEUED'
     LIMIT 1
  `;
  const job = jobs[0];
  if (!job) return;

  await sql`UPDATE report_jobs SET status = 'RUNNING' WHERE id = ${job.id}`;

  const built = await buildReportRows(sql, job.organization_id, job.family, job.filters);

  const exportReference = reference('export');
  const generatedAt = new Date().toISOString();
  const provenance = provenanceComment({
    exportId: exportReference,
    organizationId: job.organization_id,
    generatedAt,
    generatedByUserId: message.requestedByUserId,
    generatedByLevel: 'report',
    filterDescription: built.filterDescription,
    rowCount: built.rows.length,
  });
  const csv = `${provenance}\r\n${renderCsv(built.columns, built.rows)}`;
  const organization = await sql<{ slug: string }[]>`
    SELECT slug FROM organizations WHERE id = ${job.organization_id}
  `;
  const filename = exportFilename(`${job.family}-report`, organization[0]?.slug ?? 'org', generatedAt);

  let objectKey: string | null = null;
  let csvInline: string | null = null;
  if (csv.length <= INLINE_LIMIT_BYTES) {
    csvInline = csv;
  } else {
    objectKey = `reports/${job.organization_id}/${job.id}/${filename}`;
    await env.objects.put(objectKey, csv, { contentType: 'text/csv; charset=utf-8' });
  }

  await inTransaction(sql, async (tx) => {
    await tx`
      UPDATE report_jobs
         SET status = 'COMPLETED', row_count = ${built.rows.length}, object_key = ${objectKey},
             csv_inline = ${csvInline}, completed_at = now()
       WHERE id = ${job.id}
    `;
    await tx`
      INSERT INTO export_records (
        organization_id, export_reference, export_type, report_family,
        requested_by_user_id, requested_by_level, filter_description, filter_json,
        row_count, byte_size, status, completed_at, correlation_id
      ) VALUES (
        ${job.organization_id}, ${exportReference}, 'REPORT', ${job.family},
        ${message.requestedByUserId}, 'L2', ${built.filterDescription}, ${tx.json(job.filters as never)},
        ${built.rows.length}, ${csv.length}, 'COMPLETED', now(), ${message.correlationId}
      )
    `;
    await writeAuditEvent(tx, {
      organizationId: job.organization_id,
      actorId: message.requestedByUserId,
      actorLevel: null,
      eventClass: 'DATA_EXPORT',
      action: 'report.generated',
      objectType: 'ReportJob',
      objectId: job.id,
      outcome: 'SUCCESS',
      correlationId: message.correlationId,
      detail: {
        family: job.family,
        exportReference,
        rowCount: built.rows.length,
        byteSize: csv.length,
        stagedToObject: objectKey !== null,
      },
    });
  });
}
