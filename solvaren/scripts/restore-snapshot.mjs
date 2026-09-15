#!/usr/bin/env node
/**
 * Restore a logical snapshot into a scratch database (the disaster-recovery drill,
 * spec §13.7 / runbook). Verifies row counts, the audit chain, batch totals and settled
 * evidence, and prints the measured timings.
 *
 * Usage:
 *   DATABASE_URL=<scratch> S3_*=<bucket> SECRET_ENCRYPTION_KEY=<key> \
 *     node scripts/restore-snapshot.mjs --attempt-reference BAK-…
 */

import { parseArgs } from 'node:util';
import postgres from 'postgres';

const { values } = parseArgs({
  options: {
    'attempt-reference': { type: 'string' },
    'object-key': { type: 'string' },
  },
});

if (!values['attempt-reference'] && !values['object-key']) {
  console.error('Provide --attempt-reference <BAK-…> or --object-key <prefix/…/file.json>.');
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL must point at the SCRATCH database (migrations applied).');
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 1 });
const started = Date.now();

async function main() {
  // Import the storage client through the workspace source (Node type-stripping).
  const { S3ObjectStore } = await import(new URL('../packages/storage/src/s3.ts', import.meta.url).href);
  const objects = new S3ObjectStore({
    endpoint: process.env.S3_ENDPOINT,
    region: process.env.S3_REGION ?? 'auto',
    bucket: process.env.S3_BUCKET,
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
    forcePathStyle: (process.env.S3_FORCE_PATH_STYLE ?? 'true') === 'true',
  });

  let objectKey = values['object-key'];
  if (!objectKey) {
    const rows = await sql`SELECT object_key FROM backup_attempts WHERE attempt_reference = ${values['attempt-reference']} LIMIT 1`;
    if (!rows[0]?.object_key) {
      console.error(`No backup object found for attempt ${values['attempt-reference']}.`);
      process.exit(1);
    }
    objectKey = rows[0].object_key;
  }

  console.log(`Fetching ${objectKey}…`);
  const body = await objects.get(objectKey);
  if (!body) {
    console.error('The object could not be retrieved.');
    process.exit(1);
  }

  const snapshot = JSON.parse(body);
  const meta = snapshot.metadata;
  console.log(`Snapshot of ${meta.organizationId} taken ${meta.takenAt} (${meta.totalRows} rows, ${meta.tables.length} tables).`);

  // ---- Restore, in the snapshot's dependency order ------------------------------
  await sql.begin(async (tx) => {
    // Identity tables need credential columns re-seeded: the snapshot deliberately
    // excludes password/PIN/recovery hashes. Set placeholder values and force
    // PENDING_ENROLMENT — restored users must re-establish credentials.
    for (const table of meta.tables) {
      const rows = snapshot.data[table.name] ?? [];
      if (rows.length === 0) continue;
      for (const row of rows) {
        const cols = Object.keys(row);
        const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
        const updates = cols.filter((c) => c !== 'id').map((c, i) => `${quote(c)} = EXCLUDED.${quote(c)}`).join(', ');
        await tx.unsafe(
          `INSERT INTO ${table.name} (${cols.map(quote).join(', ')}) VALUES (${placeholders})
           ON CONFLICT (id) DO UPDATE SET ${updates}`,
          cols.map((c) => {
            const v = row[c];
            // Restore JSON-ish columns as JSON strings; postgres casts.
            return typeof v === 'object' && v !== null ? JSON.stringify(v) : v;
          }),
        );
      }
      console.log(`  ${table.name}: ${rows.length} rows`);
    }

    // Credential hashes were excluded: accounts must re-enrol.
    await tx`UPDATE users SET password_hash = '<restore:re-enrol>', authorization_pin_hash = NULL,
      status = 'PENDING_ENROLMENT' WHERE password_hash IS NULL OR password_hash = ''`;
    await tx`UPDATE sessions SET revoked_at = now(), revocation_reason = 'Restored snapshot'`;
  });

  // ---- Verify -------------------------------------------------------------------
  let failures = 0;

  // Row counts.
  for (const table of meta.tables) {
    const actual = await sql`SELECT COUNT(*)::int AS n FROM ${sql(table.name)}`;
    if (actual[0].n < table.rows) {
      console.error(`  ✗ ${table.name}: expected ≥${table.rows}, found ${actual[0].n}`);
      failures++;
    }
  }
  if (failures === 0) console.log('  ✓ Row counts match snapshot metadata');

  // Audit chain.
  const { verifyChainAsync, GENESIS_HASH } = await import(new URL('../packages/core/src/audit.ts', import.meta.url).href);
  const events = await sql`SELECT * FROM audit_events WHERE organization_id = ${meta.organizationId} ORDER BY sequence ASC LIMIT 5000`;
  const verification = await verifyChainAsync(events.map(adaptEvent), GENESIS_HASH);
  if (verification.valid) console.log(`  ✓ Audit chain verifies (${verification.verifiedCount} events)`);
  else {
    console.error(`  ✗ Audit chain break at sequence ${verification.failedAtSequence}: ${verification.reason}`);
    failures++;
  }

  // Batch totals.
  const badBatches = await sql`
    SELECT b.batch_reference FROM payment_batches b
    WHERE b.organization_id = ${meta.organizationId}
      AND b.total_amount_cents <> (SELECT COALESCE(SUM(amount_cents),0) FROM payment_instructions WHERE batch_id = b.id)
    LIMIT 5`;
  if (badBatches.length === 0) console.log('  ✓ Batch totals reconcile with instructions');
  else {
    console.error(`  ✗ Batch totals mismatch: ${badBatches.map((r) => r.batch_reference).join(', ')}`);
    failures++;
  }

  // Settled evidence.
  const badSuccess = await sql`SELECT COUNT(*)::int AS n FROM transactions WHERE status = 'SUCCESS' AND (mpesa_receipt_number IS NULL OR btrim(mpesa_receipt_number) = '')`;
  if (badSuccess[0].n === 0) console.log('  ✓ Every restored SUCCESS carries a receipt');
  else {
    console.error(`  ✗ ${badSuccess[0].n} SUCCESS rows lost their receipts`);
    failures++;
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(1);
  console.log('');
  if (failures > 0) {
    console.error(`Restore FAILED verification after ${elapsed}s. Preserve the scratch database for analysis.`);
    process.exit(1);
  }
  console.log(`Restore verified in ${elapsed}s (restore-only RTO component).`);
  console.log('Restored accounts are PENDING_ENROLMENT: users must set passwords and enrol security keys.');
  await sql.end();
}

function quote(identifier) {
  if (!/^[a-z_][a-z0-9_]*$/.test(identifier)) throw new Error(`Unsafe identifier: ${identifier}`);
  return `"${identifier}"`;
}

function adaptEvent(r) {
  return {
    eventId: r.id, organizationId: r.organization_id, actorId: r.actor_id, actorLevel: r.actor_level,
    eventClass: r.event_class, action: r.action, objectType: r.object_type, objectId: r.object_id,
    outcome: r.outcome, occurredAt: new Date(r.occurred_at).toISOString(),
    previousState: r.previous_state, newState: r.new_state, securityContext: r.security_context,
    detail: r.detail, correlationId: r.correlation_id, previousHash: r.previous_hash,
    eventHash: r.event_hash, sequence: Number(r.sequence),
  };
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
