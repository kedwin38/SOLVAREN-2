#!/usr/bin/env node
/**
 * Clear test recipients ahead of re-testing with the new CSV format (role/team/
 * territory/region/sales, phone number/ID number/names/payout).
 *
 * Deliberately conservative: it only deletes recipients that have never appeared in a
 * payment_instructions row (and never sat in a batch template) — i.e. recipients that
 * never touched a real financial record. A recipient with instruction history is left
 * alone and reported as "skipped (in use)"; payment_instructions has no ON DELETE
 * CASCADE from recipients on purpose (see db/migrations/0002_payments.sql), so this
 * script never has to choose whether to destroy financial history.
 *
 * Usage:
 *   DATABASE_URL=postgres://... node scripts/clear-test-recipients.mjs --org acme
 *   DATABASE_URL=postgres://... node scripts/clear-test-recipients.mjs --org acme --apply
 *
 * Without --apply this is a dry run: it prints what would be deleted and exits without
 * touching the database.
 */

import { createRequire } from 'node:module';

// 'postgres' is a dependency of apps/api; resolve it the same way scripts/migrate.mjs
// does so this script works from both the checkout and the deployed image.
const requireFromApi = createRequire(new URL('../apps/api/package.json', import.meta.url));
const postgres = requireFromApi('postgres');

const args = process.argv.slice(2);
const orgIndex = args.indexOf('--org');
const orgSlug = orgIndex >= 0 ? args[orgIndex + 1] : null;
const apply = args.includes('--apply');

if (!orgSlug) {
  console.error('Usage: node scripts/clear-test-recipients.mjs --org <slug> [--apply]');
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 1 });

try {
  const orgs = await sql`SELECT id, slug FROM organizations WHERE slug = ${orgSlug}`;
  const org = orgs[0];
  if (!org) {
    console.error(`No organization with slug "${orgSlug}"`);
    process.exit(1);
  }

  const candidates = await sql`
    SELECT r.id, r.full_name, r.msisdn
      FROM recipients r
     WHERE r.organization_id = ${org.id}
       AND NOT EXISTS (SELECT 1 FROM payment_instructions pi WHERE pi.recipient_id = r.id)
       AND NOT EXISTS (SELECT 1 FROM batch_template_items bti WHERE bti.recipient_id = r.id)
     ORDER BY r.created_at
  `;

  const inUseCount = await sql`
    SELECT COUNT(*)::int AS count
      FROM recipients r
     WHERE r.organization_id = ${org.id}
       AND (EXISTS (SELECT 1 FROM payment_instructions pi WHERE pi.recipient_id = r.id)
            OR EXISTS (SELECT 1 FROM batch_template_items bti WHERE bti.recipient_id = r.id))
  `;

  console.log(`Organization: ${org.slug}`);
  console.log(`Recipients with no payment/template history (deletable): ${candidates.length}`);
  console.log(`Recipients already in use (never touched by this script): ${inUseCount[0].count}`);

  if (candidates.length === 0) {
    console.log('Nothing to delete.');
    process.exit(0);
  }

  if (!apply) {
    console.log('\nDry run — pass --apply to actually delete. Sample of what would be removed:');
    for (const r of candidates.slice(0, 20)) {
      console.log(`  ${r.full_name}  ${r.msisdn}`);
    }
    if (candidates.length > 20) console.log(`  … and ${candidates.length - 20} more`);
    process.exit(0);
  }

  const ids = candidates.map((r) => r.id);
  const deleted = await sql`DELETE FROM recipients WHERE id = ANY(${ids}) RETURNING id`;
  console.log(`Deleted ${deleted.length} test recipient(s) from "${org.slug}".`);
} finally {
  await sql.end();
}
