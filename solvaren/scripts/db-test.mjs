#!/usr/bin/env node
/**
 * Cross-platform database security assertions: migrate (if needed) and attack the
 * schema directly (spec §24). Requires a PostgreSQL with the migrations applied.
 *
 * Usage: node scripts/db-test.mjs [connectionString]
 *   or:  DATABASE_URL=… node scripts/db-test.mjs
 */

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import postgres from 'postgres';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const connectionString = process.argv[2] ?? process.env.DATABASE_URL;
if (!connectionString) {
  console.error('Provide a connection string argument or DATABASE_URL.');
  process.exit(1);
}

const sql = postgres(connectionString, { max: 1 });

async function main() {
  console.log('SOLVAREN database security assertions');
  console.log('====================================');
  console.log('');

  // Run the assertion script; capture RAISE NOTICE (✓) and ERROR (✗) lines.
  const script = await readFile(join(root, 'db/tests/immutability.sql'), 'utf8');

  const notices = [];
  const errors = [];
  await sql.unsafe(script).catch((err) => {
    // Each DO block raises on failure; collect them.
    errors.push(err.message);
  });

  // psql-style notices are not surfaced by the driver; re-derive the summary by listing
  // which assertion DO blocks threw. Simpler and more robust: run each block.
  // The SQL file is written to be idempotent; the driver stops at the first ERROR, so
  // instead run it with a session that collects errors and continues.
  const blocks = script
    .split(/(?=DO \$\$)/)
    .map((b) => b.trim())
    .filter((b) => b.startsWith('DO $$'));

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i]!.replace(/RAISE EXCEPTION 'ASSERTION (\d+[a-z]?) FAILED: ([^']*)';/, `RAISE EXCEPTION 'ASSERTION FAILED: $2';`);
    try {
      await sql.unsafe(block);
    } catch (err) {
      errors.push(`Block ${i + 1}: ${err.message}`);
    }
  }

  // Seed/cleanup blocks (non-DO) run as one.
  const nonDo = script.split(/(?=DO \$\$)/).filter((b) => !b.trim().startsWith('DO $$')).join('\n');
  await sql.unsafe(nonDo).catch(() => {});

  const assertions = (script.match(/ASSERTION \d+[a-z]?/g) ?? []).length;
  console.log(`Assertion blocks executed: ${blocks.length} (covering ${assertions} named assertions).`);

  if (errors.length > 0) {
    console.log('');
    console.log('✗ FAILURES:');
    for (const e of errors) console.log(`  - ${e}`);
    await sql.end();
    process.exit(1);
  }

  console.log('');
  console.log('✓ All database assertions passed (no block raised).');
  await sql.end();
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
