#!/usr/bin/env node
/**
 * Migration runner: applies db/migrations/*.sql in filename order, exactly once each,
 * inside a transaction with an advisory lock so two replicas cannot race.
 *
 * Each migration records its checksum; a modified, already-applied migration fails the
 * run loudly rather than silently drifting the schema.
 */

import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { createRequire } from 'node:module';

// 'postgres' is a dependency of apps/api. In the deployed image this script runs from
// /app/scripts, where pnpm's isolated layout does not hoist it to a resolvable level,
// so resolve it through the api package's manifest — which exists in both the checkout
// and the image (apps/api/node_modules/postgres).
const requireFromApi = createRequire(new URL('../apps/api/package.json', import.meta.url));
const postgres = requireFromApi('postgres');

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const migrationsDir = join(root, 'db', 'migrations');

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 1 });

async function main() {
  const files = (await readdir(migrationsDir)).filter((f) => f.endsWith('.sql')).sort();

  await sql`CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`;

  const applied = new Map(
    (await sql`SELECT name, checksum FROM schema_migrations`).map((r) => [r.name, r.checksum]),
  );

  let ran = 0;
  for (const file of files) {
    if (applied.has(file)) {
      const current = await sha256(await readFile(join(migrationsDir, file), 'utf8'));
      if (current !== applied.get(file)) {
        console.error(`  ✗ ${file} was already applied but has been modified since.`);
        console.error('    Applied migrations are immutable; write a new migration instead.');
        process.exit(1);
      }
      continue;
    }

    const body = await readFile(join(migrationsDir, file), 'utf8');
    const checksum = await sha256(body);
    console.log(`  → ${file}`);
    await sql.begin(async (tx) => {
      await tx`SELECT pg_advisory_xact_lock(hashtext('solvaren:migrations'))`;
      await tx.unsafe(body);
      await tx`INSERT INTO schema_migrations (name, checksum) VALUES (${file}, ${checksum})`;
    });
    ran += 1;
  }

  console.log(ran === 0 ? 'Schema already up to date.' : `Applied ${ran} migration(s).`);
  await sql.end();
}

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
