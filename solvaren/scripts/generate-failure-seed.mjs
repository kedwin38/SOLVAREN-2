#!/usr/bin/env node
/**
 * Generate db/migrations/0005_seed_failure_reasons.sql from the compiled failure
 * dictionary in @solvaren/core. CI re-runs this script and fails if the committed
 * migration differs, so the database seed and the code fallback can never drift.
 *
 * Uses Node's native TypeScript type-stripping (Node >= 22.6 with --experimental-strip-types,
 * stable from Node 23+); no build step required.
 */

import { writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const { listFailureReasons, FAILURE_DICTIONARY_VERSION } = await import(
  pathToFileURL(join(root, 'packages/core/src/failure-reasons.ts')).href
);

const reasons = listFailureReasons();

const q = (s) => `'${String(s).replace(/'/g, "''")}'`;

const lines = [
  '-- SOLVAREN migration 0005 — Failure-reason dictionary seed.',
  '--',
  '-- GENERATED FILE — do not edit by hand. Regenerate with `pnpm db:generate-seed`.',
  `-- Dictionary version: ${FAILURE_DICTIONARY_VERSION}`,
  '',
  'INSERT INTO failure_reason_map (provider_code, organization_id, reason, failure_class, operator_action, transient)',
  'VALUES',
  reasons
    .map(
      (r) =>
        `  (${q(r.code)}, NULL, ${q(r.reason)}, ${q(r.class)}, ${q(r.operatorAction)}, ${r.transient})`,
    )
    .join(',\n'),
  'ON CONFLICT (organization_id, provider_code) DO UPDATE SET',
  '  reason = EXCLUDED.reason,',
  '  failure_class = EXCLUDED.failure_class,',
  '  operator_action = EXCLUDED.operator_action,',
  '  transient = EXCLUDED.transient;',
  '',
];

const target = join(root, 'db/migrations/0005_seed_failure_reasons.sql');
const next = lines.join('\n');
if (!existsSync(target) || readIfPresent(target) !== next) {
  writeFileSync(target, next);
  console.log(`Wrote ${target} (${reasons.length} codes, version ${FAILURE_DICTIONARY_VERSION})`);
} else {
  console.log(`Seed already current (${reasons.length} codes, version ${FAILURE_DICTIONARY_VERSION})`);
}

function readIfPresent(path) {
  try {
    return require('node:fs').readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}
