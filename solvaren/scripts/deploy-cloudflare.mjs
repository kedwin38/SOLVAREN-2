#!/usr/bin/env node
/**
 * Deploy the SOLVAREN console to Cloudflare Pages via Direct Upload (file upload).
 *
 * Prerequisites (all three, in the environment or this machine):
 *   CLOUDFLARE_API_TOKEN   — a token with Cloudflare Pages:Edit (and Workers:Edit for --api)
 *   CLOUDFLARE_ACCOUNT_ID  — the account to deploy into
 *
 * Usage:
 *   node scripts/deploy-cloudflare.mjs              # console → Pages (direct upload)
 *   node scripts/deploy-cloudflare.mjs --api        # additionally deploy the API Worker
 *   node scripts/deploy-cloudflare.mjs --check      # verify credentials and list targets
 *
 * The token is never written anywhere; it is passed to wrangler through the environment.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const CONSOLE_PROJECT = process.env.CF_PROJECT_NAME ?? 'solvaren-console';
const API_PROJECT = process.env.CF_API_NAME ?? 'solvaren-api';

const token = process.env.CLOUDFLARE_API_TOKEN;
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const args = process.argv.slice(2);

function fail(message) {
  console.error(`\n✗ ${message}\n`);
  process.exit(1);
}

if (!token) {
  fail(
    'CLOUDFLARE_API_TOKEN is not set.\n' +
    '  Create one at https://dash.cloudflare.com/profile/api-tokens\n' +
    '  (template "Cloudflare Pages — Edit", plus "Workers Scripts — Edit" for the API),\n' +
    '  then:  set CLOUDFLARE_API_TOKEN=<token>   (Windows)  or export it (CI).',
  );
}
if (!accountId) {
  fail(
    'CLOUDFLARE_ACCOUNT_ID is not set.\n' +
    '  Find it on the Cloudflare dashboard home page (right-hand column, "Account ID").',
  );
}

function wrangler(...wranglerArgs) {
  const result = spawnSync(
    'npx',
    ['--yes', 'wrangler@latest', ...wranglerArgs],
    {
      cwd: root,
      stdio: 'inherit',
      shell: true,
      env: { ...process.env, CLOUDFLARE_API_TOKEN: token, CLOUDFLARE_ACCOUNT_ID: accountId },
    },
  );
  if (result.status !== 0) fail(`wrangler ${wranglerArgs.join(' ')} exited with ${result.status}`);
}

async function verifyToken() {
  // A cheap authenticated call so a bad token fails here with a clear message,
  // not deep inside the deploy.
  const response = await fetch('https://api.cloudflare.com/client/v4/user/tokens/verify', {
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await response.json();
  if (!body.success) fail(`The API token was rejected: ${JSON.stringify(body.errors)}`);
  console.log('✓ API token verified');
}

async function main() {
  console.log('SOLVAREN → Cloudflare');
  console.log('=====================');
  console.log(`  account: ${accountId}`);
  console.log(`  console: Pages project "${CONSOLE_PROJECT}" (direct upload)`);
  if (args.includes('--api')) console.log(`  api:     Workers "${API_PROJECT}"`);
  console.log('');

  await verifyToken();

  if (args.includes('--check')) {
    console.log('✓ Credentials valid. Re-run without --check to deploy.');
    return;
  }

  // ---- Console → Pages (Direct Upload) ---------------------------------------
  const dist = join(root, 'apps/web/dist');
  if (!existsSync(join(dist, 'index.html'))) {
    fail('apps/web/dist does not exist — run `pnpm --filter @solvaren/web build` first.');
  }

  console.log('Uploading console files to Cloudflare Pages…');
  wrangler(
    'pages', 'project', 'create', CONSOLE_PROJECT,
    '--production-branch', 'main',
  ); // succeeds silently if the project already exists

  wrangler(
    'pages', 'deploy', dist,
    '--project-name', CONSOLE_PROJECT,
    '--branch', 'main',
    '--commit-dirty=true',
  );

  // ---- API → Workers (optional; requires DATABASE_URL etc. as secrets) --------
  if (args.includes('--api')) {
    const wranglerToml = join(root, 'apps/api/wrangler.toml');
    if (!existsSync(wranglerToml)) fail('apps/api/wrangler.toml is missing.');
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      fail(
        'The API Worker refuses to deploy without DATABASE_URL: Cloudflare does not host\n' +
        'PostgreSQL, so the database must be external (Neon, Supabase, RDS…) and passed\n' +
        'as a Worker secret. Set DATABASE_URL in the environment and re-run.',
      );
    }
    console.log('Deploying the API Worker…');
    wrangler('deploy', '--config', wranglerToml);
    console.log('');
    console.log('Set the remaining Worker secrets (one-time):');
    for (const name of [
      'SESSION_SIGNING_KEY', 'SECRET_ENCRYPTION_KEY',
      'APP_ORIGIN', 'API_BASE_URL', 'WEBAUTHN_RP_ID',
      'S3_BUCKET', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY',
    ]) {
      console.log(`  npx wrangler secret put ${name} --config apps/api/wrangler.toml`);
    }
  }

  console.log('');
  console.log('Done. The console URL is printed by wrangler above (…pages.dev).');
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
