#!/usr/bin/env node
/**
 * Source-code invariant checks (spec §24 test requirements, AC-06).
 *
 * Each check greps the tree for a property that must hold in the source itself. The
 * philosophy: some guarantees cannot be tested from the outside — "no SMS path exists"
 * is a property of the codebase, so the codebase is where it is checked.
 *
 * Cross-platform Node (CI runs `node scripts/check-invariants.mjs`; the .sh wrapper
 * delegates here so both worlds stay honest).
 */

import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');

const TARGET_DIRS = ['apps/api/src', 'apps/web/src', 'packages/core/src', 'packages/daraja/src', 'packages/storage/src', 'db/migrations', 'db/tests'];
const EXTENSIONS = new Set(['.ts', '.tsx', '.sql']);

async function collectFiles(dir, out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      await collectFiles(full, out);
    } else if (EXTENSIONS.has(entry.name.slice(entry.name.lastIndexOf('.')))) {
      out.push(full);
    }
  }
  return out;
}

const files = [];
for (const dir of TARGET_DIRS) await collectFiles(join(root, dir), files);
const contents = new Map();
for (const f of files) contents.set(f, await readFile(f, 'utf8'));

let failures = 0;
const report = [];

function check(description, expected, pattern, flags = 'i') {
  const re = new RegExp(pattern, flags);
  let matched = false;
  let where = '';
  for (const [file, text] of contents) {
    if (re.test(text)) {
      matched = true;
      where = relative(root, file);
      break;
    }
  }
  const ok = expected === 'found' ? matched : !matched;
  report.push(`${ok ? '✓' : '✗'} ${description}`);
  if (!ok) {
    failures += 1;
    report.push(`    Expected ${expected}: /${pattern}/${flags}`);
    if (matched) report.push(`    Found in: ${where}`);
  }
}

// ---------------------------------------------------------------------------
// No-SMS rule (AC-06)
// ---------------------------------------------------------------------------
report.push('── No-SMS rule (AC-06) ──');
check('no SMS/OTP integration in any source file', 'absent', 'sendSms|sms[-_]?otp|twilio|africastalking');
check('no phone column on identity tables', 'absent', 'phone_number\\s+(TEXT|VARCHAR)|\\n\\s+phone\\s+TEXT');

// ---------------------------------------------------------------------------
// Release gates (spec §7.5)
// ---------------------------------------------------------------------------
report.push('');
report.push('── Release gates (spec §7.5) ──');
check('release verifies fresh authentication', 'found', 'assertFreshAuthentication\\(actor\\)');
check('release verifies WebAuthn session', 'found', 'assertWebAuthnSession\\(actor\\)');
check('release verifies the FPAC PIN', 'found', 'verifyAuthorizationPin\\(');
check('release re-verifies separation of duties', 'found', 'assertNotSelfAuthorization\\(');
check('release re-derives the manifest from live rows', 'found', 'buildBatchManifest\\(tx,\\s*batch');
check('release burns the challenge conditionally', 'found', 'consumed_at\\s*=\\s*now\\(\\)');
check('release enqueues inside the transaction', 'found', 'input\\.env\\.queue\\.send\\(');

// ---------------------------------------------------------------------------
// Denials auditable
// ---------------------------------------------------------------------------
report.push('');
report.push('── Denials are auditable ──');
check("denials audited as DENIED outcomes", 'found', "outcome:\\s*'DENIED'");
check('PIN rejection audited', 'found', 'payment\\.release\\.pin_rejected');
check('WebAuthn rejection audited', 'found', 'payment\\.release\\.webauthn_rejected');

// ---------------------------------------------------------------------------
// AI boundary (AC-15)
// ---------------------------------------------------------------------------
report.push('');
report.push('── AI boundary (AC-15) ──');
const aiFile = contents.get(join(root, 'apps/api/src/routes/ai.ts')) ?? '';
const aiWritesPayments = /(INSERT INTO (transactions|payment_batches|payment_instructions)|UPDATE (transactions|payment_batches|payment_instructions))/i.test(aiFile);
if (aiWritesPayments) {
  report.push('✗ AI route group contains payment-table writes');
  failures += 1;
} else {
  report.push('✓ AI route group holds no payment-table writes');
}

// ---------------------------------------------------------------------------
// Secrets hygiene
// ---------------------------------------------------------------------------
report.push('');
report.push('── Secrets hygiene ──');
check('no credential-shaped literal assigned in code', 'absent', '(consumerSecret|secretAccessKey)\\s*=\\s*["\'][A-Za-z0-9+/]{20,}');
check('masked views used for configuration responses', 'found', 'MASK');
check('audit details pass through redaction', 'found', 'redactForAudit');

// ---------------------------------------------------------------------------
// Schema-enforced immutability
// ---------------------------------------------------------------------------
report.push('');
report.push('── Schema-enforced immutability ──');
check('audit UPDATE refused by trigger', 'found', 'audit_events_no_update');
check('audit DELETE refused by trigger', 'found', 'audit_events_no_delete');
check('SUCCESS requires a receipt in the schema', 'found', 'transactions_success_requires_receipt');
check('self-approval refused in the schema for L1/L2 (L3 is exempt by organizational decision)', 'found', 'enforce_batch_separation_of_duties');
check('one live payment job per instruction', 'found', 'job_queue_one_live_payment_per_instruction');

// ---------------------------------------------------------------------------
// Callback ingress (the production-critical fix)
// ---------------------------------------------------------------------------
report.push('');
report.push('── Callback ingress ──');
check('callback secret embedded in the stored URLs', 'found', 'callbacks/\\$\\{input\\.organizationId\\}/\\$\\{callbackSecret\\}');
check('callback verification compares in constant time', 'found', 'timingSafeEqual\\(presentedSecret');

// ---------------------------------------------------------------------------
// Dynamic permission engine (AC-17)
// ---------------------------------------------------------------------------
report.push('');
report.push('── Dynamic permission engine (AC-17) ──');
check('effectivePermissions strips ceilings after overrides', 'found', 'GRANT_CEILINGS\\[level\\]');
check('L3 overrides are skipped outright', 'found', "o\\.level === 'L3'");

// ---------------------------------------------------------------------------
// Daraja discipline
// ---------------------------------------------------------------------------
report.push('');
report.push('── Daraja discipline ──');
const clientFile = contents.get(join(root, 'packages/daraja/src/client.ts')) ?? '';
const b2cNoRetry = /sendB2cPayment[\s\S]{0,500}allowRetry:\s*false/.test(clientFile);
if (b2cNoRetry) {
  report.push('✓ B2C is invoked with allowRetry: false');
} else {
  report.push('✗ B2C must be invoked with allowRetry: false');
  failures += 1;
}
check('callback URLs are https-only in the schema', 'found', 'daraja_urls_https');

// ---------------------------------------------------------------------------
console.log('SOLVAREN source invariants');
console.log('=========================');
console.log('');
console.log(report.join('\n'));
console.log('');

if (failures > 0) {
  console.log(`✗ ${failures} invariant check(s) FAILED. The properties above are load-bearing.`);
  process.exit(1);
}
console.log('✓ All invariants hold.');
