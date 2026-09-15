#!/usr/bin/env node
/**
 * Create the first organization and its first L3 account (deployment step 7).
 *
 * The L3 account is created as PENDING_ENROLMENT: it cannot act until the officer signs
 * in, enrols a security key (mandatory for L3) and sets the Frontier Authorization PIN.
 *
 * Usage:
 *   DATABASE_URL=… node scripts/create-user.mjs \
 *     --org "Acme Ltd" --slug acme --email chief@acme.co.ke \
 *     --name "Jane Chief" --password '<temporary>' --pin 482913
 */

import { parseArgs } from 'node:util';
import postgres from 'postgres';

const { values } = parseArgs({
  options: {
    org: { type: 'string' },
    slug: { type: 'string' },
    email: { type: 'string' },
    name: { type: 'string' },
    password: { type: 'string' },
    pin: { type: 'string' },
    level: { type: 'string', default: 'L3' },
  },
});

const required = ['org', 'slug', 'email', 'name', 'password'];
for (const key of required) {
  if (!values[key]) {
    console.error(`--${key} is required. See the header of this script for usage.`);
    process.exit(1);
  }
}
if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(values.slug)) {
  console.error('--slug must be lowercase letters, digits and dashes.');
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error('DATABASE_URL is not set.');
  process.exit(1);
}

const sql = postgres(databaseUrl, { max: 1 });

// Argon2id hashing via the same WASM implementation the API uses.
const { argon2id } = await import(
  new URL('../packages/core/src/index.js', import.meta.url).href
).catch(() => ({ argon2id: null }));

async function main() {
  const orgId = crypto.randomUUID();
  const userId = crypto.randomUUID();
  const level = values.level;

  // Import the crypto service through the API source with Node's type stripping.
  const { hashPassword, hashAuthorizationPin, assertPinShape } = await import(
    new URL('../apps/api/src/services/crypto.ts', import.meta.url).href
  );

  const passwordHash = await hashPassword(values.password);
  const pinHash = level !== 'L1' && values.pin ? await hashAuthorizationPin(values.pin, userId) : null;
  if (values.pin) assertPinShape(values.pin);

  await sql.begin(async (tx) => {
    await tx`
      INSERT INTO organizations (id, slug, name) VALUES (${orgId}, ${values.slug}, ${values.org})
    `;
    await tx`
      INSERT INTO policies (organization_id, max_instruction_amount_cents, max_batch_total_cents,
        max_batch_instructions, high_value_threshold_cents, cooling_off_seconds, blocking_risk_band)
      VALUES (${orgId}, 25000000, 5000000000, 5000, 500000000, 300, 'CRITICAL')
    `;
    await tx`
      INSERT INTO users (id, organization_id, email, full_name, authority_level, status,
        password_hash, authorization_pin_hash, authorization_pin_updated_at)
      VALUES (${userId}, ${orgId}, ${values.email.toLowerCase()}, ${values.name}, ${level},
        ${level === 'L1' ? 'ACTIVE' : 'PENDING_ENROLMENT'}, ${passwordHash},
        ${pinHash}, ${pinHash ? new Date() : null})
    `;
  });

  console.log(`Organization "${values.org}" created (${values.slug}).`);
  console.log(`User ${values.email} (${level}) created.`);
  if (level !== 'L1') {
    console.log('');
    console.log('Next steps for this officer:');
    console.log('  1. Share the temporary password securely.');
    console.log('  2. The officer signs in with password + enrols a security key (mandatory for L2/L3).');
    console.log('  3. The account activates when the key is enrolled.');
  }

  await sql.end();
}

void argon2id;

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
