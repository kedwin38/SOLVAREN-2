/**
 * The manifest and challenge protocol (spec §7.5, §24).
 *
 * The critical property: ANY material change — amount, recipient set, MSISDN, approval
 * id, batch version, policy digest — must move the digest, invalidating the prior
 * authorization. And the challenge gates: expiry, single use, user binding.
 */

import { describe, expect, it } from 'vitest';
import {
  buildManifest,
  buildChallenge,
  verifyChallengeBinding,
  MANIFEST_VERSION,
  type ManifestInput,
} from './index.js';

const baseInput: ManifestInput = {
  organizationId: 'org-1',
  batchId: 'batch-1',
  batchReference: 'SLV-1001',
  batchVersion: 3,
  approvalId: 'APR-8821',
  approvedBatchVersion: 3,
  policyDigest: 'policy-digest-abc',
  instructions: [
    { instructionId: 'ins-1', recipientId: 'rec-1', msisdn: '254705912645', amountCents: 50_000_00 },
    { instructionId: 'ins-2', recipientId: 'rec-2', msisdn: '254722000001', amountCents: 120_000_00 },
  ],
};

async function built() {
  return buildManifest(baseInput);
}

describe('manifest determinism', () => {
  it('produces the same digest for the same input', async () => {
    const a = await built();
    const b = await built();
    expect(a.manifestHash).toBe(b.manifestHash);
    expect(a.canonicalForm).toBe(b.canonicalForm);
  });

  it('is independent of instruction array order', async () => {
    const reordered = await buildManifest({
      ...baseInput,
      instructions: [...baseInput.instructions].reverse(),
    });
    const original = await built();
    expect(reordered.manifestHash).toBe(original.manifestHash);
  });

  it('carries the version tag so protocol changes are detectable', async () => {
    const m = await built();
    expect(m.version).toBe(MANIFEST_VERSION);
    expect(m.canonicalForm.startsWith(MANIFEST_VERSION)).toBe(true);
  });
});

describe('material changes invalidate the digest (spec §24: signature invalid after edit)', () => {
  const mutations: [string, (input: ManifestInput) => ManifestInput][] = [
    [
      'an amount change',
      (i) => ({ ...i, instructions: [i.instructions[0]!, { ...i.instructions[1]!, amountCents: 9_420_500_00 }] }),
    ],
    [
      'a recipient added',
      (i) => ({
        ...i,
        instructions: [...i.instructions, { instructionId: 'ins-3', recipientId: 'rec-3', msisdn: '254733000002', amountCents: 10_000 }],
      }),
    ],
    [
      'a recipient removed',
      (i) => ({ ...i, instructions: [i.instructions[0]!] }),
    ],
    [
      'a MSISDN changed',
      (i) => ({ ...i, instructions: [{ ...i.instructions[0]!, msisdn: '254799999999' }, i.instructions[1]!] }),
    ],
    [
      'the approval id changed',
      (i) => ({ ...i, approvalId: 'APR-9999' }),
    ],
    [
      'the batch version bumped',
      (i) => ({ ...i, batchVersion: 4, approvedBatchVersion: 4 }),
    ],
    [
      'the policy digest changed',
      (i) => ({ ...i, policyDigest: 'policy-digest-new' }),
    ],
    [
      'the organization changed',
      (i) => ({ ...i, organizationId: 'org-2' }),
    ],
  ];

  for (const [label, mutate] of mutations) {
    it(`${label} moves the digest`, async () => {
      const original = await built();
      const mutated = await buildManifest(mutate(baseInput));
      expect(mutated.manifestHash).not.toBe(original.manifestHash);
    });
  }

  it('refuses outright when the approval version no longer matches the batch version', async () => {
    await expect(
      buildManifest({ ...baseInput, batchVersion: 5, approvedBatchVersion: 3 }),
    ).rejects.toThrow(/changed since it was approved/i);
  });

  it('refuses an empty manifest', async () => {
    await expect(buildManifest({ ...baseInput, instructions: [] })).rejects.toThrow(/at least one/i);
  });

  it('refuses a non-positive amount', async () => {
    await expect(
      buildManifest({
        ...baseInput,
        instructions: [{ ...baseInput.instructions[0]!, amountCents: 0 }],
      }),
    ).rejects.toThrow(/non-positive/i);
  });

  it('refuses a duplicated instruction', async () => {
    await expect(
      buildManifest({
        ...baseInput,
        instructions: [baseInput.instructions[0]!, baseInput.instructions[0]!],
      }),
    ).rejects.toThrow(/appears twice/i);
  });
});

describe('challenge construction and verification', () => {
  it('binds the challenge to the manifest, user, nonce and expiry', async () => {
    const manifest = await built();
    const challenge = await buildChallenge({
      manifest,
      nonce: 'a'.repeat(32),
      expiresAt: Date.now() + 60_000,
      authorizerUserId: 'l3-user',
    });
    expect(challenge.challengeHash).not.toBe(manifest.manifestHash);
    expect(challenge.challengeHash.length).toBe(64);
    expect(challenge.display.batchReference).toBe('SLV-1001');
    expect(challenge.display.recipientCount).toBe(2);
    expect(challenge.display.totalAmountCents).toBe(170_000_00);
  });

  it('refuses a weak nonce', async () => {
    const manifest = await built();
    await expect(
      buildChallenge({ manifest, nonce: 'short', expiresAt: Date.now() + 60_000, authorizerUserId: 'u' }),
    ).rejects.toThrow(/nonce/i);
  });

  it('verifies cleanly when nothing changed', async () => {
    const manifest = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest, nonce: 'n'.repeat(32), expiresAt: now + 60_000, authorizerUserId: 'l3-user' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'l3-user',
        now: now + 1000,
      }),
    ).not.toThrow();
  });

  it('rejects a consumed challenge (replay)', async () => {
    const manifest = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest, nonce: 'n'.repeat(32), expiresAt: now + 60_000, authorizerUserId: 'l3-user' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: now },
        current: manifest,
        presentingUserId: 'l3-user',
        now: now + 1000,
      }),
    ).toThrow(/already been used/i);
  });

  it('rejects an expired challenge', async () => {
    const manifest = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest, nonce: 'n'.repeat(32), expiresAt: now + 10_000, authorizerUserId: 'l3-user' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'l3-user',
        now: now + 60_000,
      }),
    ).toThrow(/expired/i);
  });

  it('rejects a challenge presented by a different user', async () => {
    const manifest = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest, nonce: 'n'.repeat(32), expiresAt: now + 60_000, authorizerUserId: 'l3-user' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: manifest,
        presentingUserId: 'someone-else',
        now: now + 1000,
      }),
    ).toThrow(/different user/i);
  });

  it('rejects a manifest that changed after the ceremony opened — the §24 attack', async () => {
    const authorized = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest: authorized, nonce: 'n'.repeat(32), expiresAt: now + 60_000, authorizerUserId: 'l3-user' });

    // The attacker edits the amount between approval and release.
    const tampered = await buildManifest({
      ...baseInput,
      instructions: [baseInput.instructions[0]!, { ...baseInput.instructions[1]!, amountCents: 9_420_500_00 }],
    });

    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null },
        current: tampered,
        presentingUserId: 'l3-user',
        now: now + 1000,
      }),
    ).toThrow(/batch has changed/i);
  });

  it('rejects a challenge that belongs to a different batch', async () => {
    const manifest = await built();
    const now = Date.now();
    const challenge = await buildChallenge({ manifest, nonce: 'n'.repeat(32), expiresAt: now + 60_000, authorizerUserId: 'l3-user' });
    expect(() =>
      verifyChallengeBinding({
        stored: { ...challenge, consumedAt: null, batchId: 'other-batch' },
        current: manifest,
        presentingUserId: 'l3-user',
        now: now + 1000,
      }),
    ).toThrow(/different batch/i);
  });
});
