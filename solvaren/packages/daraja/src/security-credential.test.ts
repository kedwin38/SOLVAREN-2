/**
 * Regression tests for pasted-credential handling.
 *
 * The shape heuristic once rejected credentials that arrived line-wrapped (the default
 * when copied out of the Daraja portal or an email client), treating them as initiator
 * passwords and demanding the M-PESA certificate instead. These tests pin the fix.
 */

import { describe, expect, it } from 'vitest';
import {
  cleanSecurityCredential,
  generateSecurityCredential,
  isPrecomputedCredential,
} from './security-credential.js';
import { generateKeyPairSync } from 'node:crypto';

const CREDENTIAL_2048 =
  'A'.repeat(342) + '==';

describe('isPrecomputedCredential', () => {
  it('accepts an unwrapped 2048-bit credential', () => {
    expect(isPrecomputedCredential(CREDENTIAL_2048)).toBe(true);
  });

  it('accepts a credential line-wrapped at 64 characters (portal copy-paste)', () => {
    const wrapped = CREDENTIAL_2048.replace(/(.{64})/g, '$1\n').trim();
    expect(wrapped.includes('\n')).toBe(true);
    expect(isPrecomputedCredential(wrapped)).toBe(true);
  });

  it('accepts a credential with leading/trailing whitespace', () => {
    expect(isPrecomputedCredential(`  \n${CREDENTIAL_2048}\n  `)).toBe(true);
  });

  it('rejects an initiator password', () => {
    expect(isPrecomputedCredential('Safaricom#2026$Init')).toBe(false);
    expect(isPrecomputedCredential('short-base64-but-too-short-credential-value')).toBe(false);
  });

  it('rejects values with characters outside the base64 alphabet', () => {
    expect(isPrecomputedCredential(`${'A'.repeat(200)}!`)).toBe(false);
  });
});

describe('cleanSecurityCredential', () => {
  it('strips all whitespace, leaving pure base64', () => {
    const wrapped = CREDENTIAL_2048.replace(/(.{64})/g, '$1\r\n');
    expect(cleanSecurityCredential(`\n ${wrapped} \n`)).toBe(CREDENTIAL_2048);
  });
});

describe('generateSecurityCredential round-trip (shape only)', () => {
  it('produces base64 of exactly the modulus size', () => {
    const { publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const credential = generateSecurityCredential('abc12345', publicKey);
    expect(credential).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(Buffer.from(credential, 'base64').byteLength).toBe(256);
    // A generated credential must itself pass the pre-computed heuristic.
    expect(isPrecomputedCredential(credential)).toBe(true);
  });
});
