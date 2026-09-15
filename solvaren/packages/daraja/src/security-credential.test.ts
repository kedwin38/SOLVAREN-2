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
  validateInitiatorPassword,
} from './security-credential.js';
import { createPublicKey, generateKeyPairSync } from 'node:crypto';

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

describe('validateInitiatorPassword', () => {
  // Safaricom publishes no documented composition rules, so the platform must not invent
  // any: real portal passwords (including @ and .) must pass locally. The authoritative
  // check is the Daraja connection test, which gates Enable.
  it('accepts real-world portal passwords regardless of character composition', () => {
    expect(validateInitiatorPassword('Kirinyaga@2026').ok).toBe(true);
    expect(validateInitiatorPassword('My.Pass#2026').ok).toBe(true);
    expect(validateInitiatorPassword('Str0ng!P@ssw0rd-2026').ok).toBe(true);
  });

  it('keeps our own length sanity bounds', () => {
    expect(validateInitiatorPassword('abc123!').ok).toBe(false); // 7 chars
    expect(validateInitiatorPassword('x'.repeat(129)).ok).toBe(false);
    expect(validateInitiatorPassword('x'.repeat(128)).ok).toBe(true);
  });
});

describe('certificate upload compatibility (.cer / .der)', () => {
  // The console uploads binary DER certificates as base64 text (the API takes strings),
  // PEM files verbatim, and text .cer files as bare base64. All three must encrypt.
  const makeKey = () =>
    generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

  it('accepts base64-encoded DER (binary .cer/.der converted client-side)', () => {
    const { publicKey } = makeKey();
    const spkiDer = createPublicKey(publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
    const credential = generateSecurityCredential('abc12345', spkiDer.toString('base64'));
    expect(Buffer.from(credential, 'base64').byteLength).toBe(256);
  });

  it('accepts line-wrapped base64 DER (a .cer opened in a text editor and copied)', () => {
    const { publicKey } = makeKey();
    const spkiDer = createPublicKey(publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
    const wrapped = spkiDer.toString('base64').replace(/(.{64})/g, '$1\n').trim();
    const credential = generateSecurityCredential('abc12345', wrapped);
    expect(Buffer.from(credential, 'base64').byteLength).toBe(256);
  });

  it('accepts raw DER bytes directly (Uint8Array)', () => {
    const { publicKey } = makeKey();
    const spkiDer = createPublicKey(publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
    const credential = generateSecurityCredential('abc12345', new Uint8Array(spkiDer));
    expect(Buffer.from(credential, 'base64').byteLength).toBe(256);
  });
});
