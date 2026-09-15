/**
 * The secret store (spec §8.4, Zone 6).
 *
 * Plaintext secrets never live in application tables. This store persists AES-GCM
 * envelopes (encrypted under SECRET_ENCRYPTION_KEY before leaving the process) in the
 * platform's S3-compatible bucket under an opaque `secrets/` prefix, and the database
 * keeps only the reference. Compromising the bucket alone yields nothing usable; leaking
 * the database alone yields only reference names.
 *
 * A `FileSecretStore` exists for local development and the integration test suite, so
 * tests never need real object storage.
 */

import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import type { S3ObjectStore } from '@solvaren/storage';
import { encryptSecret, decryptSecret } from './crypto.js';

export interface SecretStore {
  put(reference: string, plaintext: string, purpose?: string): Promise<void>;
  get(reference: string, purpose?: string): Promise<string | null>;
  delete(reference: string): Promise<void>;
}

const PREFIX = 'secrets/';

/** Production: S3-backed, envelope-encrypted before the bytes ever leave the process. */
export class S3SecretStore implements SecretStore {
  constructor(
    private readonly objects: S3ObjectStore,
    private readonly masterKey: string,
  ) {}

  async put(reference: string, plaintext: string, purpose?: string): Promise<void> {
    const envelope = await encryptSecret(plaintext, this.masterKey, purpose ?? 'secret');
    await this.objects.put(`${PREFIX}${reference}`, envelope, {
      contentType: 'application/octet-stream',
      metadata: { kind: 'solvaren-secret-envelope' },
    });
  }

  async get(reference: string, purpose?: string): Promise<string | null> {
    const envelope = await this.objects.get(`${PREFIX}${reference}`);
    return envelope ? decryptSecret(envelope, this.masterKey, purpose ?? 'secret') : null;
  }

  async delete(reference: string): Promise<void> {
    await this.objects.delete(`${PREFIX}${reference}`);
  }
}

/**
 * Development/test: same envelope encryption, file-backed. The directory is explicitly
 * a development artefact — production config points at the S3 store.
 */
export class FileSecretStore implements SecretStore {
  constructor(
    private readonly directory: string,
    private readonly masterKey: string,
  ) {
    mkdirSync(directory, { recursive: true });
  }

  private path(reference: string): string {
    return join(this.directory, reference.replace(/[^a-zA-Z0-9:_-]/g, '_'));
  }

  async put(reference: string, plaintext: string, purpose?: string): Promise<void> {
    const envelope = await encryptSecret(plaintext, this.masterKey, purpose ?? 'secret');
    const target = this.path(reference);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, envelope, 'utf8');
  }

  async get(reference: string, purpose?: string): Promise<string | null> {
    const target = this.path(reference);
    if (!existsSync(target)) return null;
    return decryptSecret(readFileSync(target, 'utf8'), this.masterKey, purpose ?? 'secret');
  }

  async delete(reference: string): Promise<void> {
    const target = this.path(reference);
    if (existsSync(target)) writeFileSync(target, '', 'utf8');
  }
}

/** Reference builder — deterministic, opaque, and free of secret material. */
export function secretReference(organizationId: string, ...parts: string[]): string {
  return ['org', organizationId, ...parts].join(':');
}
