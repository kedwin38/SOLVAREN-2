/**
 * Signing-conformance tests.
 *
 * The canonical URI must be reconstructable from the request exactly as a SigV4
 * server does it — from the path of the URL the client actually sends. The first
 * deployment against MinIO (path-style) failed 403 SignatureDoesNotMatch because
 * the signed path omitted the bucket prefix while the wire path included it.
 * These tests re-derive the signature from the wire request, server-style, and
 * require it to equal the client's — for both addressing styles.
 */

import { describe, expect, it, vi, afterEach } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import { S3ObjectStore } from './s3.js';

const REGION = 'us-east-1';
const ACCESS_KEY = 'AKIAEXAMPLE';
const SECRET_KEY = 'example-secret';

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Buffer;
}

function captureFetch(): Captured | undefined {
  return (globalThis.fetch as unknown as { __captured?: Captured }).__captured;
}

async function run(store: S3ObjectStore, action: () => Promise<unknown>): Promise<Captured> {
  let captured: Captured | undefined;
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    captured = {
      url: typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      method: String(init?.method),
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), String(v)]),
      ),
      body: init?.body === undefined ? Buffer.alloc(0) : Buffer.from(init.body as Uint8Array),
    };
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  try {
    await action();
  } finally {
    globalThis.fetch = original;
  }
  return captured!;
}

/** Re-derive the signature from the wire request the way a SigV4 server must. */
function serverSideSignature(captured: Captured, accessKey: string, secretKey: string, region: string): string {
  const url = new URL(captured.url);
  const payloadHash = createHash('sha256').update(captured.body).digest('hex');
  const amzDate = captured.headers['x-amz-date']!;
  const dateStamp = amzDate.slice(0, 8);
  const signedList = /SignedHeaders=([^,]+),/.exec(captured.headers['authorization']!)![1]!;
  const canonicalHeaders = signedList
    .split(';')
    .map((h) => {
      let value: string;
      if (h === 'host') value = url.host;
      else if (h === 'content-length') value = String(captured.body.length); // undici adds it on the wire
      else value = captured.headers[h] ?? '';
      return `${h}:${value}\n`;
    })
    .join('');
  // A SigV4 server re-encodes the decoded path per canonical-URI rules (each segment
  // URI-encoded, uppercase hex), so the naive raw pathname is not what is signed.
  const canonicalUri = url.pathname
    .split('/')
    .map((segment) =>
      segment
        .split('')
        .map((ch) => (/[A-Za-z0-9_.~-]/.test(ch) ? ch : `%${Buffer.from(ch)[0]!.toString(16).toUpperCase().padStart(2, '0')}`))
        .join(''),
    )
    .join('/');
  // ...and signs the sorted, strictly-encoded query string.
  const strictEncode = (value: string) =>
    value
      .split('')
      .map((ch) => (/[A-Za-z0-9_.~-]/.test(ch) ? ch : `%${Buffer.from(ch)[0]!.toString(16).toUpperCase().padStart(2, '0')}`))
      .join('');
  const canonicalQuery = [...url.searchParams.entries()]
    .map(([k, v]) => [strictEncode(k), strictEncode(v)] as const)
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const canonicalRequest = [captured.method, canonicalUri, canonicalQuery, canonicalHeaders, signedList, payloadHash].join('\n');
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    scope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');
  const hmac = (k: Buffer | string, d: string) => createHmac('sha256', k).update(d).digest();
  const kSigning = hmac(hmac(hmac(hmac(`AWS4${secretKey}`, dateStamp), region), 's3'), 'aws4_request');
  return createHmac('sha256', kSigning).update(stringToSign).digest('hex');
}

function clientSignature(captured: Captured): string {
  return /Signature=([0-9a-f]+)$/.exec(captured.headers['authorization']!)![1]!;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('S3ObjectStore SigV4 conformance', () => {
  it('path-style: the signature must cover the bucket prefix (the wire path)', async () => {
    const store = new S3ObjectStore({
      endpoint: 'http://minio.internal:9000',
      region: REGION,
      bucket: 'solvaren-backups',
      accessKeyId: ACCESS_KEY,
      secretAccessKey: SECRET_KEY,
      forcePathStyle: true,
    });
    const captured = await run(store, () =>
      store.put('secrets/org:123:daraja:consumer_secret', 'envelope-body', {
        contentType: 'application/octet-stream',
        metadata: { kind: 'solvaren-secret-envelope' },
      }),
    );
    expect(captured.url).toBe('http://minio.internal:9000/solvaren-backups/secrets/org:123:daraja:consumer_secret');
    expect(clientSignature(captured)).toBe(serverSideSignature(captured, ACCESS_KEY, SECRET_KEY, REGION));
  });

  it('virtual-host style: the signature covers the key path against the bucket host', async () => {
    const store = new S3ObjectStore({
      endpoint: 'https://account.r2.cloudflarestorage.com',
      region: 'auto',
      bucket: 'solvaren-backups',
      accessKeyId: ACCESS_KEY,
      secretAccessKey: SECRET_KEY,
      forcePathStyle: false,
    });
    const captured = await run(store, () => store.put('secrets/plain-key', 'body'));
    expect(captured.url).toBe('https://solvaren-backups.account.r2.cloudflarestorage.com/secrets/plain-key');
    expect(clientSignature(captured)).toBe(serverSideSignature(captured, ACCESS_KEY, SECRET_KEY, 'auto'));
  });

  it('bucket-root list: the canonical URI matches the trailing-slash wire path', async () => {
    const store = new S3ObjectStore({
      endpoint: 'http://minio.internal:9000',
      region: REGION,
      bucket: 'solvaren-backups',
      accessKeyId: ACCESS_KEY,
      secretAccessKey: SECRET_KEY,
      forcePathStyle: true,
    });
    const captured = await run(store, () => store.list('secrets/'));
    expect(captured.url).toContain('list-type=2');
    expect(clientSignature(captured)).toBe(serverSideSignature(captured, ACCESS_KEY, SECRET_KEY, REGION));
  });
});
