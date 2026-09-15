/**
 * A dependency-free S3-compatible object store client with AWS Signature Version 4.
 *
 * Works with AWS S3, Cloudflare R2, MinIO, Backblaze B2 and any other SigV4-speaking
 * endpoint. The platform needs exactly five operations (put, get, head, delete, list)
 * for backups and the secret store — pulling the entire AWS SDK in for five operations
 * would bloat the deployable image and its supply-chain surface for no benefit.
 *
 * Scope: single-operation requests with payload hashes (no multipart), which is exactly
 * right for JSON snapshots that are megabytes, not gigabytes.
 */

import { createHash, createHmac } from 'node:crypto';
import { providerError } from '@solvaren/core';

export interface S3Config {
  /** Required for non-AWS providers (e.g. https://accountid.r2.cloudflarestorage.com). */
  endpoint?: string;
  region: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** Path-style addressing (https://endpoint/bucket/key). R2 and MinIO require it. */
  forcePathStyle: boolean;
}

export interface PutOptions {
  contentType?: string;
  metadata?: Record<string, string>;
}

export interface HeadResult {
  exists: boolean;
  size: number | null;
  etag: string | null;
  metadata: Record<string, string>;
}

export interface ListEntry {
  key: string;
  size: number;
  lastModified: string | null;
}

const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

function uriEncode(value: string, encodeSlash = true): string {
  let out = '';
  for (const ch of value) {
    if (/[A-Za-z0-9_.~-]/.test(ch)) {
      out += ch;
    } else if (ch === '/') {
      out += encodeSlash ? '%2F' : '/';
    } else {
      const bytes = Buffer.from(ch, 'utf8');
      for (const b of bytes) out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return out;
}

export class S3ObjectStore {
  private readonly config: S3Config;

  constructor(config: S3Config) {
    this.config = config;
  }

  private hostAndBase(): { host: string; base: string } {
    if (this.config.endpoint) {
      const url = new URL(this.config.endpoint);
      const host = url.host;
      const base = this.config.forcePathStyle
        ? `${url.origin}/${this.config.bucket}`
        : `${url.protocol}//${this.config.bucket}.${url.host}`;
      return { host, base };
    }
    // AWS S3 default: virtual-host style.
    return {
      host: `${this.config.bucket}.s3.${this.config.region}.amazonaws.com`,
      base: `https://${this.config.bucket}.s3.${this.config.region}.amazonaws.com`,
    };
  }

  private sign(
    method: string,
    keyPath: string,
    query: Map<string, string>,
    headers: Record<string, string>,
    payloadHash: string,
  ): { authorization: string; amzDate: string } {
    const { host } = this.hostAndBase();
    const amzDate = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z'; // 20260914T101530Z
    const dateStamp = amzDate.slice(0, 8);

    const signedHeaders: Record<string, string> = {
      host,
      'x-amz-content-sha256': payloadHash,
      'x-amz-date': amzDate,
      ...Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])),
    };

    const sortedHeaderKeys = Object.keys(signedHeaders).sort();
    const canonicalHeaders = sortedHeaderKeys.map((k) => `${k}:${signedHeaders[k]!.trim()}\n`).join('');
    const signedHeaderList = sortedHeaderKeys.join(';');

    const canonicalQuery = [...query.entries()]
      .map(([k, v]) => [uriEncode(k), uriEncode(v)] as const)
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([k, v]) => `${k}=${v}`)
      .join('&');

    const canonicalRequest = [
      method,
      uriEncode(keyPath, false),
      canonicalQuery,
      canonicalHeaders,
      signedHeaderList,
      payloadHash,
    ].join('\n');

    const scope = `${dateStamp}/${this.config.region}/s3/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      scope,
      sha256Hex(canonicalRequest),
    ].join('\n');

    const kDate = hmac(`AWS4${this.config.secretAccessKey}`, dateStamp);
    const kRegion = hmac(kDate, this.config.region);
    const kService = hmac(kRegion, 's3');
    const kSigning = hmac(kService, 'aws4_request');
    const signature = createHmac('sha256', kSigning).update(stringToSign).digest('hex');

    return {
      authorization: `AWS4-HMAC-SHA256 Credential=${this.config.accessKeyId}/${scope}, SignedHeaders=${signedHeaderList}, Signature=${signature}`,
      amzDate,
    };
  }

  private async request(
    method: 'GET' | 'PUT' | 'HEAD' | 'DELETE',
    keyPath: string,
    options: {
      query?: Map<string, string>;
      headers?: Record<string, string>;
      body?: Buffer | string;
      timeoutMs?: number;
    } = {},
  ): Promise<Response> {
    const { base } = this.hostAndBase();
    const body = options.body !== undefined ? Buffer.from(options.body) : undefined;
    const payloadHash = body ? sha256Hex(body) : SHA256_EMPTY;

    const { authorization, amzDate } = this.sign(
      method,
      `/${keyPath}`,
      options.query ?? new Map(),
      {
        ...(options.headers ?? {}),
        ...(body ? { 'content-length': String(body.byteLength) } : {}),
      },
      payloadHash,
    );

    const url = `${base}/${keyPath}${options.query && options.query.size > 0 ? `?${[...options.query.entries()].map(([k, v]) => `${uriEncode(k)}=${uriEncode(v)}`).join('&')}` : ''}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 30_000);
    try {
      return await fetch(url, {
        method,
        headers: {
          Authorization: authorization,
          'x-amz-date': amzDate,
          'x-amz-content-sha256': payloadHash,
          ...(options.headers ?? {}),
        },
        body: body as BodyInit | undefined,
        signal: controller.signal,
      });
    } catch (err) {
      const aborted = err instanceof Error && err.name === 'AbortError';
      throw providerError(
        aborted ? 'S3_TIMEOUT' : 'S3_UNREACHABLE',
        aborted ? `The object store did not respond in time (${keyPath})` : 'SOLVAREN could not reach the object store',
        { url: url.replace(/\?.*$/, '') },
      );
    } finally {
      clearTimeout(timer);
    }
  }

  async put(key: string, body: string | Buffer, options: PutOptions = {}): Promise<void> {
    const headers: Record<string, string> = {};
    if (options.contentType) headers['Content-Type'] = options.contentType;
    for (const [k, v] of Object.entries(options.metadata ?? {})) {
      // S3 user metadata travels as x-amz-meta-*; keys are lowercased by the wire.
      headers[`x-amz-meta-${k.toLowerCase()}`] = v;
    }
    const response = await this.request('PUT', key, { body, headers, timeoutMs: 120_000 });
    if (!(response.status === 200 || response.status === 201)) {
      throw await s3Error(response, 'put', key);
    }
  }

  async get(key: string): Promise<string | null> {
    const response = await this.request('GET', key);
    if (response.status === 404) return null;
    if (!response.ok) throw await s3Error(response, 'get', key);
    return response.text();
  }

  async head(key: string): Promise<HeadResult> {
    const response = await this.request('HEAD', key);
    if (response.status === 404) return { exists: false, size: null, etag: null, metadata: {} };
    if (!response.ok) throw await s3Error(response, 'head', key);
    const metadata: Record<string, string> = {};
    response.headers.forEach((value, name) => {
      if (name.startsWith('x-amz-meta-')) metadata[name.slice('x-amz-meta-'.length)] = value;
    });
    return {
      exists: true,
      size: Number(response.headers.get('content-length') ?? '0'),
      etag: response.headers.get('etag'),
      metadata,
    };
  }

  async delete(key: string): Promise<void> {
    const response = await this.request('DELETE', key);
    if (!(response.ok || response.status === 404)) {
      throw await s3Error(response, 'delete', key);
    }
  }

  /** List keys under a prefix (single page of up to 1000; sufficient for retention). */
  async list(prefix: string): Promise<ListEntry[]> {
    const query = new Map<string, string>([
      ['list-type', '2'],
      ['max-keys', '1000'],
      ['prefix', prefix],
    ]);
    const response = await this.request('GET', '', { query });
    if (!response.ok) throw await s3Error(response, 'list', prefix);
    const xml = await response.text();
    return parseListBucketResult(xml);
  }

  /**
   * Prove the credentials and bucket are usable without writing payload data:
   * list the bucket root. Used by the backup "Test connection" flow.
   */
  async testConnection(): Promise<{ ok: boolean; message: string }> {
    try {
      const response = await this.request('GET', '', { query: new Map([['list-type', '2'], ['max-keys', '1']]) });
      if (response.ok) {
        return { ok: true, message: `Connected to bucket ${this.config.bucket}.` };
      }
      if (response.status === 403) {
        return { ok: false, message: 'The object store rejected the credentials (403).' };
      }
      if (response.status === 404) {
        return { ok: false, message: `The bucket ${this.config.bucket} was not found.` };
      }
      return { ok: false, message: `The object store returned HTTP ${response.status}.` };
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : 'The connection test failed' };
    }
  }
}

async function s3Error(response: Response, operation: string, key: string): Promise<Error> {
  let detail = '';
  try {
    const text = await response.text();
    // Surface the <Message> element from an S3 XML error without a parser dependency.
    const match = text.match(/<Message>([^<]*)<\/Message>/);
    if (match) detail = match[1]!;
  } catch {
    /* body unreadable — status is enough */
  }
  return providerError(
    'S3_REQUEST_FAILED',
    `The object store ${operation} for "${key}" failed (HTTP ${response.status}${detail ? `: ${detail}` : ''})`,
    { httpStatus: response.status, operation, keyPrefix: key.split('/')[0] },
  );
}

function parseListBucketResult(xml: string): ListEntry[] {
  const entries: ListEntry[] = [];
  const contentsBlocks = xml.split('<Contents>').slice(1);
  for (const block of contentsBlocks) {
    const key = block.match(/<Key>([^<]*)<\/Key>/)?.[1];
    if (key === undefined) continue;
    const size = Number(block.match(/<Size>([^<]*)<\/Size>/)?.[1] ?? '0');
    const lastModified = block.match(/<LastModified>([^<]*)<\/LastModified>/)?.[1] ?? null;
    entries.push({ key: key.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>'), size, lastModified });
  }
  return entries;
}
