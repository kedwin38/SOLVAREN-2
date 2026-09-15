/**
 * Rate control (spec §10, §21 Security).
 *
 * Two shapes:
 *  - `acquire(organizationId, …)` — a token bucket per organisation, mutated under
 *    `SELECT … FOR UPDATE`, so the count is authoritative across however many Railway
 *    replicas are running. Used by the payment executor to stay inside the Daraja TPS.
 *  - `acquireKey(key, …)` — the same bucket maths keyed by an arbitrary string
 *    (`login:<ip>`, `export:<userId>`, `callback:<ip>`). Used by the abuse-prone
 *    endpoints the threat model calls out.
 *
 * PostgreSQL rather than Redis: one authoritative store for correctness, and the volume
 * (a handful of token checks per payment) is nowhere near a bottleneck. If it ever
 * becomes one, an adapter in front of Redis can shadow this interface.
 */

import type { Sql } from './db/client.js';

export interface RateLimitRequest {
  permits?: number;
  /** Sustained rate in requests per second. */
  ratePerSecond?: number;
  /** Burst capacity. */
  burst?: number;
}

export interface RateLimitResponse {
  allowed: boolean;
  remaining: number;
  /** Milliseconds until the next permit becomes available, when refused. */
  retryAfterMs: number;
}

/** Conservative defaults. Daraja does not publish a universal TPS; the contract governs. */
const DEFAULT_RATE_PER_SECOND = 5;
const DEFAULT_BURST = 20;

interface BucketSnapshot {
  tokens: number;
  elapsed_seconds: number;
}

/**
 * The decision half, executed inside the caller's transaction. Kept as one function per
 * table so no dynamic SQL identifiers are ever interpolated.
 */
async function decide(
  tx: Sql,
  table: 'organization' | 'key',
  key: string,
  refilled: number,
  permits: number,
  ratePerSecond: number,
): Promise<RateLimitResponse> {
  // Persist the refill even on refusal, so the elapsed time is not counted twice on the
  // next call.
  if (table === 'organization') {
    await tx`UPDATE rate_limit_buckets
               SET tokens = ${refilled}, last_refill_at = now(), updated_at = now()
             WHERE organization_id = ${key}`;
  } else {
    await tx`UPDATE rate_limit_keys
               SET tokens = ${refilled}, last_refill_at = now()
             WHERE bucket_key = ${key}`;
  }

  if (refilled < permits) {
    const shortfall = permits - refilled;
    return {
      allowed: false,
      remaining: Math.floor(refilled),
      retryAfterMs: Math.ceil((shortfall / ratePerSecond) * 1000),
    };
  }

  const remaining = refilled - permits;
  if (table === 'organization') {
    await tx`UPDATE rate_limit_buckets
               SET tokens = ${remaining}, updated_at = now()
             WHERE organization_id = ${key}`;
  } else {
    await tx`UPDATE rate_limit_keys SET tokens = ${remaining} WHERE bucket_key = ${key}`;
  }
  return { allowed: true, remaining: Math.floor(remaining), retryAfterMs: 0 };
}

export class PostgresRateLimiter {
  constructor(private readonly sql: Sql) {}

  async acquire(organizationId: string, options: RateLimitRequest = {}): Promise<RateLimitResponse> {
    const permits = clampPermits(options.permits);
    const ratePerSecond = clampRate(options.ratePerSecond);
    const burst = clampBurst(options.burst);

    return this.sql.begin(async (txRaw) => {
      const tx = txRaw as unknown as Sql;
      await tx`SET LOCAL statement_timeout = '5s'`;

      // Create the bucket full on first use, then lock whatever is there. An UPSERT
      // that wrote `tokens` would reset a live bucket to full on every call — a rate
      // limiter that never limits.
      await tx`
        INSERT INTO rate_limit_buckets (organization_id, tokens, last_refill_at)
        VALUES (${organizationId}, ${burst}, now())
        ON CONFLICT (organization_id) DO NOTHING
      `;

      const rows = await tx<BucketSnapshot[]>`
        SELECT tokens,
               EXTRACT(EPOCH FROM (now() - last_refill_at))::double precision AS elapsed_seconds
          FROM rate_limit_buckets
         WHERE organization_id = ${organizationId}
           FOR UPDATE
      `;

      const snapshot = rows[0];
      if (!snapshot) {
        // The row was created and locked above; its absence would mean the organisation
        // was deleted mid-call. Refuse rather than invent a permit.
        return { allowed: false, remaining: 0, retryAfterMs: 1000 };
      }
      const refilled = Math.min(
        burst,
        snapshot.tokens + Math.max(0, snapshot.elapsed_seconds) * ratePerSecond,
      );
      return decide(tx, 'organization', organizationId, refilled, permits, ratePerSecond);
    });
  }

  async acquireKey(bucketKey: string, options: RateLimitRequest = {}): Promise<RateLimitResponse> {
    const permits = clampPermits(options.permits);
    const ratePerSecond = clampRate(options.ratePerSecond);
    const burst = clampBurst(options.burst);

    return this.sql.begin(async (txRaw) => {
      const tx = txRaw as unknown as Sql;
      await tx`SET LOCAL statement_timeout = '5s'`;

      await tx`
        INSERT INTO rate_limit_keys (bucket_key, tokens, last_refill_at)
        VALUES (${bucketKey}, ${burst}, now())
        ON CONFLICT (bucket_key) DO NOTHING
      `;

      const rows = await tx<BucketSnapshot[]>`
        SELECT tokens,
               EXTRACT(EPOCH FROM (now() - last_refill_at))::double precision AS elapsed_seconds
          FROM rate_limit_keys
         WHERE bucket_key = ${bucketKey}
           FOR UPDATE
      `;

      const snapshot = rows[0];
      if (!snapshot) {
        return { allowed: false, remaining: 0, retryAfterMs: 1000 };
      }
      const refilled = Math.min(
        burst,
        snapshot.tokens + Math.max(0, snapshot.elapsed_seconds) * ratePerSecond,
      );
      return decide(tx, 'key', bucketKey, refilled, permits, ratePerSecond);
    });
  }
}

function clampPermits(permits?: number): number {
  return Math.max(1, Math.min(permits ?? 1, 100));
}
function clampRate(rate?: number): number {
  return Math.max(0.1, rate ?? DEFAULT_RATE_PER_SECOND);
}
function clampBurst(burst?: number): number {
  return Math.max(1, burst ?? DEFAULT_BURST);
}

/**
 * Client helper used by the payment executor. Kept as a free function with the same
 * shape so the call site reads cleanly.
 */
export async function acquirePermit(
  limiter: PostgresRateLimiter,
  organizationId: string,
  options: RateLimitRequest = {},
): Promise<RateLimitResponse> {
  return limiter.acquire(organizationId, options);
}
