/**
 * Request security middleware (spec §4 HARD CONTROL, §21).
 *
 * `requireAuth` and `requirePermissions` sit in front of every privileged route, and the
 * effective permission matrix — baseline plus any dynamic L3 overrides minus the
 * immutable ceilings — is loaded per request, so a permission revoked a minute ago is
 * refused on the very next call.
 *
 * IP capture targets the Direct Connection IP (REMOTE_ADDR): the address of whatever
 * actually opened the TCP connection to the edge in front of this service — the user's
 * ISP gateway, home router or corporate firewall — not a value a client can assert about
 * itself. Concretely, that means trusting only a header the edge itself sets and a client
 * cannot overwrite:
 *   - Railway (this platform's default edge) sets `X-Real-IP` to the true connecting
 *     peer and does not forward a client-supplied `X-Forwarded-For` unmodified — Railway
 *     never documents X-Forwarded-For as a trustworthy signal, so it is never trusted as
 *     a primary source here.
 *   - Cloudflare's `CF-Connecting-IP` is equally authoritative, but only when Cloudflare
 *     is verified to be the sole ingress (the optional edge/WAF layer, spec §deployment);
 *     trusting it unconditionally would let any direct caller who bypasses Cloudflare
 *     forge their own IP, so it is honoured only when `TRUST_CF_CONNECTING_IP=true`.
 *   - `X-Forwarded-For` (rightmost non-private hop) is kept only as a last-resort
 *     fallback for deployments behind some other reverse proxy, never above the two
 *     edge-authoritative headers above.
 */

import type { MiddlewareHandler } from 'hono';
import {
  SolvarenError,
  authenticationError,
  authorizationError,
  requirePermission,
  correlationId as newCorrelationId,
  redactForAudit,
  rateLimitError,
  type Permission,
} from '@solvaren/core';
import { resolveSession, toActor, type AuthenticatedActor } from '../services/auth.js';
import { loadEffectiveMatrix } from '../services/permissions.js';
import { withConnection } from '../db/client.js';
import type { AppContext } from '../env.js';

const PRIVATE_IP =
  /^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|::1$|fc00:|fe80:|0\.0\.0\.0$)/;

/**
 * Direct Connection IP (REMOTE_ADDR): the edge-authoritative signal only.
 *
 * `trustCfConnectingIp` must come from verified deployment configuration
 * (`TRUST_CF_CONNECTING_IP`), never inferred from the presence of the header itself —
 * a client can send `CF-Connecting-IP` on any request, so its mere presence proves
 * nothing about whether Cloudflare actually sits in front.
 */
export function clientIpOf(headers: Headers, trustCfConnectingIp = false): string | null {
  const real = headers.get('X-Real-IP');
  if (real && isPlausibleIp(real)) return real;

  if (trustCfConnectingIp) {
    const cf = headers.get('CF-Connecting-IP');
    if (cf && isPlausibleIp(cf)) return cf;
  }

  // Last-resort fallback for a reverse proxy topology other than Railway's edge or a
  // verified Cloudflare front — not authoritative, so untrusted client-injected entries
  // are dropped by walking from the right and skipping anything private/reserved.
  const forwarded = headers.get('X-Forwarded-For');
  if (forwarded) {
    const parts = forwarded.split(',').map((p) => p.trim()).filter(Boolean);
    for (let i = parts.length - 1; i >= 0; i--) {
      const candidate = parts[i]!;
      if (isPlausibleIp(candidate) && !PRIVATE_IP.test(candidate)) return candidate;
    }
  }

  return null;
}

function isPlausibleIp(value: string): boolean {
  return /^[0-9a-fA-F:.]{3,45}$/.test(value);
}

/** Attach a correlation id and the security context to every request. */
export const requestContext: MiddlewareHandler<AppContext> = async (c, next) => {
  // Honour an inbound correlation id only if it looks like ours; otherwise a caller
  // could poison the audit trail by supplying arbitrary text.
  const inbound = c.req.header('X-Correlation-Id');
  const correlationId =
    inbound && /^cor_[A-Z0-9]{20}$/.test(inbound) ? inbound : newCorrelationId();

  c.set('correlationId', correlationId);
  c.set('securityContext', {
    ip: clientIpOf(c.req.raw.headers, c.env.TRUST_CF_CONNECTING_IP),
    userAgent: c.req.header('User-Agent')?.slice(0, 512) ?? null,
    country: c.req.header('CF-IPCountry') ?? null,
    deviceFingerprint: c.req.header('X-Solvaren-Device')?.slice(0, 200) ?? null,
  });

  c.header('X-Correlation-Id', correlationId);
  await next();
};

/**
 * Security response headers.
 *
 * Path-aware because one process may serve both surfaces (single-service deployments):
 *   - `/api/*` and `/health*` get the strict API CSP — `default-src 'none'` — because
 *     these responses carry financial data and are consumed by code, not rendered.
 *   - everything else is the console (SPA) and gets the console CSP: same-origin
 *     scripts/styles, `publickey-credentials-get` for WebAuthn, and long-lived caching
 *     only for hashed assets (the shell itself is never cached).
 */
const API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const CONSOLE_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
  "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; " +
  "object-src 'none'";

export const securityHeaders: MiddlewareHandler<AppContext> = async (c, next) => {
  await next();
  const path = new URL(c.req.url).pathname;
  const isApiSurface = path.startsWith('/api') || path.startsWith('/health');

  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Referrer-Policy', 'no-referrer');
  c.header('Cross-Origin-Opener-Policy', 'same-origin');
  c.header('Cross-Origin-Resource-Policy', 'same-origin');
  c.header(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()' +
      (isApiSurface ? '' : ', publickey-credentials-get=(self)'),
  );
  c.header('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  c.header('Content-Security-Policy', isApiSurface ? API_CSP : CONSOLE_CSP);

  if (isApiSurface) {
    // Financial data must never be cached by an intermediary or left in a shared browser.
    c.header('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    c.header('Pragma', 'no-cache');
  } else if (path.startsWith('/assets/')) {
    // Hashed console assets are immutable by construction.
    c.header('Cache-Control', 'public, max-age=31536000, immutable');
  } else if (!path.startsWith('/api')) {
    // The console shell is never cached: a stale bundle against a new API is how a
    // release ceremony breaks halfway through.
    c.header('Cache-Control', 'no-store, must-revalidate');
  }
};

/** Strict same-origin CORS. The API serves exactly one browser origin. */
export const cors: MiddlewareHandler<AppContext> = async (c, next) => {
  const origin = c.req.header('Origin');
  const allowed = c.env?.APP_ORIGIN;

  if (origin && allowed && origin === allowed) {
    c.header('Access-Control-Allow-Origin', allowed);
    c.header('Access-Control-Allow-Credentials', 'true');
    c.header('Vary', 'Origin');
  }

  if (c.req.method === 'OPTIONS') {
    c.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    c.header(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization, Idempotency-Key, X-Correlation-Id, X-Solvaren-Device',
    );
    c.header('Access-Control-Max-Age', '600');
    return c.body(null, 204);
  }

  await next();
};

/**
 * Authenticate the request and load the effective permission matrix.
 *
 * The bearer token is read from the Authorization header rather than a cookie so that
 * cross-site request forgery is structurally impossible: a browser will not attach it
 * to a request originating from another site.
 */
export const requireAuth: MiddlewareHandler<AppContext> = async (c, next) => {
  const header = c.req.header('Authorization');
  if (!header?.startsWith('Bearer ')) {
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }
  const token = header.slice(7).trim();
  if (token.length < 20 || token.length > 200) {
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }

  const actor = await withConnection(c.env, (sql) =>
    resolveSession(sql, c.env.SESSION_SIGNING_KEY, token),
  );
  c.set('actor', actor);

  // The effective matrix is loaded per request: a dynamic permission change L3 made a
  // minute ago is refused (or granted) on the very next call, not at next login.
  const matrix = await withConnection(c.env, (sql) =>
    loadEffectiveMatrix(sql, actor.organizationId),
  );
  c.set('permissionMatrix', matrix);

  await next();
};

/** Read the authenticated actor, or fail loudly if a route forgot `requireAuth`. */
export function actorOf(c: {
  get: (key: 'actor') => AppContext['Variables']['actor'];
}): AuthenticatedActor {
  const actor = c.get('actor');
  if (!actor) {
    // A programming error, not a user error: the route is misconfigured.
    throw authenticationError('AUTHENTICATION_REQUIRED', 'Sign in to continue');
  }
  return actor;
}

/**
 * Enforce one or more permissions against the effective matrix.
 *
 * Every permission must be held — there is no "any of" variant, because a route that
 * would accept either of two permissions is really two routes with different authority
 * and should be written as such.
 */
export function requirePermissions(...permissions: Permission[]): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const actor = actorOf(c);
    const matrix = c.get('permissionMatrix');
    for (const permission of permissions) {
      requirePermission(toActor(actor), permission, matrix);
    }
    await next();
  };
}

/**
 * Restrict a route to an exact authority level. Used for the executive panels and the
 * Daraja administration, where the requirement is "L3 and nobody else".
 */
export function requireExactLevel(level: 'L1' | 'L2' | 'L3'): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const actor = actorOf(c);
    if (actor.level !== level) {
      throw authorizationError(
        'LEVEL_RESTRICTED',
        `This information is available to ${level} authority only`,
        { requiredLevel: level, actorLevel: actor.level },
      );
    }
    await next();
  };
}

/**
 * Rate-limit an endpoint. Keying is 'actor' (per signed-in user) or 'ip' (per source
 * address, for unauthenticated endpoints like login and the callback ingress).
 */
export function rateLimit(
  scope: 'actor' | 'ip',
  options: { ratePerSecond: number; burst: number },
): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    if (scope === 'actor') {
      const actor = c.get('actor');
      if (!actor) {
        await next();
        return;
      }
      const decision = await c.env.rateLimiter.acquireKey(`actor:${actor.userId}`, options);
      if (!decision.allowed) {
        throw rateLimitError('RATE_LIMITED', 'Too many requests. Wait a moment and try again.', {
          retryAfterMs: decision.retryAfterMs,
        });
      }
    } else {
      const security = c.get('securityContext');
      const ip = security?.ip;
      if (!ip) {
        // No IP to key on (direct connection without proxy headers): fall back to a
        // global bucket so the limit still exists.
        const decision = await c.env.rateLimiter.acquireKey('ip:global', options);
        if (!decision.allowed) {
          throw rateLimitError('RATE_LIMITED', 'Too many requests. Wait a moment and try again.', {
            retryAfterMs: decision.retryAfterMs,
          });
        }
      } else {
        const decision = await c.env.rateLimiter.acquireKey(`ip:${ip}`, options);
        if (!decision.allowed) {
          throw rateLimitError('RATE_LIMITED', 'Too many requests. Wait a moment and try again.', {
            retryAfterMs: decision.retryAfterMs,
          });
        }
      }
    }
    await next();
  };
}

/**
 * Central error handler.
 *
 * Two properties matter. First, an unexpected exception becomes a generic 500 with a
 * correlation id rather than a stack trace — an internal message can name a table, a
 * query, or a secret. Second, error details are redacted on the way out, so a
 * `SolvarenError` carrying request context in `details` cannot leak credential material.
 */
export function errorHandler(
  err: Error,
  c: {
    get: (k: 'correlationId') => string;
    json: (body: unknown, status?: number) => Response;
  },
) {
  const correlationId = c.get('correlationId');

  if (err instanceof SolvarenError) {
    return c.json(
      {
        error: {
          code: err.code,
          category: err.category,
          message: err.message,
          details: redactForAudit(err.details),
          correlationId,
        },
      },
      err.httpStatus,
    );
  }

  // Zod validation failures arrive as ZodError; surface the field paths but not the
  // values, since a rejected payload can contain a password or a PIN.
  if (err.name === 'ZodError') {
    const issues = (err as unknown as { issues: { path: (string | number)[]; message: string }[] })
      .issues;
    return c.json(
      {
        error: {
          code: 'REQUEST_INVALID',
          category: 'VALIDATION',
          message: 'The request was not valid',
          details: { fields: issues.map((i) => ({ path: i.path.join('.'), message: i.message })) },
          correlationId,
        },
      },
      422,
    );
  }

  console.error(
    JSON.stringify({
      level: 'error',
      correlationId,
      message: err.message,
      name: err.name,
      // The stack goes to the server log, never to the client.
      stack: err.stack?.split('\n').slice(0, 6).join('\n'),
    }),
  );

  return c.json(
    {
      error: {
        code: 'INTERNAL_ERROR',
        category: 'INTERNAL',
        message: 'Something went wrong handling this request. Quote the correlation id to support.',
        details: {},
        correlationId,
      },
    },
    500,
  );
}

/**
 * Body size limit, applied before parsing — the denial-of-service risk is in the parse,
 * not the handler. CSV uploads raise their own larger limit in the batch routes.
 */
export function limitBodySize(maxBytes: number): MiddlewareHandler<AppContext> {
  return async (c, next) => {
    const declared = c.req.header('Content-Length');
    if (declared && Number(declared) > maxBytes) {
      throw new SolvarenError(
        'VALIDATION',
        'PAYLOAD_TOO_LARGE',
        `The request body exceeds the ${Math.floor(maxBytes / 1024)} KB limit for this endpoint`,
      );
    }
    await next();
  };
}
