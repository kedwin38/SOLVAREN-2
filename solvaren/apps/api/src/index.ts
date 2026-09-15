/**
 * SOLVAREN API application assembly.
 *
 * Route groups follow the spec §18 API surface. The health endpoints are deliberately
 * boring, the callback group is the only session-less ingress (it authenticates by
 * path-embedded shared secret), and everything else sits behind `requireAuth` with the
 * effective permission matrix loaded per request.
 */

import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import {
  requestContext,
  securityHeaders,
  cors,
  errorHandler,
  limitBodySize,
} from './middleware/security.js';
import { authRoutes } from './routes/auth.js';
import { batchRoutes } from './routes/batches.js';
import { transactionRoutes, exportRoutes } from './routes/transactions.js';
import { authorizationRoutes } from './routes/authorization.js';
import { analyticsRoutes } from './routes/analytics.js';
import { adminRoutes } from './routes/admin.js';
import { aiRoutes } from './routes/ai.js';
import { securityRoutes } from './routes/security.js';
import {
  directoryRoutes,
  departmentRoutes,
  reconciliationRoutes,
} from './routes/directory.js';
import { reportRoutes } from './routes/reports.js';
import { callbackRoutes } from './routes/callbacks.js';
import type { AppContext } from './env.js';

export const app = new Hono<AppContext>();

// ---------------------------------------------------------------------------
// Global middleware. Order matters: context first so every later layer and the
// error handler can reach the correlation id.
// ---------------------------------------------------------------------------
app.use('*', requestContext);
app.use('*', securityHeaders);
app.use('*', cors);
// A generous default; the CSV upload route raises its own limit, and the auth routes
// lower theirs.
app.use('*', limitBodySize(1024 * 1024));

app.onError((err, c) => errorHandler(err, c));

app.notFound((c) =>
  c.json(
    {
      error: {
        code: 'ROUTE_NOT_FOUND',
        category: 'NOT_FOUND',
        message: 'That endpoint does not exist',
        correlationId: c.get('correlationId'),
      },
    },
    404,
  ),
);

// ---------------------------------------------------------------------------
// Health (Railway deployment health, spec §17.5)
// ---------------------------------------------------------------------------

/** Liveness. Deliberately reveals nothing about version, tenancy or configuration. */
app.get('/health', (c) => c.json({ status: 'ok' }));

/** Readiness, including database reachability. */
app.get('/health/ready', async (c) => {
  const started = Date.now();
  try {
    await c.env.sql`SELECT 1`;
    return c.json({ status: 'ready', databaseLatencyMs: Date.now() - started });
  } catch {
    // The error text is not echoed: a connection string can appear in a driver message.
    return c.json({ status: 'degraded', reason: 'database unreachable' }, 503);
  }
});

// ---------------------------------------------------------------------------
// Route groups (spec §18)
// ---------------------------------------------------------------------------
app.route('/api/auth', authRoutes);
app.route('/api/payment-batches', batchRoutes);
app.route('/api/transactions', transactionRoutes);
app.route('/api/exports', exportRoutes);
app.route('/api/approvals', authorizationRoutes);
app.route('/api/analytics', analyticsRoutes);
app.route('/api/admin', adminRoutes);
app.route('/api/ai', aiRoutes);
app.route('/api/security', securityRoutes);
app.route('/api/recipients', directoryRoutes);
app.route('/api/departments', departmentRoutes);
app.route('/api/reconciliation', reconciliationRoutes);
app.route('/api/reports', reportRoutes);

// The only route group that does not require a session; it authenticates by the shared
// secret embedded in its URL (spec §9.4).
app.route('/api/daraja', callbackRoutes);

// ---------------------------------------------------------------------------
// Console (single-service deployments).
//
// When the image carries the built console under ./console, this process serves it on
// the same origin as the API. Same-origin removes the CORS surface entirely and gives
// WebAuthn a single RP domain. The SPA fallback serves index.html for every non-API
// path so hash routing works on first load.
// ---------------------------------------------------------------------------
app.use('*', serveStatic({ root: './console' }));
app.get('*', serveStatic({ path: './console/index.html' }));
