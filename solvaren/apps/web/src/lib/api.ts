/**
 * API client.
 *
 * Deliberately small and explicit. Three properties matter:
 *
 *  - **The session token is held in memory, not in localStorage.** A token in
 *    localStorage survives the tab and is readable by any script that gets injected; a
 *    token in a module-scoped variable dies with the tab, which is the correct lifetime
 *    for a payment console. The cost is re-authenticating after a refresh — the right
 *    trade for this application.
 *  - **Errors keep their server shape.** The API returns a code, a message written for
 *    the person reading it, and a correlation id. The client preserves all three rather
 *    than collapsing them into "Something went wrong", because "Batch edited since
 *    approval — re-review required" is actionable and a generic message is not.
 *  - **Capabilities are advisory.** The UI uses them to decide what to render; the
 *    server decides what is permitted against the live matrix. A stale capability set
 *    can only produce a 403, never an unauthorised action.
 */

import type { Permission } from '@solvaren/core';

export interface ApiErrorShape {
  code: string;
  category: string;
  message: string;
  details?: Record<string, unknown>;
  correlationId?: string;
}

export class ApiError extends Error {
  readonly code: string;
  readonly category: string;
  readonly status: number;
  readonly details: Record<string, unknown>;
  readonly correlationId: string | null;

  constructor(status: number, shape: ApiErrorShape) {
    super(shape.message);
    this.name = 'ApiError';
    this.status = status;
    this.code = shape.code;
    this.category = shape.category;
    this.details = shape.details ?? {};
    this.correlationId = shape.correlationId ?? null;
  }

  /** True when confirming identity again (step-up) would resolve it. */
  get requiresStepUp(): boolean {
    return this.code === 'STEP_UP_REQUIRED';
  }

  /** True when signing in again would resolve it. */
  get requiresReauthentication(): boolean {
    return this.status === 401 && !this.requiresStepUp;
  }
}

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api';

let sessionToken: string | null = null;

/** A stable per-browser device identifier, used for trusted-device binding (spec §8.1). */
function deviceId(): string {
  const key = 'solvaren.device';
  try {
    let existing = localStorage.getItem(key);
    if (!existing) {
      existing = crypto.randomUUID();
      localStorage.setItem(key, existing);
    }
    return existing;
  } catch {
    // Private browsing or blocked storage: fall back to a per-tab identifier. The device
    // simply will not be remembered as trusted, which is a safe degradation.
    return 'ephemeral';
  }
}

export function setSessionToken(token: string | null): void {
  sessionToken = token;
}

export function hasSession(): boolean {
  return sessionToken !== null;
}

/**
 * Global passkey step-up (spec §8.2), wired by App.
 *
 * When a privileged operation hits the freshness gate, the request layer runs the
 * registered handler — App shows the passkey prompt, performs the ceremony and returns
 * whether identity was confirmed. If it was, the original request is retried once,
 * transparently to the calling page: the operator confirms with their passkey and the
 * operation completes. No logout, no re-login, no password.
 */
let stepUpHandler: (() => Promise<boolean>) | null = null;
let stepUpInFlight: Promise<boolean> | null = null;

export function setStepUpHandler(handler: (() => Promise<boolean>) | null): void {
  stepUpHandler = handler;
}

async function runStepUp(): Promise<boolean> {
  if (!stepUpHandler) return false;
  if (!stepUpInFlight) {
    stepUpInFlight = stepUpHandler().finally(() => {
      stepUpInFlight = null;
    });
  }
  return stepUpInFlight;
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  /** Required on mutating payment endpoints. */
  idempotencyKey?: string;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Solvaren-Device': deviceId(),
  };
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey;

  const doFetch = () =>
    fetch(`${API_BASE}${path}`, {
      method: options.method ?? 'GET',
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
      // The token travels in a header, so no cookies and therefore no CSRF surface.
      credentials: 'omit',
    });

  let response = await doFetch();

  // A freshness-gated operation (or one that needs a WebAuthn-verified session) is
  // rescued inline: confirm with the passkey, then retry once. The step-up endpoints
  // themselves never trigger this — they are how the handler fulfils it.
  if (
    response.status === 401 &&
    !path.startsWith('/auth/step-up') &&
    stepUpHandler !== null
  ) {
    const text = await response.text();
    let payload: unknown = null;
    try {
      payload = text ? JSON.parse(text) : null;
    } catch {
      payload = null;
    }
    const code = (payload as { error?: ApiErrorShape } | null)?.error?.code;
    if (code === 'STEP_UP_REQUIRED' || code === 'WEBAUTHN_REQUIRED') {
      if (await runStepUp()) {
        response = await doFetch();
        return consumeResponse<T>(response);
      }
    }
    // Cancelled or failed step-up: fall through so the original error reaches the caller.
    return consumeResponseFromText<T>(response.status, text);
  }

  if (response.status === 204) return undefined as T;

  return consumeResponse<T>(response);
}

async function consumeResponse<T>(response: Response): Promise<T> {
  if (response.status === 204) return undefined as T;
  return consumeResponseFromText<T>(response.status, await response.text());
}

async function consumeResponseFromText<T>(status: number, text: string): Promise<T> {
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }

  if (status < 200 || status >= 300) {
    const shape = (payload as { error?: ApiErrorShape } | null)?.error;
    throw new ApiError(
      status,
      shape ?? {
        code: 'UNEXPECTED_RESPONSE',
        category: 'INTERNAL',
        message: `The server returned ${status}.`,
      },
    );
  }

  return payload as T;
}

/** Upload a file (CSV) with the session header. */
async function upload(path: string, file: File): Promise<unknown> {
  const form = new FormData();
  form.append('file', file);
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: {
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      'X-Solvaren-Device': deviceId(),
    },
    body: form,
    credentials: 'omit',
  });
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const shape = (payload as { error?: ApiErrorShape } | null)?.error;
    throw new ApiError(response.status, shape ?? { code: 'UPLOAD_FAILED', category: 'INTERNAL', message: 'The upload failed.' });
  }
  return payload;
}

/** Download a generated file, preserving the server-supplied filename. */
export async function downloadCsv(
  path: string,
): Promise<{ blob: Blob; filename: string; truncated: boolean }> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      Accept: 'text/csv',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
      'X-Solvaren-Device': deviceId(),
    },
    credentials: 'omit',
  });

  if (!response.ok) {
    const text = await response.text();
    let shape: ApiErrorShape | undefined;
    try {
      shape = (JSON.parse(text) as { error?: ApiErrorShape }).error;
    } catch {
      /* not a JSON error body */
    }
    throw new ApiError(
      response.status,
      shape ?? {
        code: 'EXPORT_FAILED',
        category: 'INTERNAL',
        message: 'The export could not be generated.',
      },
    );
  }

  const disposition = response.headers.get('Content-Disposition') ?? '';
  const match = disposition.match(/filename="([^"]+)"/);
  return {
    blob: await response.blob(),
    filename: match?.[1] ?? 'export.csv',
    truncated: response.headers.get('X-Solvaren-Row-Truncated') === 'true',
  };
}

// ---------------------------------------------------------------------------
// Response shapes (mirrors of the API's)
// ---------------------------------------------------------------------------

export interface SessionResponse {
  user: {
    userId: string;
    email: string;
    fullName: string;
    level: 'L1' | 'L2' | 'L3';
    levelTitle: string;
    organizationId: string;
  };
  session: {
    authenticatedAt: string;
    webauthnVerified: boolean;
    trustedDeviceId: string | null;
    sessionId: string;
  };
  capabilities: Record<Permission, boolean>;
}

export type TransactionStatus =
  | 'PENDING' | 'SUBMITTED' | 'AWAITING_CALLBACK' | 'PROCESSING' | 'RECONCILING'
  | 'SUCCESS' | 'FAILED' | 'TIMEOUT' | 'CANCELLED';

export interface TransactionRow {
  transactionId: string;
  instructionId: string;
  batchId: string;
  batchReference: string;
  recipientId: string;
  recipientName: string;
  msisdn: string;
  departmentId: string | null;
  departmentName: string | null;
  role: string | null;
  territory: string | null;
  region: string | null;
  salesCount: number | null;
  amountCents: number;
  status: TransactionStatus;
  statusTone: 'success' | 'danger' | 'warning' | 'info' | 'neutral';
  failureCode: string | null;
  failureReason: string | null;
  failureClass: string | null;
  operatorAction: string | null;
  providerResultDescription: string | null;
  mpesaReceiptNumber: string | null;
  conversationId: string | null;
  originatorConversationId: string | null;
  statusSource: string | null;
  lastStatusCheckAt: string | null;
  createdAt: string;
  submittedAt: string | null;
  completedAt: string | null;
  updatedAt: string;
  retryEligible: boolean;
}

export interface ExplorerResponse {
  transactions: TransactionRow[];
  page: { page: number; pageSize: number; totalRows: number; totalPages: number; hasNext: boolean; hasPrevious: boolean };
  filter: { text: string; parts: string[] };
}

export interface OperationalDashboard {
  batchesByState: Record<string, number>;
  workflows: { awaitingL2Review: number; awaitingL3Authorization: number; onHold: number };
  transactions: { total: number; success: number; failed: number; timeout: number; inFlight: number; successRate: number | null; failureRate: number | null };
  processingSeconds: { median: number | null; p95: number | null };
  dailyTrend: { day: string; total: number; failed: number }[];
  needsAttention: { failed: number; timeout: number; reconciling: number };
}

export interface BalancePanel {
  accounts: { accountType: string; currency: string; availableCents: number; unclearedCents: number; reservedCents: number; asOf: string; source: string }[];
  asOf: string | null;
  awaitingRefresh: boolean;
  note: string | null;
}

export interface RiskSignalView {
  type: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  summary: string;
  evidence: Record<string, unknown>;
  instructionIds: string[];
}

export interface CeremonyResponse {
  challengeId: string;
  challengeHash: string;
  webauthnChallenge: string;
  expiresAt: string;
  manifest: {
    manifestHash: string;
    batchReference: string;
    recipientCount: number;
    totalAmountCents: number;
    approvalId: string;
    batchVersion: number;
    policyDigest: string;
  };
  acknowledgementsRequired: string[];
  risk: { score: number; band: string; signals: RiskSignalView[]; requiresAcknowledgement: boolean };
  confirmation: { headline: string; batchReference: string; manifestDigestShort: string; warning: string };
}

export interface BatchSummary {
  batchId: string;
  batchReference: string;
  state: string;
  purpose: string;
  createdAt: string;
  instructionCount: number;
  totalAmountCents: number;
  outcomes: { success: number; failed: number; timeout: number; inFlight: number };
}

export interface BatchDetail {
  batch: {
    batchId: string;
    batchReference: string;
    purpose: string;
    state: string;
    version: number;
    instructionCount: number;
    totalAmountCents: number;
    createdAt: string;
    createdBy: string;
    submittedAt: string | null;
    approvedAt: string | null;
    authorizedAt: string | null;
    riskScore: number | null;
    riskBand: string | null;
    editable: boolean;
    availableCommands: string[];
  };
  instructions: {
    rows: {
      instructionId: string; recipientName: string; msisdn: string; amountCents: number;
      status: string; sourceLineNumber: number | null;
      role: string | null; territory: string | null; region: string | null; salesCount: number | null;
    }[];
    offset: number;
    limit: number;
    total: number;
  };
  approvals: { approval_reference: string; action: string; actor_level: string; actor_name: string; reason: string | null; batch_version: number; created_at: string }[];
  riskFindings: (RiskSignalView & { disposition: string; currentVersion: boolean })[];
}

export interface BackupConfigurationView {
  configurationId: string;
  providerLabel: string;
  bucket: string;
  pathPrefix: string | null;
  region: string | null;
  endpoint: string | null;
  accessKeyMasked: string;
  secretKeyMasked: string;
  encryptionMode: string;
  status: string;
  lastTestAt: string | null;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
  scheduleEnabled: boolean;
  scheduleLocalTime: string;
  scheduleTimezone: string;
  retentionMaxCount: number | null;
  lastScheduledRunAt: string | null;
  nextScheduledRunAt: string | null;
  suspended: boolean;
  suspensionReason: string | null;
  consecutiveFailures: number;
}

export interface BackupAttemptView {
  attemptReference: string;
  trigger: string;
  status: string;
  startedAt: string | null;
  endedAt: string | null;
  sizeBytes: number | null;
  checksum: string | null;
  errorMessage: string | null;
  retentionDeletedCount: number | null;
  retentionComplete: boolean | null;
}

export interface NotificationView {
  id: string;
  severity: 'INFO' | 'WARNING' | 'CRITICAL';
  title: string;
  body: string;
  link_path: string | null;
  created_at: string;
}

export interface MinimalWebAuthnOptions {
  challenge: string;
  rpId?: string;
  allowCredentials?: { id: string; type: 'public-key' }[];
  userVerification?: string;
  timeout?: number;
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<
        | { stage: 'AUTHENTICATED'; token: string; expiresAt: string; user: SessionResponse['user'] & { authorizationPinEnrolled: boolean } }
        | { stage: 'WEBAUTHN_REQUIRED'; ticket: string; options: MinimalWebAuthnOptions; level: string }
        | { stage: 'ENROLMENT_REQUIRED'; token: string; expiresAt: string; level: string }
      >('/auth/login', { method: 'POST', body: { email, password, deviceId: deviceId() } }),

    completeWebAuthn: (ticket: string, response: unknown) =>
      request<{
        stage: 'AUTHENTICATED';
        token: string;
        expiresAt: string;
        user: SessionResponse['user'] & { authorizationPinEnrolled: boolean };
      }>('/auth/webauthn/authenticate', {
        method: 'POST',
        body: { ticket, response, deviceId: deviceId() },
      }),

    /** Step-up, phase 1: fetch a passkey challenge bound to this session. */
    stepUpOptions: () =>
      request<MinimalWebAuthnOptions & { ticket: string }>('/auth/step-up/options', {
        method: 'POST',
        body: {},
      }),

    /** Step-up, phase 2: confirm with the passkey assertion; refreshes the session in place. */
    stepUp: (ticket: string, response: unknown) =>
      request<{ steppedUp: boolean; authenticatedAt: string }>('/auth/step-up', {
        method: 'POST',
        body: { ticket, response },
      }),

    webauthnRegisterOptions: () =>
      request<MinimalWebAuthnOptions & { user?: { name: string; displayName: string } }>(
        '/auth/webauthn/register/options',
        { method: 'POST' },
      ),

    webauthnRegister: (response: unknown, friendlyName?: string) =>
      request<{ registered: boolean; credentialId: string; authorizationPinEnrolled: boolean }>('/auth/webauthn/register', {
        method: 'POST',
        body: { response, ...(friendlyName ? { friendlyName } : {}) },
      }),

    setAuthorizationPin: (currentPassword: string, pin: string) =>
      request<{ updated: boolean }>('/auth/authorization-pin', {
        method: 'POST',
        body: { currentPassword, pin },
      }),

    recoveryCodes: (currentPassword: string) =>
      request<{ codes: string[]; note: string }>('/auth/recovery-codes', {
        method: 'POST',
        body: { currentPassword },
      }),

    recoveryRedeem: (email: string, password: string, recoveryCode: string) =>
      request<{ recovered: boolean; token: string; expiresAt: string; nextStep: string }>(
        '/auth/recovery/redeem',
        { method: 'POST', body: { email, password, recoveryCode } },
      ),

    session: () => request<SessionResponse>('/auth/session'),
    logout: () => request<{ signedOut: boolean }>('/auth/logout', { method: 'POST' }),
    logoutAll: () => request<{ sessionsRevoked: number }>('/auth/logout-all', { method: 'POST' }),
  },

  batches: {
    create: (purpose: string, paymentPeriod?: string, departmentId?: string) =>
      request<{ batchId: string; batchReference: string; state: string }>('/payment-batches', {
        method: 'POST',
        body: { purpose, ...(paymentPeriod ? { paymentPeriod } : {}), ...(departmentId ? { departmentId } : {}) },
      }),

    upload: (batchId: string, file: File) => upload(`/payment-batches/${batchId}/upload`, file),

    validate: (batchId: string) =>
      request<{ state: string; risk: { score: number; band: string; signals: RiskSignalView[] } }>(
        `/payment-batches/${batchId}/validate`,
        { method: 'POST' },
      ),

    submit: (batchId: string) =>
      request<{ state: string; batchVersion: number }>(`/payment-batches/${batchId}/submit`, { method: 'POST' }),

    approve: (batchId: string, reason: string | undefined, acknowledgeFindings: boolean) =>
      request<{ state: string; approvalReference: string; batchVersion: number }>(
        `/payment-batches/${batchId}/approve`,
        { method: 'POST', body: { reason, acknowledgeFindings } },
      ),

    reject: (batchId: string, reason: string) =>
      request<{ state: string }>(`/payment-batches/${batchId}/reject`, { method: 'POST', body: { reason } }),

    returnToL1: (batchId: string, reason: string) =>
      request<{ state: string }>(`/payment-batches/${batchId}/return`, { method: 'POST', body: { reason } }),

    hold: (batchId: string, reason?: string) =>
      request<{ state: string }>(`/payment-batches/${batchId}/hold`, { method: 'POST', body: { ...(reason ? { reason } : {}) } }),

    releaseHold: (batchId: string, reason?: string) =>
      request<{ state: string }>(`/payment-batches/${batchId}/release-hold`, { method: 'POST', body: { ...(reason ? { reason } : {}) } }),

    cancel: (batchId: string, reason: string) =>
      request<{ state: string }>(`/payment-batches/${batchId}/cancel`, { method: 'POST', body: { reason } }),

    list: (state?: string, limit = 100, offset = 0) =>
      request<{ batches: BatchSummary[] }>(
        `/payment-batches?${new URLSearchParams({ ...(state ? { state } : {}), limit: String(limit), offset: String(offset) })}`,
      ),

    detail: (batchId: string, instructionOffset = 0, instructionLimit = 500) =>
      request<BatchDetail>(
        `/payment-batches/${batchId}?instructionOffset=${instructionOffset}&instructionLimit=${instructionLimit}`,
      ),
  },

  authorization: {
    begin: (batchId: string) =>
      request<CeremonyResponse>(`/approvals/batches/${batchId}/begin`, { method: 'POST' }),

    release: (
      batchId: string,
      payload: {
        challengeId: string;
        webauthnResponse: unknown;
        authorizationPin: string;
        acknowledgements: string[];
      },
    ) =>
      request<{
        released: boolean;
        batchReference: string;
        instructionsQueued: number;
        totalAmountCents: number;
        manifestHash: string;
        releasedAt: string;
        message: string;
      }>(`/approvals/batches/${batchId}/release`, {
        method: 'POST',
        body: payload,
        // A double-clicked release button must not open a second attempt.
        idempotencyKey: crypto.randomUUID() + crypto.randomUUID(),
      }),

    abandon: (batchId: string, reason?: string) =>
      request<{ abandoned: boolean; state: string }>(`/approvals/batches/${batchId}/abandon`, {
        method: 'POST',
        body: { ...(reason ? { reason } : {}) },
      }),
  },

  transactions: {
    list: (params: URLSearchParams, signal?: AbortSignal) =>
      request<ExplorerResponse>(`/transactions/transactions?${params.toString()}`, { signal }),

    detail: (id: string) =>
      request<{
        transaction: TransactionRow;
        activity: { action: string; outcome: string; occurred_at: string; actor_id: string; detail: unknown }[];
        reconciliationCases: { case_reference: string; state: string; opened_reason: string; discrepancy: boolean; query_attempts: number }[];
      }>(`/transactions/transactions/${id}`),

    refresh: (id: string) =>
      request<{ accepted: boolean; message: string }>(`/transactions/transactions/${id}/refresh`, { method: 'POST' }),

    retry: (id: string) =>
      request<{ retried: boolean; correctionBatchId: string; correctionBatchReference: string; newInstructionId: string; message: string }>(
        `/transactions/transactions/${id}/retry`,
        { method: 'POST' },
      ),

    failureSummary: (batchId?: string) =>
      request<{
        failures: { failureCode: string; failureReason: string; failureClass: string; operatorAction: string; count: number; totalCents: number }[];
      }>(`/transactions/failure-summary${batchId ? `?batchId=${batchId}` : ''}`),

    rollup: (batchId: string) =>
      request<{
        batchReference: string; state: string; instructionCount: number; totalAmountCents: number;
        successCount: number; failedCount: number; timeoutCount: number; inFlightCount: number;
        disbursedCents: number; failedCents: number;
      }>(`/transactions/batches/${batchId}/rollup`),
  },

  exports: {
    failedTransactions: (params: URLSearchParams) =>
      downloadCsv(`/exports/transactions/failed?${params.toString()}`),
  },

  analytics: {
    operational: () => request<OperationalDashboard>('/analytics/operational'),
    financial: () =>
      request<{
        departmentExpenditure: { departmentName: string; periodMonth: string; paidCents: number; paidCount: number; failedCount: number }[];
        payrollCycles: { periodMonth: string; totalCents: number; recipientCount: number }[];
        openFindingsBySeverity: Record<string, number>;
        reconciliationByState: Record<string, number>;
        forecast: { nextCycleCents: number | null; basis: string; method: string };
      }>('/analytics/financial'),
    balance: () => request<BalancePanel>('/analytics/executive/balance'),
    refreshBalance: () => request<{ accepted: boolean; message: string }>('/analytics/executive/balance/refresh', { method: 'POST' }),
    recentTransactions: () =>
      request<{
        transactions: { transactionId: string; status: string; amountCents: number; recipientName: string; msisdn: string; mpesaReceiptNumber: string | null; batchReference: string; failureReason: string | null; at: string }[];
      }>('/analytics/executive/recent-transactions'),
    briefing: () =>
      request<{
        monthlyDisbursement: { period: string; totalCents: number; transactionCount: number }[];
        monthOverMonth: { currentCents: number; previousCents: number; changePercent: number | null; largestMover: { departmentName: string; deltaCents: number } | null };
        risk: { openFindings: number; reviewedFindings: number };
        unresolvedReconciliationCases: number;
      }>('/analytics/executive/briefing'),
  },

  recipients: {
    list: (search?: string, status?: string, limit = 100, offset = 0) =>
      request<{
        recipients: {
          recipientId: string; fullName: string; msisdn: string; departmentName: string | null;
          externalReference: string | null; status: string; notes: string | null; createdAt: string;
          paymentCount: number; meanAmountCents: number;
          role: string | null; territory: string | null; region: string | null;
        }[];
        total: number;
      }>(`/recipients/recipients?${new URLSearchParams({ ...(search ? { search } : {}), ...(status ? { status } : {}), limit: String(limit), offset: String(offset) })}`),

    create: (body: {
      fullName: string; msisdn: string; externalReference?: string; departmentId?: string;
      role?: string; territory?: string; region?: string;
    }) =>
      request<{ recipientId: string }>('/recipients/recipients', { method: 'POST', body }),

    update: (id: string, body: {
      fullName?: string; msisdn?: string; status?: 'ACTIVE' | 'INACTIVE' | 'BLOCKED';
      role?: string | null; territory?: string | null; region?: string | null;
    }) =>
      request<{ updated: boolean }>(`/recipients/recipients/${id}`, { method: 'PATCH', body }),

    history: (id: string) =>
      request<{
        recipient: { recipientId: string; fullName: string; msisdnMasked: string };
        history: { batchReference: string; amountCents: number; status: string; failureCode: string | null; mpesaReceipt: string | null; completedAt: string | null }[];
      }>(`/recipients/recipients/${id}/history`),
  },

  departments: {
    list: () =>
      request<{ departments: { departmentId: string; name: string; status: string; recipientCount: number }[] }>('/departments'),
    create: (name: string) => request<{ departmentId: string }>('/departments', { method: 'POST', body: { name } }),
  },

  reconciliation: {
    list: (state?: string) =>
      request<{
        cases: {
          caseId: string; caseReference: string; state: string; openedReason: string; discrepancy: boolean;
          queryAttempts: number; openedAt: string; resolvedAt: string | null; resolutionNote: string | null;
          transactionId: string; batchReference: string | null; recipientName: string | null; amountCents: number | null; transactionStatus: string | null;
        }[];
      }>(`/reconciliation${state ? `?state=${state}` : ''}`),

    resolve: (caseId: string, outcome: 'RESOLVED_MANUAL' | 'RESOLVED_SUCCESS' | 'RESOLVED_FAILED', note: string, portalReceipt?: string) =>
      request<{ resolved: boolean }>(`/reconciliation/${caseId}/resolve`, {
        method: 'POST',
        body: { outcome, note, ...(portalReceipt ? { portalReceipt } : {}) },
      }),
  },

  reports: {
    catalogue: () =>
      request<{
        reports: { family: string; title: string; description: string; requiredPermission: string; available: boolean; supportsDateRange: boolean }[];
      }>('/reports/catalogue'),

    request: (family: string, filters: { dateFrom?: string; dateTo?: string }) =>
      request<{ reportJobId: string; message: string }>('/reports', { method: 'POST', body: { family, ...filters } }),

    history: () =>
      request<{ jobs: { reportJobId: string; family: string; status: string; rowCount: number | null; errorMessage: string | null; requestedAt: string; completedAt: string | null }[] }>('/reports/history'),

    download: (id: string) => downloadCsv(`/reports/${id}/download`),
  },

  ai: {
    analyseBatch: (batchId: string) =>
      request<{ deterministicFindings: { signal_type: string; severity: string; summary: string }[]; riskScore: number | null; riskBand: string | null; narrative: string | null; degraded: boolean; advisoryNotice: string }>(
        `/ai/batches/${batchId}/analyse`,
        { method: 'POST' },
      ),

    explainFailure: (transactionId: string) =>
      request<{ failureCode: string; failureReason: string; failureClass: string; operatorAction: string; narrative: string | null }>(
        '/ai/failures/explain',
        { method: 'POST', body: { transactionId } },
      ),

    briefing: () =>
      request<{ briefing: string | null; degraded: boolean; figures: Record<string, unknown>; advisoryNotice: string }>('/ai/briefing', {
        method: 'POST',
      }),
  },

  admin: {
    users: {
      list: () =>
        request<{ users: { userId: string; email: string; fullName: string; level: string; status: string; lastLoginAt: string | null; createdAt: string; activeSessions: number; webauthnCredentials: number }[] }>('/admin/users'),
      create: (body: { email: string; fullName: string; authorityLevel: 'L1' | 'L2' | 'L3'; temporaryPassword: string; authorizationPin?: string }) =>
        request<{ userId: string; nextStep: string }>('/admin/users', { method: 'POST', body }),
      update: (id: string, body: { status?: 'ACTIVE' | 'DISABLED'; authorityLevel?: 'L1' | 'L2' | 'L3'; resetPassword?: string; unlock?: boolean; revokeSessions?: boolean }) =>
        request<{ updated: boolean }>(`/admin/users/${id}`, { method: 'PATCH', body }),
      adminRecovery: (id: string, reason: string, authorizationPin: string) =>
        request<{ recovered: boolean; nextStep: string }>(`/admin/users/${id}/admin-recovery`, {
          method: 'POST',
          body: { reason, authorizationPin },
        }),
    },

    daraja: {
      list: () =>
        request<{ configurations: BackupConfigurationView[] }>('/admin/daraja'), // shape reused: masked views
      configure: (body: {
        environment: 'sandbox' | 'production';
        shortCode: string;
        initiatorName: string;
        commandId?: string;
        consumerKey: string;
        consumerSecret: string;
        initiatorPasswordOrCredential: string;
        mpesaCertificatePem?: string;
        authorizationPin: string;
      }) =>
        request<{
          configuration: unknown;
          callbackSecret: string;
          callbackUrls: { resultUrl: string; queueTimeoutUrl: string; statusResultUrl: string; balanceResultUrl: string };
          nextStep: string;
        }>('/admin/daraja', { method: 'POST', body }),
      test: (configId: string) => request<{ ok: boolean; message: string; latencyMs: number }>(`/admin/daraja/${configId}/test`, { method: 'POST' }),
      testPayment: (configId: string, body: { msisdn: string; amountKes: number; authorizationPin: string }) =>
        request<{
          transactionId: string;
          originatorConversationId: string;
          status: string;
          msisdn: string;
          amountCents: number;
          failure: { code: string; message: string } | null;
          note?: string;
        }>(`/admin/daraja/${configId}/test-payment`, { method: 'POST', body }),
      testPaymentStatus: (configId: string, transactionId: string) =>
        request<{
          transactionId: string;
          status: string;
          terminal: boolean;
          receipt: string | null;
          conversationId: string | null;
          originatorConversationId: string;
          failureCode: string | null;
          failureReason: string | null;
          providerDescription: string | null;
          submittedAt: string | null;
          completedAt: string | null;
          lastStatusCheckAt: string | null;
          statusSource: string | null;
        }>(`/admin/daraja/${configId}/test-payment/${transactionId}`),
      testPaymentRefresh: (configId: string, transactionId: string) =>
        request<{ queued: boolean; note: string }>(`/admin/daraja/${configId}/test-payment/${transactionId}/refresh`, { method: 'POST' }),
      edit: (configId: string, body: { shortCode?: string; initiatorName?: string; commandId?: 'BusinessPayment' | 'SalaryPayment' | 'PromotionPayment'; authorizationPin: string }) =>
        request<{ configuration: unknown; note: string }>(`/admin/daraja/${configId}`, { method: 'PATCH', body }),
      remove: (configId: string, body: { reason: string; authorizationPin: string }) =>
        request<{ deleted: boolean; note: string }>(`/admin/daraja/${configId}`, { method: 'DELETE', body }),
      enable: (configId: string) => request<{ status: string }>(`/admin/daraja/${configId}/enable`, { method: 'POST' }),
      disable: (configId: string, reason: string) => request<{ status: string; note: string }>(`/admin/daraja/${configId}/disable`, { method: 'POST', body: { reason } }),
    },

    ai: {
      get: () =>
        request<{
          configuration: {
            provider: 'anthropic' | 'openai-compatible';
            baseUrl: string;
            model: string;
            apiKeyMasked: string;
            status: string;
            lastTestAt: string | null;
            lastTestOk: boolean | null;
            lastTestMessage: string | null;
          } | null;
          platformDefault: { provider: string; model: string; note: string } | null;
        }>('/admin/ai'),
      configure: (body: { provider: 'anthropic' | 'openai-compatible'; baseUrl: string; model: string; apiKey: string; authorizationPin: string }) =>
        request<{ configured: boolean; note: string }>('/admin/ai', { method: 'PUT', body }),
      test: () => request<{ ok: boolean; message: string; latencyMs: number; sample: string | null }>('/admin/ai/test', { method: 'POST' }),
      remove: (body: { authorizationPin: string }) =>
        request<{ deleted: boolean; note: string }>('/admin/ai', { method: 'DELETE', body }),
    },

    backups: {
      overview: () =>
        request<{
          configuration: BackupConfigurationView | null;
          latestResult: BackupAttemptView | null;
          history: { attemptReference: string; trigger: string; status: string; startedAt: string | null; endedAt: string | null; sizeBytes: number | null; errorMessage: string | null; objectRetained: boolean }[];
          restoreValidationNote: string;
        }>('/admin/backups'),
      configure: (body: {
        providerLabel?: string; endpoint?: string; region?: string; bucket: string; pathPrefix?: string;
        accessKeyId: string; secretAccessKey: string; encryptionMode?: string; retentionMaxCount?: number;
      }) => request<{ configurationId: string; accessKeyMasked: string; nextStep: string }>('/admin/backups/target', { method: 'POST', body }),
      test: () => request<{ ok: boolean; message: string }>('/admin/backups/test', { method: 'POST' }),
      run: () => request<{ accepted: boolean; attemptReference: string; message: string }>('/admin/backups/run', { method: 'POST' }),
      schedule: (body: { enabled: boolean; localTime?: string; timezone?: string; retentionMaxCount?: number }) =>
        request<{ scheduleEnabled: boolean }>('/admin/backups/schedule', { method: 'PATCH', body }),
    },

    policies: {
      get: () => request<{ policy: Record<string, unknown> }>('/admin/policies'),
      update: (patch: Record<string, unknown>) => request<{ policy: Record<string, unknown> }>('/admin/policies', { method: 'PATCH', body: patch }),
    },

    permissions: {
      overview: () =>
        request<{
          baseline: Record<string, string[]>;
          effective: Record<string, string[]>;
          ceilings: Record<string, string[]>;
          overrides: { id: string; level: string; permission: string; effect: string; version: number; reason: string; createdAt: string; superseded: boolean }[];
          catalogue: string[];
        }>('/admin/permissions'),
      override: (body: { level: 'L1' | 'L2'; permission: string; effect: 'GRANT' | 'REVOKE'; reason: string }) =>
        request<{ applied: boolean; overrideId: string; policyVersion: number; note: string }>('/admin/permissions/overrides', { method: 'POST', body }),
      reset: (reason: string) => request<{ reset: boolean }>('/admin/permissions/reset', { method: 'POST', body: { reason } }),
    },

    templates: {
      list: () =>
        request<{ templates: { templateId: string; name: string; purpose: string; scheduleCron: string; scheduleEnabled: boolean; nextRunAt: string | null; lastMaterializedAt: string | null; itemCount: number }[] }>('/admin/templates'),
      setEnabled: (id: string, enabled: boolean) => request<{ scheduleEnabled: boolean }>(`/admin/templates/${id}`, { method: 'PATCH', body: { enabled } }),
    },
  },

  security: {
    devices: () =>
      request<{ devices: { deviceId: string; userName: string; friendlyName: string; trustStatus: string; firstSeenIp: string | null; lastSeenIp: string | null; userAgent: string | null; registeredAt: string; lastActivityAt: string; revoked: boolean }[] }>('/security/security/devices'),
    revokeDevice: (id: string, reason: string) => request<{ revoked: boolean }>(`/security/security/devices/${id}/revoke`, { method: 'POST', body: { reason } }),
    trustDevice: (id: string) => request<{ trusted: boolean }>(`/security/security/devices/${id}/trust`, { method: 'POST' }),
    events: (severity?: string) =>
      request<{ events: { eventId: string; eventType: string; severity: string; description: string; ip: string | null; createdAt: string; acknowledged: boolean; userName: string | null; detail: unknown }[] }>(
        `/security/security/events${severity ? `?severity=${severity}` : ''}`,
      ),
    acknowledgeEvent: (id: string) => request<{ acknowledged: boolean }>(`/security/security/events/${id}/acknowledge`, { method: 'POST' }),
    audit: (filters?: { eventClass?: string; objectId?: string; limit?: number }) => {
      const params = new URLSearchParams();
      if (filters?.eventClass) params.set('eventClass', filters.eventClass);
      if (filters?.objectId) params.set('objectId', filters.objectId);
      params.set('limit', String(filters?.limit ?? 100));
      return request<{ events: { event_reference: string; sequence: string; actor_id: string; event_class: string; action: string; object_type: string; object_id: string | null; outcome: string; occurred_at: string; detail: unknown }[] }>(
        `/security/security/audit?${params}`,
      );
    },
    verifyAuditChain: (fromSequence = 1, limit = 1000) =>
      request<{ valid: boolean; failedAtSequence: number | null; reason: string | null; verifiedCount: number; interpretation: string }>(
        '/security/security/audit/verify',
        { method: 'POST', body: { fromSequence, limit } },
      ),
    queue: () =>
      request<{
        summary: { queue: string; status: string; count: number; oldest: string | null }[];
        stuckJobs: { jobId: string; queue: string; status: string; attempts: number; maxAttempts: number; lastError: string | null; createdAt: string }[];
      }>('/security/ops/queue'),
    requeueJob: (jobId: string, reason: string) => request<{ requeued: boolean }>(`/security/ops/queue/${jobId}/requeue`, { method: 'POST', body: { reason } }),
  },

  notifications: {
    list: () => request<{ notifications: NotificationView[] }>('/security/notifications'),
    markRead: (id: string) => request<{ read: boolean }>(`/security/notifications/${id}/read`, { method: 'POST' }),
  },
};

/** Minimal browser WebAuthn helpers (no @simplewebauthn/browser dependency needed). */
export async function requestWebAuthnAssertion(options: MinimalWebAuthnOptions): Promise<unknown> {
  if (!window.PublicKeyCredential) {
    throw new ApiError(400, {
      code: 'WEBAUTHN_UNSUPPORTED',
      category: 'AUTHENTICATION',
      message: 'This browser does not support security keys. Use a modern browser with WebAuthn support.',
    });
  }

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlToBuffer(options.challenge),
      rpId: options.rpId,
      allowCredentials: (options.allowCredentials ?? []).map((c) => ({
        id: base64UrlToBuffer(c.id),
        type: c.type ?? 'public-key',
      })),
      userVerification: 'required',
      timeout: options.timeout ?? 120_000,
    },
  });

  return assertionToJson(credential as PublicKeyCredential);
}

export async function createWebAuthnRegistration(
  options: MinimalWebAuthnOptions & { user?: { name: string; displayName: string } },
): Promise<unknown> {
  if (!window.PublicKeyCredential) {
    throw new ApiError(400, {
      code: 'WEBAUTHN_UNSUPPORTED',
      category: 'AUTHENTICATION',
      message: 'This browser does not support security keys. Use a modern browser with WebAuthn support.',
    });
  }

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: base64UrlToBuffer(options.challenge),
      rp: { name: 'SOLVAREN Payment Solutions', id: options.rpId },
      user: {
        id: base64UrlToBuffer(crypto.randomUUID()),
        name: options.user?.name ?? 'solvaren-user',
        displayName: options.user?.displayName ?? 'SOLVAREN User',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -8 }, // EdDSA
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      timeout: 120_000,
      attestation: 'none',
    },
  });

  return registrationToJson(credential as PublicKeyCredential);
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function assertionToJson(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: {},
    response: {
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  };
}

function registrationToJson(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: {},
    response: {
      attestationObject: bufferToBase64Url(response.attestationObject),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    },
  };
}
