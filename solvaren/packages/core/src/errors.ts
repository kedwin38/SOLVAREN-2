/**
 * The error taxonomy of SOLVAREN.
 *
 * Every error that crosses an API boundary is a `SolvarenError` carrying a stable machine
 * code, a category that determines HTTP status, and a message written for the person
 * reading it. Internal details (stacks, SQL, driver messages) never travel in the payload.
 *
 * The category is the single source of truth for HTTP status — handlers do not choose.
 */

export type ErrorCategory =
  | 'VALIDATION' // 422 — the request was malformed
  | 'AUTHENTICATION' // 401 — who are you?
  | 'AUTHORIZATION' // 403 — you may not do this
  | 'NOT_FOUND' // 404 — scoped out of existence on purpose
  | 'STATE' // 409 — the object is not in a state that permits this
  | 'POLICY' // 403 — organization policy refuses
  | 'PROVIDER' // 502 — M-PESA said no, or said nothing
  | 'RATE_LIMIT' // 429 — too fast
  | 'CONFLICT' // 409 — concurrent modification
  | 'INTERNAL'; // 500 — our fault, opaque by design

const CATEGORY_STATUS: Record<ErrorCategory, number> = {
  VALIDATION: 422,
  AUTHENTICATION: 401,
  AUTHORIZATION: 403,
  NOT_FOUND: 404,
  STATE: 409,
  POLICY: 403,
  PROVIDER: 502,
  RATE_LIMIT: 429,
  CONFLICT: 409,
  INTERNAL: 500,
};

export class SolvarenError extends Error {
  readonly code: string;
  readonly category: ErrorCategory;
  /** Redacted before it ever leaves the process (`redactForAudit`). */
  readonly details: Record<string, unknown>;

  constructor(
    category: ErrorCategory,
    code: string,
    message: string,
    details: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'SolvarenError';
    this.category = category;
    this.code = code;
    this.details = details;
  }

  get httpStatus(): number {
    return CATEGORY_STATUS[this.category];
  }
}

export function validationError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('VALIDATION', code, message, details);
}
export function authenticationError(
  code: string,
  message: string,
  details?: Record<string, unknown>,
) {
  return new SolvarenError('AUTHENTICATION', code, message, details);
}
export function authorizationError(
  code: string,
  message: string,
  details?: Record<string, unknown>,
) {
  return new SolvarenError('AUTHORIZATION', code, message, details);
}
export function notFoundError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('NOT_FOUND', code, message, details);
}
export function stateError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('STATE', code, message, details);
}
export function policyError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('POLICY', code, message, details);
}
export function providerError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('PROVIDER', code, message, details);
}
export function rateLimitError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('RATE_LIMIT', code, message, details);
}
export function conflictError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('CONFLICT', code, message, details);
}
export function internalError(code: string, message: string, details?: Record<string, unknown>) {
  return new SolvarenError('INTERNAL', code, message, details);
}

/** True when two errors carry the same code and category — used by tests. */
export function sameErrorCode(a: unknown, b: unknown): boolean {
  return (
    a instanceof SolvarenError && b instanceof SolvarenError && a.code === b.code
  );
}
