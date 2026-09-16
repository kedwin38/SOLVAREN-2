/**
 * Authority levels, the permission catalogue, the baseline matrix, and the **dynamic
 * permission engine** with immutable ceilings (spec §4, AC-16, AC-17).
 *
 * Design, in one paragraph: the baseline matrix is code — pure, versioned, exhaustively
 * tested. On top of it, a Level 3 administrator may grant or revoke specific L1/L2
 * capabilities at runtime (persisted as versioned `permission_overrides` rows). The
 * effective set is computed as: (baseline ∪ grants) − revokes − **ceilings**. Ceilings
 * are immutable constraints that no override can cross — not by API, not by database
 * seed, not by a future code change that forgets the rule, because `effectivePermissions`
 * applies them last and `validateOverride` refuses to store an override that would be
 * masked by one. The default state of a fresh install is exactly the baseline matrix.
 *
 * The engine is pure: overrides in, effective sets out. Persistence and audit live in
 * the API layer; the security reasoning lives here where it can be tested exhaustively.
 */

import { authorizationError, validationError } from './errors.js';

export const AUTHORITY_LEVELS = ['L1', 'L2', 'L3'] as const;
export type AuthorityLevel = (typeof AUTHORITY_LEVELS)[number];

export const LEVEL_TITLES: Record<AuthorityLevel, string> = {
  L1: 'Payment Operations',
  L2: 'Finance Control & Review',
  L3: 'Chief / Executive Payment Authority',
};

// ---------------------------------------------------------------------------
// The permission catalogue
// ---------------------------------------------------------------------------

export const PERMISSIONS = [
  // Recipients & organisation data
  'recipients:read',
  'recipients:write',
  'departments:read',
  'departments:write',
  // Batch lifecycle
  'batch:create',
  'batch:edit',
  'batch:validate',
  'batch:read',
  'batch:submit_to_l2',
  'batch:review',
  'batch:approve_to_l3',
  'batch:reject',
  'batch:hold',
  'batch:cancel',
  'batch:release_hold',
  // Payment authorization & release — L3 only, ceiling-protected
  'payment:authorize',
  'payment:release',
  // Transactions (§ record-keeping)
  'transactions:read',
  'transactions:export_failed',
  'transactions:export_all',
  'transactions:refresh_status',
  'transactions:retry',
  // Reconciliation
  'reconciliation:read',
  'reconciliation:resolve',
  // Executive dashboard
  'dashboard:balance_panel',
  'dashboard:recent_transactions_panel',
  // Analytics & AI
  'analytics:basic',
  'analytics:advanced',
  'analytics:executive',
  'ai:batch_analysis',
  'ai:financial_analysis',
  'ai:executive_intelligence',
  // Reports
  'reports:operational',
  'reports:management',
  'reports:executive',
  // Administration
  'admin:users',
  'admin:policies',
  'admin:permissions',
  'admin:security',
  'admin:daraja',
  'admin:backups',
  'admin:templates',
  // Audit
  'audit:read_own_scope',
  'audit:read_org',
  'audit:read_full',
  // Queue diagnostics (operators need to see stuck jobs)
  'ops:queue_read',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

const PERMISSION_SET: ReadonlySet<string> = new Set(PERMISSIONS);

// ---------------------------------------------------------------------------
// Baseline matrix (spec §4.4) — default deny: absent means refused
// ---------------------------------------------------------------------------

const BASELINE: Record<AuthorityLevel, ReadonlySet<Permission>> = {
  L1: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:read',
    'batch:submit_to_l2',
    'batch:cancel',
    'transactions:read',
    'transactions:export_failed', // org policy may tighten — see canExportFailedTransactions
    'transactions:retry', // policy-limited at the handler
    'reconciliation:read',
    'analytics:basic',
    'ai:batch_analysis',
    'reports:operational',
    'audit:read_own_scope',
    'ops:queue_read',
  ]),
  L2: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'departments:write',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:read',
    'batch:review',
    'batch:approve_to_l3',
    'batch:reject',
    'batch:hold',
    'batch:release_hold',
    'transactions:read',
    'transactions:export_failed',
    'transactions:export_all',
    'transactions:refresh_status',
    'transactions:retry',
    'reconciliation:read',
    'reconciliation:resolve',
    'analytics:basic',
    'analytics:advanced',
    'ai:batch_analysis',
    'ai:financial_analysis',
    'reports:operational',
    'reports:management',
    'audit:read_own_scope',
    'audit:read_org',
    'ops:queue_read',
  ]),
  L3: new Set<Permission>([
    'recipients:read',
    'recipients:write',
    'departments:read',
    'departments:write',
    'batch:create',
    'batch:edit',
    'batch:validate',
    'batch:submit_to_l2',
    'batch:read',
    'batch:review',
    'batch:reject',
    'batch:hold',
    'batch:cancel',
    'batch:release_hold',
    'payment:authorize',
    'payment:release',
    'transactions:read',
    'transactions:export_failed',
    'transactions:export_all',
    'transactions:refresh_status',
    'transactions:retry',
    'reconciliation:read',
    'reconciliation:resolve',
    'dashboard:balance_panel',
    'dashboard:recent_transactions_panel',
    'analytics:basic',
    'analytics:advanced',
    'analytics:executive',
    'ai:batch_analysis',
    'ai:financial_analysis',
    'ai:executive_intelligence',
    'reports:operational',
    'reports:management',
    'reports:executive',
    'admin:users',
    'admin:policies',
    'admin:permissions',
    'admin:security',
    'admin:daraja',
    'admin:backups',
    'admin:templates',
    'audit:read_own_scope',
    'audit:read_org',
    'audit:read_full',
    'ops:queue_read',
  ]),
};

export function baselinePermissions(level: AuthorityLevel): ReadonlySet<Permission> {
  return BASELINE[level];
}

// ---------------------------------------------------------------------------
// Immutable ceilings (AC-17)
// ---------------------------------------------------------------------------

/**
 * Capabilities that **no level may ever hold**. They exist so that granting one — by a
 * future code change, a seeded row, or a compromised administrator — fails a test and is
 * refused by the engine rather than quietly becoming reachable.
 */
export const FORBIDDEN_TO_ALL = [
  'audit:delete',
  'transactions:alter_history',
  'transactions:force_status',
  'daraja:view_plaintext_secret',
  'batch:self_approve',
] as const;
export type ForbiddenCapability = (typeof FORBIDDEN_TO_ALL)[number];

/**
 * Ceiling per level: permissions an override can never grant to that level, because the
 * specification marks them as exclusive to a higher authority or to nobody.
 *
 *   - L1 may never hold anything on the payment release path, Daraja administration,
 *     user/policy/security administration, advanced analytics or full audit.
 *   - L2 may never hold anything on payment release or Daraja administration — L2 review
 *     and L3 authorization must remain two hands.
 *   - L3 is the ceiling itself; nothing above it exists.
 */
export const GRANT_CEILINGS: Record<AuthorityLevel, readonly Permission[]> = {
  L1: [
    'payment:authorize',
    'payment:release',
    'batch:approve_to_l3',
    'batch:review',
    'admin:users',
    'admin:policies',
    'admin:permissions',
    'admin:security',
    'admin:daraja',
    'admin:backups',
    'admin:templates',
    'analytics:advanced',
    'analytics:executive',
    'ai:financial_analysis',
    'ai:executive_intelligence',
    'reports:management',
    'reports:executive',
    'audit:read_org',
    'audit:read_full',
    'transactions:export_all',
    'transactions:refresh_status',
    'reconciliation:resolve',
  ],
  L2: [
    'payment:authorize',
    'payment:release',
    'admin:daraja',
    'admin:backups',
    'admin:permissions',
    'admin:templates',
    'analytics:executive',
    'ai:executive_intelligence',
    'reports:executive',
    'audit:read_full',
  ],
  L3: [],
};

// ---------------------------------------------------------------------------
// Overrides
// ---------------------------------------------------------------------------

export interface PermissionOverride {
  level: AuthorityLevel;
  permission: Permission;
  effect: 'GRANT' | 'REVOKE';
  /** Monotonic policy version this override belongs to. */
  version: number;
  reason: string;
  grantedByUserId: string;
}

export interface OverrideValidation {
  ok: boolean;
  problems: string[];
}

/**
 * Validate an override **before** it is persisted.
 *
 * Refuses: unknown permissions, FORBIDDEN_TO_ALL anywhere, grants that would pierce a
 * ceiling, and revokes of permissions the level does not hold (a no-op that would only
 * muddy the audit trail). L3 is not overridable at all: its authority is the constitution,
 * not a setting.
 */
export function validateOverride(input: {
  level: AuthorityLevel;
  permission: string;
  effect: 'GRANT' | 'REVOKE';
}): OverrideValidation {
  const problems: string[] = [];

  if (!PERMISSION_SET.has(input.permission)) {
    problems.push(`"${input.permission}" is not a permission SOLVAREN knows`);
    return { ok: false, problems };
  }
  const permission = input.permission as Permission;

  if ((FORBIDDEN_TO_ALL as readonly string[]).includes(permission)) {
    problems.push(`"${permission}" is forbidden to every level; it cannot be granted or revoked`);
  }
  if (input.level === 'L3') {
    problems.push('Level 3 authority is not configurable; overrides apply to L1 and L2 only');
  }
  if (input.effect === 'GRANT' && GRANT_CEILINGS[input.level].includes(permission)) {
    problems.push(
      `"${permission}" cannot be granted to ${input.level}: the specification reserves it ` +
        (input.level === 'L1' ? 'for Finance Control or executive authority' : 'for executive authority only'),
    );
  }
  if (
    input.effect === 'REVOKE' &&
    !BASELINE[input.level].has(permission) &&
    !problems.length
  ) {
    // Revoking something not held is a no-op; we only reject it when it is not also a
    // ceiling breach, which would already be listed above.
    problems.push(`${input.level} does not currently hold "${permission}"; there is nothing to revoke`);
  }

  return { ok: problems.length === 0, problems };
}

/**
 * Compute the effective permission sets for all levels under a set of overrides.
 *
 * Order of application — ceilings last, so they cannot be argued away:
 *   effective(level) = ((baseline(level) ∪ grants) − revokes) − ceilings(level) − forbidden
 */
export function effectivePermissions(
  overrides: readonly PermissionOverride[],
): Record<AuthorityLevel, ReadonlySet<Permission>> {
  const sets: Record<AuthorityLevel, Set<Permission>> = {
    L1: new Set(BASELINE.L1),
    L2: new Set(BASELINE.L2),
    L3: new Set(BASELINE.L3),
  };

  // Highest version wins per (level, permission); ties broken by array order (last wins).
  const byKey = new Map<string, PermissionOverride>();
  for (const o of overrides) {
    byKey.set(`${o.level}::${o.permission}`, o);
  }
  const ordered = [...byKey.values()].sort((a, b) => a.version - b.version);
  for (const o of ordered) {
    if (o.level === 'L3') continue; // constitution, not configuration
    if (o.effect === 'GRANT') sets[o.level].add(o.permission);
    else sets[o.level].delete(o.permission);
  }

  // Ceilings and forbidden capabilities are applied unconditionally, after everything.
  for (const level of AUTHORITY_LEVELS) {
    for (const p of GRANT_CEILINGS[level]) sets[level].delete(p);
    for (const p of FORBIDDEN_TO_ALL) sets[level].delete(p as Permission);
  }

  return sets;
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export interface Actor {
  userId: string;
  organizationId: string;
  level: AuthorityLevel;
  status: 'ACTIVE' | 'DISABLED' | 'LOCKED' | 'PENDING_ENROLMENT';
}

/** Effective permission sets for an organization, as computed by `effectivePermissions`. */
export type EffectiveMatrix = Record<AuthorityLevel, ReadonlySet<Permission>>;

const IDENTITY_MATRIX: EffectiveMatrix = {
  L1: BASELINE.L1,
  L2: BASELINE.L2,
  L3: BASELINE.L3,
};

export function effectivePermissionsOf(actor: Pick<Actor, 'level'>, matrix: EffectiveMatrix = IDENTITY_MATRIX): ReadonlySet<Permission> {
  return matrix[actor.level];
}

/** Pure predicate — safe for UI capability payloads and tests. */
export function hasPermission(
  actor: Pick<Actor, 'level' | 'status'>,
  permission: Permission,
  matrix: EffectiveMatrix = IDENTITY_MATRIX,
): boolean {
  if (actor.status !== 'ACTIVE') return false;
  return matrix[actor.level].has(permission);
}

/** Enforcement helper used by every privileged handler. Throws 403 on denial. */
export function requirePermission(
  actor: Actor,
  permission: Permission,
  matrix: EffectiveMatrix = IDENTITY_MATRIX,
): void {
  if (actor.status !== 'ACTIVE') {
    throw authorizationError('ACTOR_NOT_ACTIVE', 'This account is not active', {
      status: actor.status,
    });
  }
  if (!matrix[actor.level].has(permission)) {
    throw authorizationError('PERMISSION_DENIED', `${LEVEL_TITLES[actor.level]} may not perform this action`, {
      permission,
      level: actor.level,
    });
  }
}

/** Organization scoping — reported as not-found so a cross-tenant id is not an oracle. */
export function requireSameOrganization(actor: Actor, objectOrganizationId: string): void {
  if (actor.organizationId !== objectOrganizationId) {
    throw authorizationError('CROSS_ORGANIZATION_DENIED', 'Object not found in this organization');
  }
}

/** Failed-export policy: L1 access is organization-configurable (spec §4.4). */
export function canExportFailedTransactions(
  actor: Pick<Actor, 'level' | 'status'>,
  policy: { allowL1FailedExport: boolean },
  matrix: EffectiveMatrix = IDENTITY_MATRIX,
): boolean {
  if (!hasPermission(actor, 'transactions:export_failed', matrix)) return false;
  if (actor.level === 'L1') return policy.allowL1FailedExport;
  return true;
}

/** The capability payload sent to the browser — a courtesy, never a control. */
export function capabilitiesFor(
  actor: Pick<Actor, 'level' | 'status'>,
  matrix: EffectiveMatrix = IDENTITY_MATRIX,
): Record<Permission, boolean> {
  const out = {} as Record<Permission, boolean>;
  for (const p of PERMISSIONS) out[p] = hasPermission(actor, p, matrix);
  return out;
}

/** Human-readable diff of what an override policy change does — for the audit trail. */
export function describeOverrideChange(
  overrides: readonly PermissionOverride[],
): { level: AuthorityLevel; permission: Permission; effect: string; reason: string }[] {
  const effective = new Map<string, PermissionOverride>();
  for (const o of overrides) effective.set(`${o.level}::${o.permission}`, o);
  return [...effective.values()]
    .sort((a, b) => a.level.localeCompare(b.level) || a.permission.localeCompare(b.permission))
    .map((o) => ({ level: o.level, permission: o.permission, effect: o.effect, reason: o.reason }));
}

/** Guard used by the override API: every proposed change must validate or nothing stores. */
export function assertValidOverride(input: {
  level: AuthorityLevel;
  permission: string;
  effect: 'GRANT' | 'REVOKE';
}): void {
  const result = validateOverride(input);
  if (!result.ok) {
    throw validationError('PERMISSION_OVERRIDE_INVALID', result.problems.join('; '), {
      problems: result.problems,
    });
  }
}
