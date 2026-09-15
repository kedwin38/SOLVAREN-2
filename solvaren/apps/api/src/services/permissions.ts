/**
 * Permission resolution: load the organization's dynamic permission policy and compute
 * the effective matrix (baseline ∪ grants − revokes − ceilings).
 *
 * The matrix is loaded fresh on every request in `requireAuth` — a permission L3 revoked
 * a minute ago is refused on the next request, not at next login. Overrides are few, so
 * the query is cheap.
 */

import {
  effectivePermissions,
  type AuthorityLevel,
  type EffectiveMatrix,
  type Permission,
  type PermissionOverride,
} from '@solvaren/core';
import type { Sql } from '../db/client.js';

interface OverrideRow {
  id: string;
  level: AuthorityLevel;
  permission: Permission;
  effect: 'GRANT' | 'REVOKE';
  version: number;
  reason: string;
  granted_by_user_id: string;
}

export async function loadEffectiveMatrix(sql: Sql, organizationId: string): Promise<EffectiveMatrix> {
  const rows = await sql<OverrideRow[]>`
    SELECT id, level, permission, effect, version, reason, granted_by_user_id
      FROM permission_overrides
     WHERE organization_id = ${organizationId}
       AND superseded_by_id IS NULL
       AND level IN ('L1', 'L2')
  `;

  const overrides: PermissionOverride[] = rows.map((r) => ({
    level: r.level,
    permission: r.permission,
    effect: r.effect,
    version: r.version,
    reason: r.reason,
    grantedByUserId: r.granted_by_user_id,
  }));

  return effectivePermissions(overrides);
}

/** The live override list for the admin screen and the audit trail. */
export async function listOverrides(
  sql: Sql,
  organizationId: string,
): Promise<(OverrideRow & { created_at: string; superseded: boolean })[]> {
  const rows = await sql<(OverrideRow & { created_at: string; superseded: boolean })[]>`
    SELECT id, level, permission, effect, version, reason, granted_by_user_id, created_at,
           (superseded_by_id IS NOT NULL) AS superseded
      FROM permission_overrides
     WHERE organization_id = ${organizationId}
     ORDER BY version DESC, created_at DESC
  `;
  return rows;
}
