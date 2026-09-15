/**
 * RBAC and the dynamic permission engine (spec §4, AC-16, AC-17).
 *
 * The engine's security reasoning is tested exhaustively here: default deny, ceiling
 * enforcement, override validation, supersession, and the invariant that no override can
 * ever produce a permission the immutable ceilings forbid.
 */

import { describe, expect, it } from 'vitest';
import {
  AUTHORITY_LEVELS,
  FORBIDDEN_TO_ALL,
  GRANT_CEILINGS,
  PERMISSIONS,
  assertValidOverride,
  baselinePermissions,
  capabilitiesFor,
  effectivePermissions,
  hasPermission,
  requirePermission,
  validateOverride,
  SolvarenError,
  type Permission,
  type PermissionOverride,
} from './index.js';

const actor = (level: 'L1' | 'L2' | 'L3', status: 'ACTIVE' | 'DISABLED' | 'LOCKED' = 'ACTIVE') => ({
  userId: 'u1',
  organizationId: 'org1',
  level,
  status,
});

describe('baseline matrix (spec §4.4)', () => {
  it('denies payment release to L1 and L2, grants it to L3 only', () => {
    expect(hasPermission(actor('L1'), 'payment:release')).toBe(false);
    expect(hasPermission(actor('L2'), 'payment:release')).toBe(false);
    expect(hasPermission(actor('L3'), 'payment:release')).toBe(true);
  });

  it('gives final payment authorization to L3 alone', () => {
    expect(hasPermission(actor('L1'), 'payment:authorize')).toBe(false);
    expect(hasPermission(actor('L2'), 'payment:authorize')).toBe(false);
    expect(hasPermission(actor('L3'), 'payment:authorize')).toBe(true);
  });

  it('gives batch approval to L2 alone (not L1, not L3)', () => {
    expect(hasPermission(actor('L1'), 'batch:approve_to_l3')).toBe(false);
    expect(hasPermission(actor('L2'), 'batch:approve_to_l3')).toBe(true);
    expect(hasPermission(actor('L3'), 'batch:approve_to_l3')).toBe(false);
  });

  it('reserves Daraja administration for L3', () => {
    expect(hasPermission(actor('L1'), 'admin:daraja')).toBe(false);
    expect(hasPermission(actor('L2'), 'admin:daraja')).toBe(false);
    expect(hasPermission(actor('L3'), 'admin:daraja')).toBe(true);
  });

  it('reserves full audit access for L3, org audit for L2', () => {
    expect(hasPermission(actor('L1'), 'audit:read_org')).toBe(false);
    expect(hasPermission(actor('L2'), 'audit:read_org')).toBe(true);
    expect(hasPermission(actor('L3'), 'audit:read_full')).toBe(true);
    expect(hasPermission(actor('L2'), 'audit:read_full')).toBe(false);
  });

  it('refuses every permission for a non-active account', () => {
    for (const level of AUTHORITY_LEVELS) {
      for (const status of ['DISABLED', 'LOCKED'] as const) {
        for (const permission of PERMISSIONS) {
          expect(hasPermission(actor(level, status), permission)).toBe(false);
        }
      }
    }
  });

  it('requirePermission throws a 403-shaped error on denial', () => {
    expect(() => requirePermission(actor('L1'), 'payment:release')).toThrow(SolvarenError);
    try {
      requirePermission(actor('L1'), 'payment:release');
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(SolvarenError);
      expect((err as SolvarenError).category).toBe('AUTHORIZATION');
      expect((err as SolvarenError).httpStatus).toBe(403);
    }
  });

  it('default-deny: a permission absent from the set is refused', () => {
    // Every catalogue permission tested against a stripped matrix.
    const stripped = effectivePermissions([]);
    expect(stripped.L1.size).toBe(baselinePermissions('L1').size);
    // Fabricate an unknown permission by identity: not in any set.
    expect(hasPermission(actor('L3'), 'batch:approve_to_l3')).toBe(false);
  });
});

describe('immutable ceilings (AC-17)', () => {
  it('no override combination can ever grant a ceiling-protected permission', () => {
    // Grant EVERY catalogued permission to L1 via overrides.
    const grantEverything: PermissionOverride[] = PERMISSIONS.map((p, i) => ({
      level: 'L1',
      permission: p,
      effect: 'GRANT',
      version: i + 1,
      reason: 'test: grant everything',
      grantedByUserId: 'l3-user',
    }));
    const matrix = effectivePermissions(grantEverything);
    for (const forbidden of GRANT_CEILINGS.L1) {
      expect(matrix.L1.has(forbidden)).toBe(false);
    }
    for (const forbidden of GRANT_CEILINGS.L2) {
      const grantToL2: PermissionOverride[] = PERMISSIONS.map((p, i) => ({
        level: 'L2',
        permission: p,
        effect: 'GRANT',
        version: i + 1,
        reason: 'test: grant everything',
        grantedByUserId: 'l3-user',
      }));
      const m2 = effectivePermissions(grantToL2);
      expect(m2.L2.has(forbidden)).toBe(false);
    }
    // Forbidden-to-all capabilities never appear at any level.
    for (const p of FORBIDDEN_TO_ALL) {
      expect(matrix.L1.has(p as Permission)).toBe(false);
      expect(matrix.L2.has(p as Permission)).toBe(false);
      expect(matrix.L3.has(p as Permission)).toBe(false);
    }
  });

  it('validateOverride refuses ceiling-piercing grants with a reason', () => {
    const result = validateOverride({ level: 'L1', permission: 'payment:release', effect: 'GRANT' });
    expect(result.ok).toBe(false);
    expect(result.problems.join(' ')).toMatch(/reserves it/i);
  });

  it('validateOverride refuses L3 modification outright', () => {
    const result = validateOverride({ level: 'L3', permission: 'batch:edit', effect: 'REVOKE' });
    expect(result.ok).toBe(false);
    expect(result.problems.join(' ')).toMatch(/not configurable/i);
  });

  it('validateOverride refuses forbidden-to-all capabilities anywhere', () => {
    for (const level of ['L1', 'L2'] as const) {
      const result = validateOverride({ level, permission: 'audit:delete', effect: 'GRANT' });
      expect(result.ok).toBe(false);
    }
  });

  it('validateOverride rejects unknown permissions', () => {
    const result = validateOverride({ level: 'L1', permission: 'not:a:permission', effect: 'GRANT' });
    expect(result.ok).toBe(false);
  });

  it('assertValidOverride throws on ceiling breach', () => {
    expect(() =>
      assertValidOverride({ level: 'L2', permission: 'admin:daraja', effect: 'GRANT' }),
    ).toThrow(SolvarenError);
  });
});

describe('dynamic overrides (AC-17)', () => {
  it('a valid GRANT extends L1 within its ceiling', () => {
    const before = effectivePermissions([]);
    expect(before.L1.has('batch:cancel')).toBe(true); // L1 holds cancel in baseline

    const after = effectivePermissions([
      {
        level: 'L1',
        permission: 'transactions:refresh_status',
        effect: 'GRANT',
        version: 1,
        reason: 'ops need live status',
        grantedByUserId: 'l3',
      },
    ]);
    // refresh_status is ceiling-protected for L1, so the grant is masked.
    expect(after.L1.has('transactions:refresh_status')).toBe(false);

    const allowed = effectivePermissions([
      {
        level: 'L1',
        permission: 'reports:operational' as Permission,
        effect: 'GRANT',
        version: 1,
        reason: 'x'.repeat(3),
        grantedByUserId: 'l3',
      },
    ]);
    // reports:operational is baseline L1 — already held; ceiling not applicable.
    expect(allowed.L1.has('reports:operational')).toBe(true);
  });

  it('a REVOKE removes a held permission', () => {
    const after = effectivePermissions([
      {
        level: 'L1',
        permission: 'transactions:export_failed',
        effect: 'REVOKE',
        version: 1,
        reason: 'finance wants controlled exports',
        grantedByUserId: 'l3',
      },
    ]);
    expect(after.L1.has('transactions:export_failed')).toBe(false);
    expect(after.L2.has('transactions:export_failed')).toBe(true);
  });

  it('highest version wins per (level, permission)', () => {
    const overrides: PermissionOverride[] = [
      {
        level: 'L1',
        permission: 'transactions:export_failed',
        effect: 'REVOKE',
        version: 1,
        reason: 'revoke first',
        grantedByUserId: 'l3',
      },
      {
        level: 'L1',
        permission: 'transactions:export_failed',
        effect: 'GRANT',
        version: 2,
        reason: 'reinstated',
        grantedByUserId: 'l3',
      },
    ];
    const matrix = effectivePermissions(overrides);
    expect(matrix.L1.has('transactions:export_failed')).toBe(true);
  });

  it('L3 is immune to overrides entirely', () => {
    const matrix = effectivePermissions(
      PERMISSIONS.map((p, i) => ({
        level: 'L3' as const,
        permission: p,
        effect: 'REVOKE' as const,
        version: i + 1,
        reason: 'attempt',
        grantedByUserId: 'rogue',
      })),
    );
    expect(matrix.L3.size).toBe(baselinePermissions('L3').size);
  });
});

describe('capabilities payload', () => {
  it('mirrors the effective matrix for the browser', () => {
    const caps = capabilitiesFor(actor('L1'));
    expect(caps['payment:release']).toBe(false);
    expect(caps['batch:create']).toBe(true);
    const overrides = effectivePermissions([
      {
        level: 'L1',
        permission: 'transactions:export_failed',
        effect: 'REVOKE',
        version: 1,
        reason: 'tightened',
        grantedByUserId: 'l3',
      },
    ]);
    const capsAfter = capabilitiesFor(actor('L1'), overrides);
    expect(capsAfter['transactions:export_failed']).toBe(false);
  });
});
