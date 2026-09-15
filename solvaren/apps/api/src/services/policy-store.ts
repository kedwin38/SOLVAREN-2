/**
 * Organisation policy loading (spec §21 Security/policies).
 *
 * Policy is read fresh on every release rather than cached: a limit an administrator
 * tightened five minutes ago must apply to the payroll being authorized now. The policy
 * digest is bound into the authorization manifest, so a policy change between the
 * opening and completion of a release ceremony invalidates that ceremony.
 */

import { sha256Hex, DEFAULT_POLICY, policySchema, policyDigestInput, type OrganizationPolicy } from '@solvaren/core';
import type { Sql } from '../db/client.js';

interface PolicyRow {
  max_instruction_amount_cents: string;
  max_batch_total_cents: string;
  max_batch_instructions: number;
  high_value_threshold_cents: string;
  cooling_off_seconds: number;
  blocking_risk_band: 'NEVER' | 'HIGH' | 'CRITICAL';
  allow_l1_failed_export: boolean;
  allow_l1_retry: boolean;
  max_export_rows: number;
  daily_disbursement_ceiling_cents: string;
  release_cutoff_local_time: string;
  holiday_dates: string[];
}

export async function loadPolicy(sql: Sql, organizationId: string): Promise<OrganizationPolicy> {
  const rows = await sql<PolicyRow[]>`
    SELECT max_instruction_amount_cents, max_batch_total_cents, max_batch_instructions,
           high_value_threshold_cents, cooling_off_seconds, blocking_risk_band,
           allow_l1_failed_export, allow_l1_retry, max_export_rows,
           daily_disbursement_ceiling_cents, release_cutoff_local_time, holiday_dates
      FROM policies
     WHERE organization_id = ${organizationId}
     LIMIT 1
  `;

  const row = rows[0];
  // An organisation with no policy row gets the platform defaults, which are the
  // conservative ones — never an absence of limits.
  if (!row) return DEFAULT_POLICY;

  return policySchema.parse({
    maxInstructionAmountCents: Number(row.max_instruction_amount_cents),
    maxBatchTotalCents: Number(row.max_batch_total_cents),
    maxBatchInstructions: row.max_batch_instructions,
    highValueThresholdCents: Number(row.high_value_threshold_cents),
    coolingOffSeconds: row.cooling_off_seconds,
    blockingRiskBand: row.blocking_risk_band,
    allowL1FailedExport: row.allow_l1_failed_export,
    allowL1Retry: row.allow_l1_retry,
    maxExportRows: row.max_export_rows,
    dailyDisbursementCeilingCents: Number(row.daily_disbursement_ceiling_cents),
    releaseCutoffLocalTime: row.release_cutoff_local_time,
    holidayDates: row.holiday_dates,
  });
}

/** The digest bound into the authorization manifest. */
export async function policyDigest(policy: OrganizationPolicy): Promise<string> {
  return (await sha256Hex(policyDigestInput(policy))).slice(0, 32);
}
