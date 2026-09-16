/**
 * Analytics (spec §12, §22): operational (L1+), financial (L2+), executive briefing (L3).
 * Computed facts are always distinguished from AI narrative (spec §12.2).
 */

import { useEffect, useState } from 'react';
import type { Permission } from '@solvaren/core';
import { api, ApiError } from '../lib/api.js';
import { Amount, Card, DistributionBar, Empty, ErrorPane, Loading, Notice, PageHeader, Stat } from '../components/primitives.js';

const MOMENTUM_LABEL: Record<'ACCELERATING' | 'STEADY' | 'SLOWING' | 'INSUFFICIENT_DATA', string> = {
  ACCELERATING: 'Accelerating',
  STEADY: 'Steady',
  SLOWING: 'Slowing',
  INSUFFICIENT_DATA: 'Not enough history',
};
const MOMENTUM_TONE: Record<'ACCELERATING' | 'STEADY' | 'SLOWING' | 'INSUFFICIENT_DATA', 'success' | 'danger' | 'warning' | undefined> = {
  ACCELERATING: 'success',
  STEADY: undefined,
  SLOWING: 'warning',
  INSUFFICIENT_DATA: undefined,
};
const RISK_POSTURE_TONE: Record<'STABLE' | 'WATCH' | 'ELEVATED', 'success' | 'danger' | 'warning' | undefined> = {
  STABLE: 'success',
  WATCH: 'warning',
  ELEVATED: 'danger',
};

export function AnalyticsPage({ level, capabilities }: { level: 'L1' | 'L2' | 'L3'; capabilities: Record<Permission, boolean> }) {
  const [tab, setTab] = useState<'financial' | 'briefing'>(capabilities['analytics:advanced'] ? 'financial' : 'briefing');
  const [financial, setFinancial] = useState<Awaited<ReturnType<typeof api.analytics.financial>> | null>(null);
  const [briefing, setBriefing] = useState<Awaited<ReturnType<typeof api.analytics.briefing>> | null>(null);
  const [aiBriefing, setAiBriefing] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        if (capabilities['analytics:advanced']) setFinancial(await api.analytics.financial());
        if (capabilities['analytics:executive']) setBriefing(await api.analytics.briefing());
      } catch (err) {
        setError(err instanceof ApiError ? err : null);
      }
    })();
  }, [capabilities]);

  async function draftBriefing() {
    setBusy(true);
    try {
      const result = await api.ai.briefing();
      setAiBriefing(result.briefing ?? 'The AI assistant is unavailable. The computed figures above are complete and unaffected.');
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  if (error) return <ErrorPane error={error} />;

  if (!capabilities['analytics:advanced'] && !capabilities['analytics:executive']) {
    return (
      <>
        <PageHeader title="Analytics" />
        <Card>
          <Empty title="Advanced analytics" hint="Available to Finance Control and above." />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Analytics"
        subtitle="Departmental expenditure, payroll cycles, risk position"
        actions={
          capabilities['ai:executive_intelligence'] && (
            <button className="button" onClick={() => void draftBriefing()} disabled={busy}>
              Draft executive briefing (AI)
            </button>
          )
        }
      />

      {capabilities['analytics:advanced'] && capabilities['analytics:executive'] && (
        <div className="filters" style={{ gap: 8, marginBottom: 16 }}>
          <button className="button button-sm" data-variant={tab === 'financial' ? 'primary' : 'ghost'} onClick={() => setTab('financial')}>
            Financial
          </button>
          <button className="button button-sm" data-variant={tab === 'briefing' ? 'primary' : 'ghost'} onClick={() => setTab('briefing')}>
            Executive briefing
          </button>
        </div>
      )}

      {aiBriefing && (
        <Notice tone="info">
          <div className="small muted" style={{ marginBottom: 4 }}>AI advisory draft — computed facts above/below are authoritative</div>
          {aiBriefing}
        </Notice>
      )}

      {(tab === 'financial' || !capabilities['analytics:executive']) && financial !== null && (
        <>
          {financial.payrollCycles.length > 0 && (
            <Card title="Payroll cycles (successful disbursements per month)">
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Month</th>
                      <th className="num">Total</th>
                      <th className="num">Recipients</th>
                    </tr>
                  </thead>
                  <tbody>
                    {financial.payrollCycles.map((c) => (
                      <tr key={c.periodMonth}>
                        <td>{c.periodMonth}</td>
                        <td className="num"><Amount cents={c.totalCents} /></td>
                        <td className="num">{c.recipientCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {financial.forecast.nextCycleCents !== null && (
                <p className="small muted" style={{ marginTop: 8 }}>
                  Next-cycle forecast: <Amount cents={financial.forecast.nextCycleCents} /> — {financial.forecast.basis}.
                </p>
              )}
            </Card>
          )}

          {financial.departmentExpenditure.length > 0 && (
            <Card title="Departmental expenditure (by month)">
              <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Month</th>
                      <th>Department</th>
                      <th className="num">Paid</th>
                      <th className="num">Payments</th>
                      <th className="num">Failed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {financial.departmentExpenditure.map((d, i) => (
                      <tr key={i}>
                        <td className="small muted">{d.periodMonth}</td>
                        <td>{d.departmentName}</td>
                        <td className="num"><Amount cents={d.paidCents} /></td>
                        <td className="num">{d.paidCount}</td>
                        <td className="num" style={{ color: d.failedCount > 0 ? 'var(--danger)' : undefined }}>{d.failedCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          <Card title="Position">
            <div className="stat-grid">
              {Object.entries(financial.openFindingsBySeverity).map(([severity, count]) => (
                <Stat key={severity} label={`Open ${severity} findings`} value={count} tone={severity === 'CRITICAL' || severity === 'HIGH' ? 'danger' : 'warning'} />
              ))}
              {Object.entries(financial.reconciliationByState).map(([state, count]) => (
                <Stat key={state} label={`Reconciliation ${state.toLowerCase()}`} value={count} />
              ))}
            </div>
          </Card>
        </>
      )}

      {(tab === 'briefing' || !capabilities['analytics:advanced']) && briefing && (
        <>
          <Card title="Disbursement momentum">
            <div className="stat-grid">
              <Stat
                label="Trend"
                value={MOMENTUM_LABEL[briefing.momentum]}
                hint="Compares the last two months' average against the two before — a single month's swing is noise, not a trend."
                tone={MOMENTUM_TONE[briefing.momentum]}
              />
              <Stat label="This month" value={<Amount cents={briefing.monthOverMonth.currentCents} />} />
              <Stat label="Last month" value={<Amount cents={briefing.monthOverMonth.previousCents} />} />
              <Stat
                label="Change"
                value={briefing.monthOverMonth.changePercent !== null ? `${briefing.monthOverMonth.changePercent > 0 ? '+' : ''}${briefing.monthOverMonth.changePercent}%` : '—'}
              />
              {briefing.monthOverMonth.largestMover && (
                <Stat
                  label="Largest mover"
                  value={briefing.monthOverMonth.largestMover.departmentName}
                  hint={`${briefing.monthOverMonth.largestMover.deltaCents >= 0 ? '+' : ''}KES ${(briefing.monthOverMonth.largestMover.deltaCents / 100).toLocaleString()} vs. last month`}
                />
              )}
            </div>
          </Card>

          {briefing.monthlyDisbursement.length > 0 && (
            <Card title="Monthly disbursements">
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Month</th>
                      <th className="num">Disbursed</th>
                      <th className="num">Transactions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {briefing.monthlyDisbursement.map((m) => (
                      <tr key={m.period}>
                        <td>{m.period}</td>
                        <td className="num"><Amount cents={m.totalCents} /></td>
                        <td className="num">{m.transactionCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          <Card title="Risk posture">
            <div className="stat-grid">
              <Stat label="Overall posture" value={briefing.riskPosture.band} tone={RISK_POSTURE_TONE[briefing.riskPosture.band]} />
              <Stat label="Open findings (30d)" value={briefing.risk.openFindings} />
              <Stat label="Reviewed findings (30d)" value={briefing.risk.reviewedFindings} />
              <Stat label="Unresolved reconciliation" value={briefing.unresolvedReconciliationCases} />
            </div>
            {briefing.riskPosture.reasons.length > 0 ? (
              <ul className="small muted" style={{ marginTop: 12, paddingLeft: 18 }}>
                {briefing.riskPosture.reasons.map((reason, i) => (
                  <li key={i}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p className="small muted" style={{ marginTop: 12 }}>No conditions elevating risk posture right now.</p>
            )}
          </Card>

          <Card title="Settlement speed">
            <DistributionBar
              headline={briefing.settlementDistribution.headline}
              ariaLabel="How quickly payments settle, last 30 days"
              segments={[
                { label: 'Fast (under 30s)', value: briefing.settlementDistribution.fast, percent: briefing.settlementDistribution.fastPercent, tone: 'success' },
                { label: 'Typical (30s–2min)', value: briefing.settlementDistribution.typical, percent: briefing.settlementDistribution.typicalPercent, tone: 'info' },
                { label: 'Slow (2min+)', value: briefing.settlementDistribution.slow, percent: briefing.settlementDistribution.slowPercent, tone: 'warning' },
              ]}
            />
          </Card>
        </>
      )}

      {!financial && !briefing && <Loading label="Loading analytics" />}
    </>
  );
}
