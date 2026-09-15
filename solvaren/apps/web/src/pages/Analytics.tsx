/**
 * Analytics (spec §12, §22): operational (L1+), financial (L2+), executive briefing (L3).
 * Computed facts are always distinguished from AI narrative (spec §12.2).
 */

import { useEffect, useState } from 'react';
import type { Permission } from '@solvaren/core';
import { api, ApiError } from '../lib/api.js';
import { Amount, Card, Empty, ErrorPane, Loading, Notice, PageHeader, Stat } from '../components/primitives.js';

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

      {(tab === 'financial' || !capabilities['analytics:execensive' as never]) && financial !== null && (
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
          <Card title="Month over month">
            <div className="stat-grid">
              <Stat label="This month" value={<Amount cents={briefing.monthOverMonth.currentCents} />} />
              <Stat label="Last month" value={<Amount cents={briefing.monthOverMonth.previousCents} />} />
              <Stat
                label="Change"
                value={briefing.monthOverMonth.changePercent !== null ? `${briefing.monthOverMonth.changePercent > 0 ? '+' : ''}${briefing.monthOverMonth.changePercent}%` : '—'}
                tone={briefing.monthOverMonth.changePercent !== null && briefing.monthOverMonth.changePercent > 10 ? 'warning' : undefined}
              />
              {briefing.monthOverMonth.largestMover && (
                <Stat
                  label="Largest mover"
                  value={briefing.monthOverMonth.largestMover.departmentName}
                  hint={`KES ${(briefing.monthOverMonth.largestMover.deltaCents / 100).toLocaleString()}`}
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

          <Card title="Risk position">
            <div className="stat-grid">
              <Stat label="Open findings (30d)" value={briefing.risk.openFindings} tone={briefing.risk.openFindings > 0 ? 'warning' : 'success'} />
              <Stat label="Reviewed findings (30d)" value={briefing.risk.reviewedFindings} />
              <Stat label="Unresolved reconciliation" value={briefing.unresolvedReconciliationCases} tone={briefing.unresolvedReconciliationCases > 0 ? 'warning' : 'success'} />
            </div>
          </Card>
        </>
      )}

      {!financial && !briefing && <Loading label="Loading analytics" />}
    </>
  );
}
