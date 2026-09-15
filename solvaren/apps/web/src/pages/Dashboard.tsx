/**
 * The operational dashboard (spec §22): what is waiting, what is blocked, what is
 * risky, and the L3 executive panels (balance + recent transactions, AC-19 — served by
 * APIs that reject non-L3 callers server-side).
 */

import { useEffect, useState } from 'react';
import type { Permission, TxnState } from '@solvaren/core';
import { api, ApiError, type BalancePanel, type OperationalDashboard } from '../lib/api.js';
import {
  Amount,
  Card,
  Empty,
  ErrorPane,
  Loading,
  PageHeader,
  Stat,
  StatusChip,
  relativeTime,
} from '../components/primitives.js';

interface Props {
  capabilities: Record<Permission, boolean>;
  level: 'L1' | 'L2' | 'L3';
  fullName: string;
  onDrillDown: (statuses: TxnState[]) => void;
}

export function Dashboard({ capabilities, level, fullName, onDrillDown: drillDown }: Props) {
  const [data, setData] = useState<OperationalDashboard | null>(null);
  const [balance, setBalance] = useState<BalancePanel | null>(null);
  const [recent, setRecent] = useState<Awaited<ReturnType<typeof api.analytics.recentTransactions>>['transactions'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [balanceRefreshing, setBalanceRefreshing] = useState(false);

  useEffect(() => {
    void (async () => {
      try {
        setData(await api.analytics.operational());
        if (capabilities['dashboard:balance_panel']) {
          setBalance(await api.analytics.balance());
          setRecent((await api.analytics.recentTransactions()).transactions);
        }
      } catch (err) {
        setError(err instanceof ApiError ? err : null);
      }
    })();
  }, [capabilities]);

  async function refreshBalance() {
    setBalanceRefreshing(true);
    try {
      await api.analytics.refreshBalance();
      // The result arrives asynchronously by callback; poll in a few seconds.
      setTimeout(() => void api.analytics.balance().then(setBalance).catch(() => {}), 5000);
    } catch {
      /* surfaced by the next poll */
    } finally {
      setBalanceRefreshing(false);
    }
  }

  if (error) return <ErrorPane error={error} onRetry={() => window.location.reload()} />;
  if (!data) return <Loading label="Loading dashboard" />;

  const attentionTotal = data.needsAttention.failed + data.needsAttention.timeout + data.needsAttention.reconciling;
  const workWaiting = data.workflows.awaitingL2Review + data.workflows.awaitingL3Authorization + data.workflows.onHold;

  return (
    <>
      <PageHeader
        title={`Good day, ${fullName.split(' ')[0]}`}
        subtitle={
          attentionTotal > 0
            ? `${attentionTotal} transaction${attentionTotal === 1 ? '' : 's'} need attention`
            : workWaiting > 0
              ? `${workWaiting} batch${workWaiting === 1 ? '' : 'es'} in the workflow`
              : 'Everything is quiet'
        }
      />

      {attentionTotal > 0 && (
        <Card>
          <h2 className="card-title">Needs attention</h2>
          <div className="stat-grid">
            {data.needsAttention.failed > 0 && (
              <button className="stat" data-tone="danger" style={{ border: 'none', cursor: 'pointer', textAlign: 'left' }} onClick={() => drillDown(['FAILED'])}>
                <div className="stat-label">Failed payments</div>
                <div className="stat-value">{data.needsAttention.failed}</div>
                <div className="stat-hint">Click to view →</div>
              </button>
            )}
            {data.needsAttention.timeout > 0 && (
              <button className="stat" data-tone="warning" style={{ border: 'none', cursor: 'pointer', textAlign: 'left' }} onClick={() => drillDown(['TIMEOUT'])}>
                <div className="stat-label">Timed out</div>
                <div className="stat-value">{data.needsAttention.timeout}</div>
                <div className="stat-hint">Awaiting reconciliation →</div>
              </button>
            )}
            {data.needsAttention.reconciling > 0 && (
              <button className="stat" data-tone="warning" style={{ border: 'none', cursor: 'pointer', textAlign: 'left' }} onClick={() => drillDown(['RECONCILING'])}>
                <div className="stat-label">Reconciling</div>
                <div className="stat-value">{data.needsAttention.reconciling}</div>
                <div className="stat-hint">Provider status being queried →</div>
              </button>
            )}
          </div>
        </Card>
      )}

      <Card title="Payment operations (last 30 days)">
        <div className="stat-grid">
          <Stat label="Success rate" value={data.transactions.successRate !== null ? `${(data.transactions.successRate * 100).toFixed(1)}%` : '—'} tone="success" />
          <Stat label="Failure rate" value={data.transactions.failureRate !== null ? `${(data.transactions.failureRate * 100).toFixed(1)}%` : '—'} tone={(data.transactions.failureRate ?? 0) > 0.05 ? 'danger' : undefined} />
          <Stat label="In flight" value={data.transactions.inFlight} hint="Being processed now" />
          <Stat label="Median processing" value={data.processingSeconds.median !== null ? `${data.processingSeconds.median}s` : '—'} />
          <Stat label="95th percentile" value={data.processingSeconds.p95 !== null ? `${data.processingSeconds.p95}s` : '—'} />
        </div>
      </Card>

      <Card title="Workflow queue">
        {workWaiting === 0 ? (
          <Empty title="Nothing waiting" hint="Batches awaiting review or authorization appear here." />
        ) : (
          <div className="stat-grid">
            {level !== 'L1' && (
              <Stat label="Awaiting L2 review" value={data.workflows.awaitingL2Review} hint="Finance Control" />
            )}
            <Stat label="Awaiting L3 authorization" value={data.workflows.awaitingL3Authorization} hint="Executive authority" />
            <Stat label="On hold" value={data.workflows.onHold} tone="warning" />
          </div>
        )}
      </Card>

      {balance && (
        <Card
          title="M-PESA account balances"
          footer={
            <>
              <span className="small muted">
                {balance.asOf ? `As of ${relativeTime(balance.asOf)}${balance.awaitingRefresh ? ' · refresh pending' : ''}` : 'No balance retrieved yet'}
              </span>
              <button className="button" onClick={() => void refreshBalance()} disabled={balanceRefreshing}>
                {balanceRefreshing ? 'Requesting…' : 'Refresh balance'}
              </button>
            </>
          }
        >
          {balance.accounts.length === 0 ? (
            <Empty title={balance.note ?? 'No balance retrieved yet'} hint="Refreshing queries M-PESA directly." />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Account</th>
                    <th className="num">Available</th>
                    <th className="num">Uncleared</th>
                    <th className="num">Reserved</th>
                  </tr>
                </thead>
                <tbody>
                  {balance.accounts.map((a) => (
                    <tr key={a.accountType}>
                      <td>{a.accountType}</td>
                      <td className="num"><Amount cents={a.availableCents} /></td>
                      <td className="num"><Amount cents={a.unclearedCents} /></td>
                      <td className="num"><Amount cents={a.reservedCents} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {recent && (
        <Card title="Recent transactions">
          {recent.length === 0 ? (
            <Empty title="No transactions yet" />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Recipient</th>
                    <th className="num">Amount</th>
                    <th>Status</th>
                    <th>Receipt</th>
                    <th>Batch</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.slice(0, 8).map((t) => (
                    <tr key={t.transactionId}>
                      <td>{t.recipientName}</td>
                      <td className="num"><Amount cents={t.amountCents} /></td>
                      <td><StatusChip status={t.status} /></td>
                      <td className="mono small">{t.mpesaReceiptNumber ?? '—'}</td>
                      <td className="small">{t.batchReference}</td>
                      <td className="small muted">{relativeTime(t.at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </>
  );
}
