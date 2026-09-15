/**
 * Transactions Explorer (spec §22, §12): every transaction's live status, filterable
 * (status, date, amount, department, recipient, batch, failure code, free search),
 * server-side sortable and paginated, with the one-click failed CSV export, on-demand
 * status refresh, the retry workflow and payment detail drill-in.
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { Permission, TxnState } from '@solvaren/core';
import { api, ApiError, type ExplorerResponse, type TransactionRow } from '../lib/api.js';
import {
  Amount,
  Card,
  Empty,
  ErrorPane,
  Loading,
  Modal,
  Notice,
  PageHeader,
  Stat,
  StatusChip,
  relativeTime,
} from '../components/primitives.js';

interface Props {
  capabilities: Record<Permission, boolean>;
  initialStatuses?: TxnState[];
  initialBatchId?: string;
}

const STATUS_OPTIONS: { value: TxnState; label: string }[] = [
  { value: 'PENDING', label: 'Pending' },
  { value: 'SUBMITTED', label: 'Submitted' },
  { value: 'AWAITING_CALLBACK', label: 'Awaiting result' },
  { value: 'PROCESSING', label: 'Processing' },
  { value: 'RECONCILING', label: 'Reconciling' },
  { value: 'SUCCESS', label: 'Paid' },
  { value: 'FAILED', label: 'Failed' },
  { value: 'TIMEOUT', label: 'Timed out' },
  { value: 'CANCELLED', label: 'Cancelled' },
];

export function TransactionsExplorer({ capabilities, initialStatuses, initialBatchId }: Props) {
  const [data, setData] = useState<ExplorerResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);

  const [statuses, setStatuses] = useState<Set<TxnState>>(new Set(initialStatuses ?? []));
  const [batchId, setBatchId] = useState(initialBatchId ?? '');
  const [search, setSearch] = useState('');
  const [failureCode, setFailureCode] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sort, setSort] = useState('created_desc');
  const [page, setPage] = useState(1);
  const [detail, setDetail] = useState<TransactionRow | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const params = useMemo(() => {
    const p = new URLSearchParams();
    if (statuses.size > 0) for (const s of statuses) p.append('status', s);
    if (batchId) p.set('batchId', batchId);
    if (search.trim()) p.set('search', search.trim());
    if (failureCode.trim()) p.set('failureCode', failureCode.trim());
    if (dateFrom) p.set('dateFrom', new Date(`${dateFrom}T00:00:00Z`).toISOString().replace('.000Z', ''));
    if (dateTo) p.set('dateTo', new Date(`${dateTo}T23:59:59Z`).toISOString().replace('.000Z', ''));
    p.set('sort', sort);
    p.set('page', String(page));
    p.set('pageSize', '50');
    return p;
  }, [statuses, batchId, search, failureCode, dateFrom, dateTo, sort, page]);

  const load = useCallback(
    async (signal?: AbortSignal) => {
      setLoading(true);
      try {
        setData(await api.transactions.list(params, signal));
        setError(null);
      } catch (err) {
        if ((err as Error).name !== 'AbortError') setError(err instanceof ApiError ? err : null);
      } finally {
        setLoading(false);
      }
    },
    [params],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  // Auto-refresh while anything in view is in flight.
  useEffect(() => {
    const inflight = data?.transactions.some((t) =>
      ['PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'RECONCILING'].includes(t.status),
    );
    if (!inflight) return;
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [data, load]);

  async function exportFailed() {
    try {
      const { blob, filename, truncated } = await api.exports.failedTransactions(params);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      if (truncated) {
        setNotice('Export truncated to your organisation’s row limit. Narrow the filter for the remainder.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  return (
    <>
      <PageHeader
        title="Transactions"
        subtitle={data ? `${data.page.totalRows.toLocaleString()} matching · ${data.filter.text}` : 'Loading…'}
        actions={
          capabilities['transactions:export_failed'] && (
            <button className="button" onClick={() => void exportFailed()}>
              Export failed CSV
            </button>
          )
        }
      />

      {notice && <Notice tone="warning">{notice}</Notice>}
      {error && <ErrorPane error={error} onRetry={() => void load()} />}

      <div className="filters">
        <label className="field" style={{ minWidth: 200 }}>
          <span className="field-label">Search</span>
          <input className="input" placeholder="Name, receipt, reference…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
        </label>
        <label className="field">
          <span className="field-label">From</span>
          <input className="input" type="date" value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setPage(1); }} />
        </label>
        <label className="field">
          <span className="field-label">To</span>
          <input className="input" type="date" value={dateTo} onChange={(e) => { setDateTo(e.target.value); setPage(1); }} />
        </label>
        <label className="field">
          <span className="field-label">Sort</span>
          <select className="select" value={sort} onChange={(e) => { setSort(e.target.value); setPage(1); }}>
            <option value="created_desc">Newest first</option>
            <option value="created_asc">Oldest first</option>
            <option value="amount_desc">Largest amount</option>
            <option value="amount_asc">Smallest amount</option>
            <option value="status">Status</option>
            <option value="completed_desc">Recently completed</option>
          </select>
        </label>
        {batchId && (
          <button className="button" data-variant="ghost" onClick={() => { setBatchId(''); setPage(1); }}>
            Clear batch filter
          </button>
        )}
      </div>

      <div className="filters" style={{ gap: 'var(--s2)' }}>
        {STATUS_OPTIONS.map((s) => (
          <button
            key={s.value}
            className="button button-sm"
            data-variant={statuses.has(s.value) ? 'primary' : 'ghost'}
            onClick={() => {
              const next = new Set(statuses);
              if (next.has(s.value)) next.delete(s.value);
              else next.add(s.value);
              setStatuses(next);
              setPage(1);
            }}
          >
            {s.label}
          </button>
        ))}
        {statuses.size > 0 && (
          <button className="button button-sm" data-variant="ghost" onClick={() => setStatuses(new Set())}>
            Clear
          </button>
        )}
      </div>

      {loading && !data ? (
        <Loading label="Loading transactions" />
      ) : !data || data.transactions.length === 0 ? (
        <Card>
          <Empty title="No transactions match" hint="Adjust the filters above." />
        </Card>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Recipient</th>
                  <th>Department</th>
                  <th className="num">Amount</th>
                  <th>Status</th>
                  <th>Failure</th>
                  <th>Receipt</th>
                  <th>Batch</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {data.transactions.map((t) => (
                  <tr key={t.transactionId} className="row-link" onClick={() => setDetail(t)}>
                    <td>{t.recipientName}</td>
                    <td className="small muted">{t.departmentName ?? '—'}</td>
                    <td className="num"><Amount cents={t.amountCents} /></td>
                    <td><StatusChip status={t.status} /></td>
                    <td className="small">
                      {t.failureCode ? (
                        <span title={t.failureReason ?? ''} style={{ color: 'var(--danger)' }}>
                          {t.failureCode}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="mono small">{t.mpesaReceiptNumber ?? '—'}</td>
                    <td className="mono small">{t.batchReference}</td>
                    <td className="small muted">{relativeTime(t.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <button className="button button-sm" disabled={!data.page.hasPrevious} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <span className="muted">
              Page {data.page.page} of {data.page.totalPages}
            </span>
            <button className="button button-sm" disabled={!data.page.hasNext} onClick={() => setPage((p) => p + 1)}>
              Next
            </button>
          </div>
        </>
      )}

      {detail && <TransactionDetailModal transaction={detail} capabilities={capabilities} onClose={() => setDetail(null)} onChanged={() => void load()} onNotice={setNotice} />}
    </>
  );
}

function TransactionDetailModal({
  transaction,
  capabilities,
  onClose,
  onChanged,
  onNotice,
}: {
  transaction: TransactionRow;
  capabilities: Record<Permission, boolean>;
  onClose: () => void;
  onChanged: () => void;
  onNotice: (message: string) => void;
}) {
  const [detail, setDetail] = useState<Awaited<ReturnType<typeof api.transactions.detail>> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void api.transactions.detail(transaction.transactionId).then(setDetail).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [transaction.transactionId]);

  async function refresh() {
    setBusy(true);
    setError(null);
    try {
      await api.transactions.refresh(transaction.transactionId);
      onNotice('A status query has been sent to M-PESA. The result arrives asynchronously.');
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  async function retry() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.transactions.retry(transaction.transactionId);
      onNotice(result.message);
      onChanged();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  async function explainFailure() {
    setBusy(true);
    try {
      const explanation = await api.ai.explainFailure(transaction.transactionId);
      onNotice(`${explanation.failureReason} → ${explanation.operatorAction}`);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose} wide>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <h2>Payment detail</h2>
          <p className="muted mono small">
            {transaction.batchReference} · {transaction.originatorConversationId}
          </p>
        </div>
        <StatusChip status={transaction.status} />
      </div>

      {error && <Notice tone="danger">{error.message}</Notice>}

      <div className="stat-grid" style={{ marginBottom: 16 }}>
        <Stat label="Recipient" value={<span style={{ fontSize: 15 }}>{transaction.recipientName}</span>} hint={transaction.msisdn} />
        <Stat label="Amount" value={<Amount cents={transaction.amountCents} size="large" />} hint={transaction.departmentName ?? undefined} />
        <Stat label="M-PESA receipt" value={<span className="mono">{transaction.mpesaReceiptNumber ?? '—'}</span>} />
        <Stat label="Status source" value={transaction.statusSource ?? '—'} hint={transaction.lastStatusCheckAt ? `checked ${relativeTime(transaction.lastStatusCheckAt)}` : undefined} />
      </div>

      {transaction.failureCode && (
        <Notice tone="danger">
          <div className="strong">
            {transaction.failureCode}: {transaction.failureReason}
          </div>
          {transaction.operatorAction && <div className="small" style={{ marginTop: 4 }}>→ {transaction.operatorAction}</div>}
        </Notice>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '16px 0' }}>
        {capabilities['transactions:refresh_status'] &&
          !['SUCCESS', 'FAILED', 'CANCELLED'].includes(transaction.status) && (
            <button className="button" onClick={() => void refresh()} disabled={busy}>
              Refresh status from M-PESA
            </button>
          )}
        {capabilities['transactions:retry'] && transaction.retryEligible && (
          <button className="button" data-variant="primary" onClick={() => void retry()} disabled={busy}>
            Retry as new instruction
          </button>
        )}
        {capabilities['ai:batch_analysis'] && transaction.failureCode && (
          <button className="button" data-variant="ghost" onClick={() => void explainFailure()} disabled={busy}>
            Explain this failure
          </button>
        )}
      </div>

      {detail && detail.reconciliationCases.length > 0 && (
        <Card title="Reconciliation cases">
          {detail.reconciliationCases.map((k, i) => (
            <div key={i} style={{ marginBottom: 8 }}>
              <span className="chip" data-tone={k.state.startsWith('RESOLVED') ? 'success' : 'warning'}>
                {k.state}
              </span>{' '}
              <span className="small">{k.opened_reason}</span>
              {k.discrepancy && <div className="small" style={{ color: 'var(--danger)' }}>⚠ Provider contradicts the recorded outcome</div>}
            </div>
          ))}
        </Card>
      )}

      {detail && detail.activity.length > 0 && (
        <Card title="Activity trail (immutable)">
          <ul className="timeline">
            {detail.activity.map((a, i) => (
              <li key={i}>
                <time>{new Date(a.occurred_at).toLocaleString()}</time>
                <div>
                  <span className="strong">{a.action}</span> <span className="muted">({a.outcome})</span> by{' '}
                  <span className="mono small">{a.actor_id}</span>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </Modal>
  );
}
