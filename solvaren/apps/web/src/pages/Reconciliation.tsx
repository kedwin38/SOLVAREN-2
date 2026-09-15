/**
 * Reconciliation (spec §9.5, §23): the case queue with the manual resolution workflow
 * for escalated and discrepant cases. The ledger is never rewritten from here — a manual
 * resolution records a human decision with evidence.
 */

import { useEffect, useState } from 'react';
import type { Permission } from '@solvaren/core';
import { api, ApiError } from '../lib/api.js';
import {
  Amount,
  Card,
  Empty,
  ErrorPane,
  Loading,
  Modal,
  Notice,
  PageHeader,
  relativeTime,
} from '../components/primitives.js';

type CaseRow = Awaited<ReturnType<typeof api.reconciliation.list>>['cases'][number];

export function ReconciliationPage({ capabilities, level }: { capabilities: Record<Permission, boolean>; level: 'L1' | 'L2' | 'L3' }) {
  const [cases, setCases] = useState<CaseRow[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [stateFilter, setStateFilter] = useState('');
  const [resolving, setResolving] = useState<CaseRow | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.reconciliation.list(stateFilter || undefined).then((d) => setCases(d.cases)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [stateFilter, reloadKey]);

  // Live refresh while anything is open or querying.
  useEffect(() => {
    if (cases?.some((k) => k.state === 'OPEN' || k.state === 'QUERYING')) {
      const timer = setInterval(() => setReloadKey((k) => k + 1), 8000);
      return () => clearInterval(timer);
    }
  }, [cases]);

  return (
    <>
      <PageHeader
        title="Reconciliation"
        subtitle="Ambiguous outcomes resolved by the provider's own word — never by assumption"
      />

      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <ErrorPane error={error} onRetry={() => setReloadKey((k) => k + 1)} />}

      <div className="filters">
        <label className="field">
          <span className="field-label">State</span>
          <select className="select" value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            <option value="">All</option>
            <option value="OPEN">Open</option>
            <option value="QUERYING">Querying M-PESA</option>
            <option value="ESCALATED">Escalated (needs human)</option>
            <option value="RESOLVED_SUCCESS">Resolved: success</option>
            <option value="RESOLVED_FAILED">Resolved: failed</option>
            <option value="RESOLVED_MANUAL">Resolved: manual</option>
          </select>
        </label>
      </div>

      {!cases ? (
        <Loading label="Loading reconciliation cases" />
      ) : cases.length === 0 ? (
        <Card>
          <Empty title="No reconciliation cases" hint="Cases open automatically when a payment outcome is ambiguous." />
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Case</th>
                <th>State</th>
                <th>Transaction</th>
                <th>Recipient</th>
                <th className="num">Amount</th>
                <th className="num">Queries</th>
                <th>Reason</th>
                <th>Opened</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {cases.map((k) => (
                <tr key={k.caseId}>
                  <td className="mono small strong">{k.caseReference}</td>
                  <td>
                    <span className={`chip`} data-tone={k.state.startsWith('RESOLVED') ? 'success' : k.state === 'ESCALATED' || k.discrepancy ? 'danger' : 'warning'}>
                      {k.state}
                      {k.discrepancy ? ' ⚠' : ''}
                    </span>
                  </td>
                  <td>
                    <div className="small">{k.batchReference}</div>
                    <div className="mono small muted">{k.transactionStatus ?? ''}</div>
                  </td>
                  <td className="small">{k.recipientName ?? '—'}</td>
                  <td className="num">{k.amountCents !== null ? <Amount cents={k.amountCents} /> : '—'}</td>
                  <td className="num">{k.queryAttempts}</td>
                  <td className="small" style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={k.openedReason}>
                    {k.openedReason}
                  </td>
                  <td className="small muted">{relativeTime(k.openedAt)}</td>
                  <td>
                    {capabilities['reconciliation:resolve'] && ['OPEN', 'QUERYING', 'ESCALATED'].includes(k.state) && (
                      <button className="button button-sm" onClick={() => setResolving(k)}>
                        Resolve
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {resolving && (
        <ResolveCaseModal
          kase={resolving}
          onClose={() => setResolving(null)}
          onResolved={(message) => {
            setResolving(null);
            setNotice(message);
            setReloadKey((k) => k + 1);
          }}
        />
      )}
    </>
  );
}

function ResolveCaseModal({ kase, onClose, onResolved }: { kase: CaseRow; onClose: () => void; onResolved: (message: string) => void }) {
  const [outcome, setOutcome] = useState<'RESOLVED_MANUAL' | 'RESOLVED_SUCCESS' | 'RESOLVED_FAILED'>('RESOLVED_MANUAL');
  const [note, setNote] = useState('');
  const [portalReceipt, setPortalReceipt] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.reconciliation.resolve(kase.caseId, outcome, note, outcome === 'RESOLVED_SUCCESS' ? portalReceipt : undefined);
      onResolved('Resolution recorded. The transaction record itself was NOT modified.');
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose}>
      <h2>Resolve {kase.caseReference}</h2>
      <p className="muted small">
        Record what you established. The ledger is never rewritten here — if the provider's own status query
        later disagrees, the existing discrepancy machinery handles it.
      </p>
      {error && <Notice tone="danger">{error.message}</Notice>}
      <form onSubmit={submit}>
        <label className="field">
          <span className="field-label">Outcome</span>
          <select className="select" value={outcome} onChange={(e) => setOutcome(e.target.value as typeof outcome)}>
            <option value="RESOLVED_MANUAL">Resolved manually (investigated, no provider confirmation)</option>
            <option value="RESOLVED_SUCCESS">Confirmed paid (verified on the M-PESA portal)</option>
            <option value="RESOLVED_FAILED">Confirmed not paid (verified on the M-PESA portal)</option>
          </select>
        </label>
        {outcome === 'RESOLVED_SUCCESS' && (
          <label className="field">
            <span className="field-label">M-PESA receipt observed on the portal</span>
            <input className="input mono" placeholder="SG…" value={portalReceipt} onChange={(e) => setPortalReceipt(e.target.value)} required />
          </label>
        )}
        <label className="field">
          <span className="field-label">Evidence note (min 10 characters)</span>
          <textarea className="textarea" rows={3} value={note} onChange={(e) => setNote(e.target.value)} required minLength={10} placeholder="What did you check, and what did you find?" />
        </label>
        <div className="card-footer">
          <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button" data-variant="primary" disabled={busy}>{busy ? 'Recording…' : 'Record resolution'}</button>
        </div>
      </form>
    </Modal>
  );
}
