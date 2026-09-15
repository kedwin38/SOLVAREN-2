/**
 * Recipients master data (spec §22): search, add, edit, deactivate/reactivate/block,
 * per-recipient payment history. This screen exists because the previous system had no
 * recipient management at all — records could only be created implicitly via CSV.
 */

import { useCallback, useEffect, useState } from 'react';
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
  StatusChip,
  relativeTime,
} from '../components/primitives.js';

export function RecipientsPage({ capabilities }: { capabilities: Record<Permission, boolean> }) {
  const [recipients, setRecipients] = useState<Awaited<ReturnType<typeof api.recipients.list>>['recipients'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [historyFor, setHistoryFor] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const load = useCallback(async () => {
    try {
      const data = await api.recipients.list(search || undefined, statusFilter || undefined);
      setRecipients(data.recipients);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }, [search, statusFilter]);

  useEffect(() => {
    const t = setTimeout(() => void load(), 250);
    return () => clearTimeout(t);
  }, [load, reloadKey]);

  return (
    <>
      <PageHeader
        title="Recipients"
        subtitle="Employee, supplier and contractor master records"
        actions={
          capabilities['recipients:write'] && (
            <button className="button" data-variant="primary" onClick={() => setAddOpen(true)}>
              Add recipient
            </button>
          )
        }
      />

      {error && <ErrorPane error={error} onRetry={() => setReloadKey((k) => k + 1)} />}

      <div className="filters">
        <label className="field" style={{ flex: 1 }}>
          <span className="field-label">Search</span>
          <input className="input" placeholder="Name, phone or reference…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </label>
        <label className="field">
          <span className="field-label">Status</span>
          <select className="select" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
            <option value="">All</option>
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
            <option value="BLOCKED">Blocked</option>
          </select>
        </label>
      </div>

      {!recipients ? (
        <Loading label="Loading recipients" />
      ) : recipients.length === 0 ? (
        <Card>
          <Empty title="No recipients" hint="Recipients are also created automatically when a CSV is uploaded." />
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Phone</th>
                <th>Department</th>
                <th>Status</th>
                <th className="num">Payments</th>
                <th className="num">Mean amount</th>
                <th>Added</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {recipients.map((r) => (
                <tr key={r.recipientId}>
                  <td className="strong">{r.fullName}</td>
                  <td className="mono small">{r.msisdn}</td>
                  <td className="small muted">{r.departmentName ?? '—'}</td>
                  <td>
                    <span className="chip" data-tone={r.status === 'ACTIVE' ? 'success' : r.status === 'BLOCKED' ? 'danger' : 'neutral'}>
                      {r.status}
                    </span>
                  </td>
                  <td className="num">{r.paymentCount}</td>
                  <td className="num">{r.paymentCount > 0 ? <Amount cents={r.meanAmountCents} /> : '—'}</td>
                  <td className="small muted">{relativeTime(r.createdAt)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button className="button button-sm" data-variant="ghost" onClick={() => setHistoryFor(r.recipientId)}>
                        History
                      </button>
                      {capabilities['recipients:write'] && r.status !== 'ACTIVE' && (
                        <button
                          className="button button-sm"
                          onClick={() => void api.recipients.update(r.recipientId, { status: 'ACTIVE' }).then(() => setReloadKey((k) => k + 1))}
                        >
                          Activate
                        </button>
                      )}
                      {capabilities['recipients:write'] && r.status === 'ACTIVE' && (
                        <button
                          className="button button-sm"
                          data-variant="ghost"
                          onClick={() => void api.recipients.update(r.recipientId, { status: 'INACTIVE' }).then(() => setReloadKey((k) => k + 1))}
                        >
                          Deactivate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {addOpen && (
        <AddRecipientModal
          onClose={() => setAddOpen(false)}
          onAdded={() => {
            setAddOpen(false);
            setReloadKey((k) => k + 1);
          }}
        />
      )}

      {historyFor && <HistoryModal recipientId={historyFor} onClose={() => setHistoryFor(null)} />}
    </>
  );
}

function AddRecipientModal({ onClose, onAdded }: { onClose: () => void; onAdded: () => void }) {
  const [fullName, setFullName] = useState('');
  const [msisdn, setMsisdn] = useState('');
  const [externalReference, setExternalReference] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.recipients.create({
        fullName,
        msisdn,
        ...(externalReference ? { externalReference } : {}),
      });
      onAdded();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose}>
      <h2>Add recipient</h2>
      {error && <Notice tone="danger">{error.message}</Notice>}
      <form onSubmit={submit}>
        <label className="field">
          <span className="field-label">Full name</span>
          <input className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} required />
        </label>
        <label className="field">
          <span className="field-label">Phone number</span>
          <input className="input mono" placeholder="07… or 2547… or +2547…" value={msisdn} onChange={(e) => setMsisdn(e.target.value)} required />
        </label>
        <label className="field">
          <span className="field-label">Reference (optional)</span>
          <input className="input" placeholder="Employee ID" value={externalReference} onChange={(e) => setExternalReference(e.target.value)} />
        </label>
        <div className="card-footer">
          <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button" data-variant="primary" disabled={busy}>Add</button>
        </div>
      </form>
    </Modal>
  );
}

function HistoryModal({ recipientId, onClose }: { recipientId: string; onClose: () => void }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.recipients.history>> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void api.recipients.history(recipientId).then(setData).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [recipientId]);

  return (
    <Modal open onClose={onClose} wide>
      <h2>Payment history</h2>
      {error && <Notice tone="danger">{error.message}</Notice>}
      {!data ? (
        <Loading />
      ) : (
        <>
          <p className="muted">
            {data.recipient.fullName} · {data.recipient.msisdnMasked} · {data.history.length} payment(s)
          </p>
          {data.history.length === 0 ? (
            <Empty title="No payments yet" />
          ) : (
            <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Batch</th>
                    <th className="num">Amount</th>
                    <th>Status</th>
                    <th>Receipt</th>
                    <th>Completed</th>
                  </tr>
                </thead>
                <tbody>
                  {data.history.map((h, i) => (
                    <tr key={i}>
                      <td className="mono small">{h.batchReference}</td>
                      <td className="num"><Amount cents={h.amountCents} /></td>
                      <td><StatusChip status={h.status} /></td>
                      <td className="mono small">{h.mpesaReceipt ?? '—'}</td>
                      <td className="small muted">{relativeTime(h.completedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
