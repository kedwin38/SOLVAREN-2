/**
 * Payment batches (spec §22): the full workflow console — create, upload CSV, validate,
 * submit (L1); review, approve, reject, return, hold, release-hold (L2); authorize,
 * release, cancel (L3 via the ceremony). State timeline, instructions, approvals
 * history, risk findings, AI batch analysis.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { Permission } from '@solvaren/core';
import {
  api,
  ApiError,
  requestWebAuthnAssertion,
  type BatchDetail,
  type BatchSummary,
  type CeremonyResponse,
} from '../lib/api.js';
import {
  Amount,
  BatchStateChip,
  Card,
  Empty,
  ErrorPane,
  Loading,
  Modal,
  Notice,
  PageHeader,
  SeverityChip,
  Stat,
  StatusChip,
  relativeTime,
} from '../components/primitives.js';
import { AuthorizationCeremony } from './AuthorizationCeremony.js';

interface Props {
  capabilities: Record<Permission, boolean>;
  level: 'L1' | 'L2' | 'L3';
  onReleased: (summary: { batchReference: string; message: string }) => void;
  onViewTransactions: (batchId: string) => void;
}

const STATE_FILTERS = [
  { value: '', label: 'All' },
  { value: 'DRAFT', label: 'Draft' },
  { value: 'VALIDATED', label: 'Validated' },
  { value: 'SUBMITTED_TO_L2', label: 'Awaiting review' },
  { value: 'L2_REVIEW', label: 'In review' },
  { value: 'L3_READY', label: 'Awaiting authorization' },
  { value: 'AUTHORIZATION_PENDING', label: 'Authorization open' },
  { value: 'PROCESSING', label: 'Processing' },
  { value: 'SUCCESS', label: 'Complete' },
  { value: 'PARTIAL_SUCCESS', label: 'Partial' },
  { value: 'FAILED', label: 'Failed' },
  { value: 'TIMEOUT', label: 'Timed out' },
  { value: 'ON_HOLD', label: 'On hold' },
  { value: 'REJECTED', label: 'Rejected' },
  { value: 'CANCELLED', label: 'Cancelled' },
];

export function BatchesPage({ capabilities, level, onReleased, onViewTransactions }: Props) {
  const [batches, setBatches] = useState<BatchSummary[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [stateFilter, setStateFilter] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [ceremonyBatchId, setCeremonyBatchId] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void (async () => {
      try {
        const data = await api.batches.list(stateFilter || undefined);
        setBatches(data.batches);
      } catch (err) {
        setError(err instanceof ApiError ? err : null);
      }
    })();
  }, [stateFilter, reloadKey]);

  // Auto-refresh while any batch is in flight (operators watch a payroll run live).
  useEffect(() => {
    const inflight = batches?.some((b) => ['QUEUED', 'SUBMITTED', 'PROCESSING'].includes(b.state));
    if (!inflight) return;
    const timer = setInterval(() => setReloadKey((k) => k + 1), 5000);
    return () => clearInterval(timer);
  }, [batches]);

  if (error) return <ErrorPane error={error} onRetry={() => setReloadKey((k) => k + 1)} />;

  return (
    <>
      <PageHeader
        title="Payment batches"
        subtitle="Prepare, review, authorize and monitor disbursements"
        actions={
          capabilities['batch:create'] && (
            <button className="button" data-variant="primary" onClick={() => setCreateOpen(true)}>
              New batch
            </button>
          )
        }
      />

      <div className="filters">
        <label className="field">
          <span className="field-label">State</span>
          <select className="select" value={stateFilter} onChange={(e) => setStateFilter(e.target.value)}>
            {STATE_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      {!batches ? (
        <Loading label="Loading batches" />
      ) : batches.length === 0 ? (
        <Card>
          <Empty
            title="No batches"
            hint={
              capabilities['batch:create']
                ? 'Create a batch and upload a CSV of recipients and amounts to begin.'
                : 'Batches created by Payment Operations will appear here.'
            }
          />
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Purpose</th>
                <th>State</th>
                <th className="num">Recipients</th>
                <th className="num">Total</th>
                <th className="num">Paid</th>
                <th className="num">Failed</th>
                <th>Created</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {batches.map((b) => (
                <tr key={b.batchId} className="row-link" onClick={() => setSelected(b.batchId)}>
                  <td className="mono small strong">{b.batchReference}</td>
                  <td>{b.purpose.length > 40 ? `${b.purpose.slice(0, 40)}…` : b.purpose}</td>
                  <td><BatchStateChip state={b.state} /></td>
                  <td className="num">{b.instructionCount}</td>
                  <td className="num"><Amount cents={b.totalAmountCents} /></td>
                  <td className="num" style={{ color: b.outcomes.success > 0 ? 'var(--accent-strong)' : undefined }}>
                    {b.outcomes.success}
                  </td>
                  <td className="num" style={{ color: b.outcomes.failed > 0 ? 'var(--danger)' : undefined }}>
                    {b.outcomes.failed + b.outcomes.timeout}
                  </td>
                  <td className="small muted">{relativeTime(b.createdAt)}</td>
                  <td>
                    {b.state === 'L3_READY' && capabilities['payment:authorize'] && (
                      <button
                        className="button button-sm"
                        data-variant="danger"
                        onClick={(e) => {
                          e.stopPropagation();
                          setCeremonyBatchId(b.batchId);
                        }}
                      >
                        Authorize & release
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <BatchDetailModal
          batchId={selected}
          capabilities={capabilities}
          level={level}
          onClose={() => {
            setSelected(null);
            setReloadKey((k) => k + 1);
          }}
          onOpenCeremony={() => {
            setCeremonyBatchId(selected);
            setSelected(null);
          }}
          onViewTransactions={onViewTransactions}
        />
      )}

      {createOpen && (
        <CreateBatchModal
          onClose={() => setCreateOpen(false)}
          onCreated={() => {
            setCreateOpen(false);
            setReloadKey((k) => k + 1);
          }}
        />
      )}

      {ceremonyBatchId && (
        <AuthorizationCeremony
          batchId={ceremonyBatchId}
          onClose={() => {
            setCeremonyBatchId(null);
            setReloadKey((k) => k + 1);
          }}
          onReleased={(summary) => {
            setCeremonyBatchId(null);
            setReloadKey((k) => k + 1);
            onReleased(summary);
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Batch detail (instructions, approvals, risk findings, actions)
// ---------------------------------------------------------------------------

function BatchDetailModal({
  batchId,
  capabilities,
  level,
  onClose,
  onOpenCeremony,
  onViewTransactions,
}: {
  batchId: string;
  capabilities: Record<Permission, boolean>;
  level: 'L1' | 'L2' | 'L3';
  onClose: () => void;
  onOpenCeremony: () => void;
  onViewTransactions: (batchId: string) => void;
}) {
  const [detail, setDetail] = useState<BatchDetail | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [showReason, setShowReason] = useState<'reject' | 'return' | 'hold' | 'cancel' | null>(null);
  const [acknowledgeFindings, setAcknowledgeFindings] = useState(false);
  const [aiNarrative, setAiNarrative] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const reload = useCallback(async () => {
    try {
      setDetail(await api.batches.detail(batchId));
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }, [batchId]);

  useEffect(() => {
    void reload();
    // Auto-refresh while processing.
    const timer = setInterval(() => void reload(), 5000);
    return () => clearInterval(timer);
  }, [reload]);

  async function action(fn: () => Promise<unknown>, successMessage: string) {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await fn();
      setNotice(successMessage);
      setShowReason(null);
      setReason('');
      await reload();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  async function uploadCsv(file: File) {
    setBusy(true);
    try {
      const result = (await api.batches.upload(batchId, file)) as {
        accepted: number;
        rejected: { lineNumber: number; reason: string }[];
        duplicateWarnings: { reason: string }[];
        totalAmountCents: number;
      };
      const parts = [
        `${result.accepted} rows accepted`,
        result.rejected.length > 0 ? `${result.rejected.length} rejected` : null,
        result.duplicateWarnings.length > 0 ? `${result.duplicateWarnings.length} duplicate warning(s)` : null,
      ].filter(Boolean);
      setNotice(`${parts.join(' · ')}.`);
      await reload();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  async function runAi() {
    setBusy(true);
    try {
      const result = await api.ai.analyseBatch(batchId);
      setAiNarrative(result.narrative ?? result.degraded ? result.narrative : 'AI unavailable — deterministic findings shown above.');
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  if (error && !detail) {
    return (
      <Modal open onClose={onClose}>
        <ErrorPane error={error} />
      </Modal>
    );
  }
  if (!detail) {
    return (
      <Modal open onClose={onClose}>
        <Loading label="Loading batch" />
      </Modal>
    );
  }

  const b = detail.batch;
  const openFindings = detail.riskFindings.filter((f) => f.disposition === 'OPEN' && f.currentVersion);

  return (
    <Modal open onClose={onClose} wide>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <h2 className="mono">{b.batchReference}</h2>
          <p className="muted">{b.purpose} · created by {b.createdBy} {relativeTime(b.createdAt)}</p>
        </div>
        <BatchStateChip state={b.state} />
      </div>

      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}
      {showReason && (
        <Notice tone="warning">
          <label className="field" style={{ marginBottom: 8 }}>
            <span className="field-label">
              Reason for {showReason === 'return' ? 'returning' : showReason} (required, kept in the audit trail)
            </span>
            <textarea className="textarea" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="button"
              data-variant={showReason === 'cancel' ? 'danger' : 'primary'}
              disabled={busy || reason.trim().length < 3}
              onClick={() => {
                if (showReason === 'reject') void action(() => api.batches.reject(batchId, reason), 'Batch rejected.');
                if (showReason === 'return') void action(() => api.batches.returnToL1(batchId, reason), 'Batch returned to Payment Operations.');
                if (showReason === 'hold') void action(() => api.batches.hold(batchId, reason), 'Batch placed on hold.');
                if (showReason === 'cancel') void action(() => api.batches.cancel(batchId, reason), 'Batch cancelled.');
              }}
            >
              Confirm {showReason}
            </button>
            <button className="button" data-variant="ghost" onClick={() => setShowReason(null)}>
              Cancel
            </button>
          </div>
        </Notice>
      )}

      <div className="stat-grid" style={{ marginBottom: 16 }}>
        <Stat label="Recipients" value={b.instructionCount} />
        <Stat label="Total" value={<Amount cents={b.totalAmountCents} />} />
        <Stat label="Version" value={b.version} hint="Bumps on every material edit" />
        {b.riskScore !== null && <Stat label="Risk" value={`${b.riskScore} (${b.riskBand})`} tone={b.riskBand === 'CRITICAL' || b.riskBand === 'HIGH' ? 'danger' : 'warning'} />}
      </div>

      {/* ---- Workflow actions ---- */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        <a
          className="button"
          href="/templates/solvaren-batch-template.csv"
          download="solvaren-batch-template.csv"
          title="Official template: recipient name, phone, amount (whole shillings), department, reference, remarks"
        >
          Download CSV template
        </a>
        {b.editable && capabilities['batch:edit'] && (
          <>
            <button className="button" onClick={() => fileRef.current?.click()} disabled={busy}>
              Upload CSV {detail.instructions.total > 0 ? '(replaces)' : ''}
            </button>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              style={{ display: 'none' }}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void uploadCsv(file);
                e.target.value = '';
              }}
            />
          </>
        )}
        {b.state === 'DRAFT' && b.instructionCount > 0 && capabilities['batch:validate'] && (
          <button className="button" onClick={() => void action(() => api.batches.validate(batchId), 'Validation complete.')} disabled={busy}>
            Validate
          </button>
        )}
        {(b.state === 'VALIDATED' || b.state === 'RETURNED_FOR_CORRECTION') && capabilities['batch:submit_to_l2'] && (
          <button className="button" data-variant="primary" onClick={() => void action(() => api.batches.submit(batchId), 'Submitted to Finance Control.')} disabled={busy}>
            Submit to Finance Control
          </button>
        )}
        {(b.state === 'SUBMITTED_TO_L2' || b.state === 'L2_REVIEW') && capabilities['batch:approve_to_l3'] && level === 'L2' && (
          <button
            className="button"
            data-variant="primary"
            disabled={busy || (openFindings.length > 0 && !acknowledgeFindings)}
            onClick={() => void action(() => api.batches.approve(batchId, reason || undefined, acknowledgeFindings), 'Approved for Level 3 authorization.')}
          >
            Approve for L3 {openFindings.length > 0 && !acknowledgeFindings ? `(${openFindings.length} findings need acknowledgement below)` : ''}
          </button>
        )}
        {(b.state === 'SUBMITTED_TO_L2' || b.state === 'L2_REVIEW' || b.state === 'L3_READY') && capabilities['batch:reject'] && !showReason && (
          <button className="button" onClick={() => setShowReason('reject')}>Reject</button>
        )}
        {(b.state === 'SUBMITTED_TO_L2' || b.state === 'L2_REVIEW') && capabilities['batch:reject'] && (
          <button className="button" onClick={() => setShowReason('return')}>Return to L1</button>
        )}
        {(b.state === 'SUBMITTED_TO_L2' || b.state === 'L2_REVIEW' || b.state === 'L3_READY') && capabilities['batch:hold'] && !showReason && (
          <button className="button" onClick={() => setShowReason('hold')}>Hold</button>
        )}
        {b.state === 'ON_HOLD' && capabilities['batch:release_hold'] && (
          <button className="button" onClick={() => void action(() => api.batches.releaseHold(batchId, reason || undefined), 'Hold lifted; batch returned to review.')} disabled={busy}>
            Release hold
          </button>
        )}
        {['DRAFT', 'VALIDATED', 'RETURNED_FOR_CORRECTION', 'L3_READY', 'ON_HOLD'].includes(b.state) && capabilities['batch:cancel'] && !showReason && (
          <button className="button" data-variant="danger" onClick={() => setShowReason('cancel')}>Cancel batch</button>
        )}
        {b.state === 'L3_READY' && capabilities['payment:authorize'] && (
          <button className="button button-release" onClick={onOpenCeremony}>
            Authorize & release
          </button>
        )}
        {['QUEUED', 'SUBMITTED', 'PROCESSING', 'SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'TIMEOUT'].includes(b.state) && (
          <button className="button" onClick={() => onViewTransactions(batchId)}>
            View transactions
          </button>
        )}
        {capabilities['ai:batch_analysis'] && detail.instructions.total > 0 && (
          <button className="button" data-variant="ghost" onClick={() => void runAi()} disabled={busy}>
            AI analysis
          </button>
        )}
      </div>

      {openFindings.length > 0 && (b.state === 'SUBMITTED_TO_L2' || b.state === 'L2_REVIEW') && (
        <Notice tone="warning">
          <label className="checkbox">
            <input type="checkbox" checked={acknowledgeFindings} onChange={(e) => setAcknowledgeFindings(e.target.checked)} />
            <span>
              I have reviewed all {openFindings.length} open risk finding(s) below and accept them for approval.
            </span>
          </label>
        </Notice>
      )}

      {/* ---- Risk findings ---- */}
      {detail.riskFindings.length > 0 && (
        <Card title="Risk findings">
          {detail.riskFindings.map((f, i) => (
            <div key={i} style={{ display: 'flex', gap: 12, marginBottom: 8, alignItems: 'flex-start', opacity: f.currentVersion ? 1 : 0.5 }}>
              <SeverityChip severity={f.severity} />
              <div style={{ flex: 1 }}>
                <div>{f.summary}</div>
                <div className="small muted">
                  {f.type}
                  {f.disposition !== 'OPEN' ? ` · ${f.disposition}` : ''}
                  {!f.currentVersion ? ' · from an earlier version' : ''}
                </div>
              </div>
            </div>
          ))}
        </Card>
      )}

      {aiNarrative && (
        <Notice tone="info">
          <div className="small muted" style={{ marginBottom: 4 }}>AI advisory analysis — cannot approve or release anything</div>
          {aiNarrative}
        </Notice>
      )}

      {/* ---- Instructions ---- */}
      <Card title={`Instructions (${detail.instructions.total})`}>
        {detail.instructions.total === 0 ? (
          <Empty title="No instructions" hint="Upload a CSV to populate this batch." />
        ) : (
          <div className="table-wrap" style={{ maxHeight: 320, overflowY: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Recipient</th>
                  <th>Phone</th>
                  <th className="num">Amount</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {detail.instructions.rows.map((i) => (
                  <tr key={i.instructionId}>
                    <td className="small muted">{i.sourceLineNumber ?? '—'}</td>
                    <td>{i.recipientName}</td>
                    <td className="mono small">{i.msisdn}</td>
                    <td className="num"><Amount cents={i.amountCents} /></td>
                    <td><StatusChip status={i.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* ---- Approval history ---- */}
      {detail.approvals.length > 0 && (
        <Card title="Approval history">
          <ul className="timeline">
            {detail.approvals.map((a, i) => (
              <li key={i}>
                <time>{new Date(a.created_at).toLocaleString()}</time>
                <div>
                  <span className="strong">{a.action}</span> by {a.actor_name} ({a.actor_level})
                  {a.reason && <div className="small muted">“{a.reason}”</div>}
                  <div className="small muted">version {a.batch_version}</div>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Create batch
// ---------------------------------------------------------------------------

function CreateBatchModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [purpose, setPurpose] = useState('');
  const [paymentPeriod, setPaymentPeriod] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.batches.create(purpose, paymentPeriod || undefined);
      onCreated();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose}>
      <h2>New payment batch</h2>
      {error && <Notice tone="danger">{error.message}</Notice>}
      <form onSubmit={create}>
        <label className="field">
          <span className="field-label">Purpose</span>
          <input className="input" value={purpose} onChange={(e) => setPurpose(e.target.value)} placeholder="September 2026 payroll" required minLength={3} />
        </label>
        <label className="field">
          <span className="field-label">Payment period (optional)</span>
          <input className="input" value={paymentPeriod} onChange={(e) => setPaymentPeriod(e.target.value)} placeholder="2026-09" />
        </label>
        <div className="card-footer" style={{ marginTop: 16 }}>
          <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button" data-variant="primary" disabled={busy}>Create draft</button>
        </div>
      </form>
    </Modal>
  );
}

export { requestWebAuthnAssertion };
