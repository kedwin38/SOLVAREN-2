/**
 * Settings (spec §22): Daraja configuration (L3-only surface, AC-16), organization
 * policies, the dynamic permission engine (AC-17), batch templates and notification
 * channels. Every L3 mutation here requires fresh auth + WebAuthn + FPAC PIN server-side.
 */

import { useEffect, useState } from 'react';
import { api, ApiError } from '../lib/api.js';
import { Card, Empty, ErrorPane, Loading, Notice, PageHeader, relativeTime } from '../components/primitives.js';

export function SettingsPage() {
  const [tab, setTab] = useState<'daraja' | 'policies' | 'permissions' | 'templates'>('daraja');
  const [error, setError] = useState<ApiError | null>(null);

  return (
    <>
      <PageHeader title="Settings" subtitle="Daraja integration, organization policies, permissions, scheduling" />

      {error && <ErrorPane error={error} />}

      <div className="filters" style={{ gap: 8 }}>
        {(['daraja', 'policies', 'permissions', 'templates'] as const).map((t) => (
          <button key={t} className="button button-sm" data-variant={tab === t ? 'primary' : 'ghost'} onClick={() => setTab(t)}>
            {t === 'daraja' ? 'Daraja' : t === 'policies' ? 'Policies' : t === 'permissions' ? 'Permissions' : 'Templates'}
          </button>
        ))}
      </div>

      {tab === 'daraja' && <DarajaTab />}
      {tab === 'policies' && <PoliciesTab />}
      {tab === 'permissions' && <PermissionsTab />}
      {tab === 'templates' && <TemplatesTab />}
    </>
  );
}

// ---------------------------------------------------------------------------
// Daraja
// ---------------------------------------------------------------------------

interface DarajaConfigView {
  id: string;
  environment: string;
  shortCode: string;
  initiatorName: string;
  commandId: string;
  consumerKeyMasked: string;
  credentialVersion: number;
  credentialRotatedAt: string | null;
  status: string;
  lastTestOk: boolean | null;
  lastTestMessage: string | null;
}

function DarajaTab() {
  const [configs, setConfigs] = useState<DarajaConfigView[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [configureOpen, setConfigureOpen] = useState(false);
  const [callbackInfo, setCallbackInfo] = useState<{ secret: string; urls: { resultUrl: string } } | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const load = async () => {
    try {
      const data = (await api.admin.daraja.list()) as unknown as { configurations: DarajaConfigView[] };
      setConfigs(data.configurations);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  };

  useEffect(() => {
    void load();
  }, [reloadKey]);

  return (
    <>
      {notice && <Notice tone="success">{notice}</Notice>}
      {callbackInfo && (
        <Notice tone="warning">
          <div className="strong">Register these callback URLs on the Daraja portal now.</div>
          <div className="mono small" style={{ marginTop: 4 }}>{callbackInfo.urls.resultUrl}</div>
          <div className="small muted" style={{ marginTop: 4 }}>The secret is embedded in the URL and shown only this once. Register it, then run a connection test.</div>
        </Notice>
      )}

      <Card
        title="Daraja integration"
        footer={
          <button className="button" data-variant="primary" onClick={() => setConfigureOpen(true)}>
            {configs && configs.length > 0 ? 'Rotate credentials' : 'Configure Daraja'}
          </button>
        }
      >
        {!configs ? (
          <Loading />
        ) : configs.length === 0 ? (
          <Empty title="No Daraja configuration" hint="Configure the integration to enable payment execution." />
        ) : (
          configs.map((c) => (
            <div key={c.id}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
              <div>
                <div className="small muted">Environment</div>
                <div className="strong">{c.environment}</div>
              </div>
              <div>
                <div className="small muted">Shortcode</div>
                <div className="mono">{c.shortCode}</div>
              </div>
              <div>
                <div className="small muted">Consumer key</div>
                <div className="mono">{c.consumerKeyMasked}</div>
              </div>
              <div>
                <div className="small muted">Credential version</div>
                <div>v{c.credentialVersion} {c.credentialRotatedAt ? `· ${relativeTime(c.credentialRotatedAt)}` : ''}</div>
              </div>
              <div>
                <div className="small muted">Status</div>
                <span className="chip" data-tone={c.status === 'ENABLED' ? 'success' : c.status === 'ERROR' ? 'danger' : 'warning'}>
                  {c.status}
                </span>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                <button className="button button-sm" onClick={() => void api.admin.daraja.test(c.id).then((r) => setNotice(r.message)).then(() => setReloadKey((k) => k + 1)).catch((e) => setError(e instanceof ApiError ? e : null))}>
                  Test
                </button>
                {c.status !== 'ENABLED' && c.lastTestOk && (
                  <button className="button button-sm" data-variant="primary" onClick={() => void api.admin.daraja.enable(c.id).then(() => setReloadKey((k) => k + 1)).catch((e) => setError(e instanceof ApiError ? e : null))}>
                    Enable
                  </button>
                )}
                {c.status === 'ENABLED' && (
                  <button
                    className="button button-sm"
                    data-variant="danger"
                    onClick={() => {
                      const reason = window.prompt('Reason for disabling the integration?');
                      if (reason && reason.length >= 3) {
                        void api.admin.daraja.disable(c.id, reason).then(() => setReloadKey((k) => k + 1)).catch((e) => setError(e instanceof ApiError ? e : null));
                      }
                    }}
                  >
                    Disable
                  </button>
                )}
              </div>
              </div>
              <TestPaymentPanel configId={c.id} environment={c.environment} />
            </div>
          ))
        )}
      </Card>

      {configureOpen && (
        <ConfigureDarajaModal
          onClose={() => setConfigureOpen(false)}
          onConfigured={(info) => {
            setConfigureOpen(false);
            setCallbackInfo(info);
            setReloadKey((k) => k + 1);
          }}
        />
      )}
    </>
  );
}

/**
 * Live test payment: send a real, minimal B2C disbursement to a phone number and watch
 * its full lifecycle — submission, callback, receipt — with an on-demand status query
 * against M-PESA if the result is slow to arrive. The payment rides the production
 * ledger, so it is tracked and reconciled exactly like any disbursement.
 */
function TestPaymentPanel({ configId, environment }: { configId: string; environment: string }) {
  const [open, setOpen] = useState(false);
  const [msisdn, setMsisdn] = useState('');
  const [amountKes, setAmountKes] = useState(10);
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [txn, setTxn] = useState<Awaited<ReturnType<typeof api.admin.daraja.testPaymentStatus>> | null>(null);
  const [refreshNote, setRefreshNote] = useState<string | null>(null);

  useEffect(() => {
    if (!txn || txn.terminal) return;
    const timer = setInterval(() => {
      void api.admin.daraja
        .testPaymentStatus(configId, txn.transactionId)
        .then((next) => setTxn(next))
        .catch(() => {});
    }, 3000);
    return () => clearInterval(timer);
  }, [txn, configId]);

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setRefreshNote(null);
    try {
      const result = await api.admin.daraja.testPayment(configId, {
        msisdn,
        amountKes,
        authorizationPin: pin,
      });
      setPin('');
      const status = await api.admin.daraja.testPaymentStatus(configId, result.transactionId);
      setTxn(status);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  const tone =
    txn?.status === 'SUCCESS' ? 'success' : txn?.status === 'FAILED' ? 'danger' : txn ? 'warning' : 'neutral';

  return (
    <div style={{ padding: '0 0 14px', borderBottom: '1px solid var(--border)' }}>
      {!open ? (
        <button className="button button-sm" data-variant="ghost" onClick={() => setOpen(true)}>
          Send test payment ({environment})
        </button>
      ) : (
        <>
          <form onSubmit={send} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end', margin: 0 }}>
            <label className="field" style={{ margin: 0, minWidth: 180 }}>
              <span className="field-label">Phone number</span>
              <input
                className="input mono"
                placeholder="07XX XXX XXX or 2547XXXXXXXX"
                value={msisdn}
                onChange={(e) => setMsisdn(e.target.value)}
                required
              />
            </label>
            <label className="field" style={{ margin: 0, width: 110 }}>
              <span className="field-label">Amount (KES)</span>
              <input
                className="input mono"
                type="number"
                min={10}
                max={10000}
                step={1}
                value={amountKes}
                onChange={(e) => setAmountKes(Number(e.target.value))}
                required
              />
            </label>
            <label className="field" style={{ margin: 0, width: 130 }}>
              <span className="field-label">PIN</span>
              <input
                className="input mono"
                type="password"
                inputMode="numeric"
                value={pin}
                onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 12))}
                required
              />
            </label>
            <button className="button" data-variant="primary" type="submit" disabled={busy}>
              {busy ? 'Sending…' : `Send KES ${amountKes}`}
            </button>
            <button className="button" data-variant="ghost" type="button" onClick={() => { setOpen(false); setTxn(null); setError(null); }}>
              Close
            </button>
          </form>
          <div className="small muted" style={{ marginTop: 6 }}>
            Minimum KES 10 — the M-PESA B2C floor. The payment is real money to a real phone, tracked on the
            ledger and reconciled automatically if the callback is delayed.
          </div>
          {error && <Notice tone="danger">{error.message}</Notice>}

          {txn && (
            <div className="card" style={{ marginTop: 12, marginBottom: 0, padding: 16 }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <span className="chip" data-tone={tone}>{txn.status.replace(/_/g, ' ')}</span>
                {!txn.terminal && (
                  <>
                    <span className="spinner" aria-hidden="true" style={{ width: 14, height: 14 }} />
                    <span className="small muted">Tracking…</span>
                    <button
                      className="button button-sm"
                      type="button"
                      onClick={() =>
                        void api.admin.daraja
                          .testPaymentRefresh(configId, txn.transactionId)
                          .then((r) => setRefreshNote(r.note))
                          .catch((e) => setError(e instanceof ApiError ? e : null))
                      }
                    >
                      Query M-PESA now
                    </button>
                  </>
                )}
                {txn.terminal && (
                  <button className="button button-sm" data-variant="ghost" type="button" onClick={() => setTxn(null)}>
                    Clear
                  </button>
                )}
              </div>

              {txn.receipt && (
                <div style={{ marginTop: 10 }}>
                  <div className="small muted">M-PESA receipt (transaction code)</div>
                  <div
                    className="mono"
                    style={{ fontSize: 20, fontWeight: 700, letterSpacing: '0.04em', cursor: 'pointer' }}
                    title="Click to copy"
                    onClick={() => void navigator.clipboard?.writeText(txn.receipt!).then(() => setRefreshNote('Receipt copied to clipboard.'))}
                  >
                    {txn.receipt}
                  </div>
                </div>
              )}

              {(txn.failureReason || txn.providerDescription) && (
                <div className="small" style={{ marginTop: 8 }}>
                  {txn.failureCode && <span className="mono muted">{txn.failureCode} — </span>}
                  {txn.failureReason ?? txn.providerDescription}
                </div>
              )}

              <div className="small muted mono" style={{ marginTop: 8, wordBreak: 'break-all' }}>
                Originator: {txn.originatorConversationId}
                {txn.conversationId ? ` · Conversation: ${txn.conversationId}` : ''}
              </div>
              {refreshNote && <div className="small muted" style={{ marginTop: 4 }}>{refreshNote}</div>}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function ConfigureDarajaModal({ onClose, onConfigured }: { onClose: () => void; onConfigured: (info: { secret: string; urls: { resultUrl: string } }) => void }) {
  const [environment, setEnvironment] = useState<'sandbox' | 'production'>('sandbox');
  const [shortCode, setShortCode] = useState('');
  const [initiatorName, setInitiatorName] = useState('');
  const [consumerKey, setConsumerKey] = useState('');
  const [consumerSecret, setConsumerSecret] = useState('');
  const [initiatorPasswordOrCredential, setInitiatorPasswordOrCredential] = useState('');
  const [certMode, setCertMode] = useState<'paste' | 'upload'>('paste');
  const [mpesaCertificatePem, setMpesaCertificatePem] = useState('');
  const [certFileInfo, setCertFileInfo] = useState<string | null>(null);
  const [certError, setCertError] = useState<string | null>(null);
  const [authorizationPin, setAuthorizationPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  /**
   * Accept an M-PESA public certificate as uploaded from the Daraja portal.
   * Handles all three forms the portal hands out: PEM text, a text file of bare
   * base64, and a binary DER .cer/.der. Binary DER is base64-encoded here because
   * the API takes text — the server's DER walker accepts base64-encoded DER.
   */
  async function onCertificateFile(file: File) {
    setCertError(null);
    setCertFileInfo(null);
    try {
      const buffer = new Uint8Array(await file.arrayBuffer());
      const kb = (buffer.byteLength / 1024).toFixed(1);
      let text: string | null = null;
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
      } catch {
        text = null; // binary
      }

      if (text !== null) {
        const trimmed = text.trim();
        if (trimmed.startsWith('-----BEGIN')) {
          setMpesaCertificatePem(trimmed);
          setCertFileInfo(`${file.name} · ${kb} KB · PEM certificate`);
        } else if (/^[A-Za-z0-9+/=\s]+$/.test(trimmed) && trimmed.replace(/\s+/g, '').length > 100) {
          setMpesaCertificatePem(trimmed);
          setCertFileInfo(`${file.name} · ${kb} KB · base64 certificate`);
        } else {
          setCertError('That file is neither a PEM certificate nor base64 certificate data.');
        }
      } else if (buffer[0] === 0x30) {
        // DER: an ASN.1 SEQUENCE — base64 the bytes; the server decodes and walks them.
        let binary = '';
        const chunk = 0x8000;
        for (let i = 0; i < buffer.length; i += chunk) {
          binary += String.fromCharCode(...buffer.subarray(i, i + chunk));
        }
        setMpesaCertificatePem(btoa(binary));
        setCertFileInfo(`${file.name} · ${kb} KB · binary DER — converted`);
      } else {
        setCertError('That file does not look like a certificate (expected DER, PEM or base64).');
      }
    } catch {
      setCertError('The certificate file could not be read.');
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.admin.daraja.configure({
        environment,
        shortCode,
        initiatorName,
        consumerKey,
        consumerSecret,
        initiatorPasswordOrCredential,
        ...(mpesaCertificatePem.trim() ? { mpesaCertificatePem: mpesaCertificatePem.trim() } : {}),
        authorizationPin,
      });
      onConfigured({ secret: result.callbackSecret, urls: result.callbackUrls });
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="modal modal-wide" role="dialog" aria-modal="true">
        <h2>Configure Daraja {configsExistHint() ? '— credential rotation' : ''}</h2>
        <p className="muted small">
          Requires fresh authentication + WebAuthn + your Frontier Authorization PIN. Secrets are encrypted at rest and shown masked thereafter — never again in plaintext to anyone.
        </p>
        {error && <Notice tone="danger">{error.message}</Notice>}
        <form onSubmit={submit}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <label className="field">
              <span className="field-label">Environment</span>
              <select className="select" value={environment} onChange={(e) => setEnvironment(e.target.value as 'sandbox' | 'production')}>
                <option value="sandbox">Sandbox</option>
                <option value="production">Production</option>
              </select>
            </label>
            <label className="field">
              <span className="field-label">Shortcode (5–9 digits)</span>
              <input className="input mono" value={shortCode} onChange={(e) => setShortCode(e.target.value)} required pattern="\d{5,9}" />
            </label>
            <label className="field">
              <span className="field-label">Initiator name</span>
              <input className="input" value={initiatorName} onChange={(e) => setInitiatorName(e.target.value)} required />
            </label>
            <label className="field">
              <span className="field-label">Command</span>
              <span className="mono small">BusinessPayment (default)</span>
            </label>
            <label className="field">
              <span className="field-label">Consumer key</span>
              <input className="input mono" value={consumerKey} onChange={(e) => setConsumerKey(e.target.value)} required minLength={10} />
            </label>
            <label className="field">
              <span className="field-label">Consumer secret</span>
              <input className="input mono" type="password" value={consumerSecret} onChange={(e) => setConsumerSecret(e.target.value)} required minLength={10} />
            </label>
          </div>
          <label className="field">
            <span className="field-label">Initiator password OR pre-computed SecurityCredential</span>
            <textarea
              className="textarea mono"
              rows={2}
              placeholder="Initiator password, or paste the base64 SecurityCredential from the portal (line wrapping is fine)"
              value={initiatorPasswordOrCredential}
              onChange={(e) => setInitiatorPasswordOrCredential(e.target.value)}
              required
            />
          </label>
          <div className="field">
            <span className="field-label">
              M-PESA public certificate — required with a password, not with a pre-computed credential
            </span>
            <div className="segmented" role="group" aria-label="Certificate input method">
              <button
                type="button"
                className="segmented-item"
                aria-pressed={certMode === 'paste'}
                onClick={() => { setCertMode('paste'); setCertError(null); }}
              >
                Paste
              </button>
              <button
                type="button"
                className="segmented-item"
                aria-pressed={certMode === 'upload'}
                onClick={() => { setCertMode('upload'); setCertError(null); }}
              >
                Upload file
              </button>
            </div>

            {certMode === 'paste' ? (
              <textarea
                className="textarea mono"
                rows={3}
                placeholder={'-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n\nor paste base64 certificate data'}
                value={mpesaCertificatePem}
                onChange={(e) => { setMpesaCertificatePem(e.target.value); setCertFileInfo(null); }}
              />
            ) : (
              <label className="file-field">
                <input
                  type="file"
                  accept=".cer,.der,.crt,.pem,application/pkix-cert,application/x-x509-ca-cert,application/x-pem-file"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void onCertificateFile(file);
                  }}
                />
                <span className="file-field-label">Choose certificate file</span>
                <span className="file-field-hint">.cer · .der · .crt · .pem — binary DER is converted automatically</span>
                {certFileInfo && <span className="file-field-status">{certFileInfo}</span>}
              </label>
            )}
            {certError && <div className="small" style={{ color: 'var(--danger)', marginTop: 4 }}>{certError}</div>}
          </div>
          <label className="field" style={{ maxWidth: 260 }}>
            <span className="field-label">Your Frontier Authorization PIN</span>
            <input className="input mono" type="password" inputMode="numeric" value={authorizationPin} onChange={(e) => setAuthorizationPin(e.target.value.replace(/\D/g, '').slice(0, 12))} required />
          </label>
          <div className="card-footer">
            <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
            <button type="submit" className="button" data-variant="primary" disabled={busy}>
              {busy ? 'Saving…' : 'Save configuration'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );

  function configsExistHint(): string {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

function PoliciesTab() {
  const [policy, setPolicy] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    void api.admin.policies.get().then((d) => setPolicy(d.policy)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, []);

  async function save(patch: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.admin.policies.update(patch);
      setPolicy(result.policy);
      setNotice('Policy updated. The change is enforced on the next release attempt.');
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  if (error && !policy) return <ErrorPane error={error} />;
  if (!policy) return <Loading />;

  // Per-field policy bounds in KES (mirror of the server schema, in input units) so a
  // bad edit is caught in the form instead of surfacing as a generic server rejection.
  const POLICY_BOUNDS_KES: Record<string, { min: number; max: number }> = {
    maxInstructionAmountCents: { min: 10, max: 250_000 },
    maxBatchTotalCents: { min: 10, max: 500_000_000 },
    highValueThresholdCents: { min: 0, max: 500_000_000 },
    dailyDisbursementCeilingCents: { min: 0, max: 500_000_000 },
  };

  const numberField = (key: string, label: string, hint?: string) => {
    const bounds = POLICY_BOUNDS_KES[key]!;
    return (
      <label className="field">
        <span className="field-label">{label}</span>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            className="input"
            type="number"
            defaultValue={Number(policy[key] ?? 0) / 100}
            step="0.01"
            min={bounds.min}
            max={bounds.max}
            onBlur={(e) => {
              const raw = e.target.value.trim();
              if (raw === '') return; // mid-edit; do not save an empty field
              const kes = Number(raw);
              if (!Number.isFinite(kes) || kes < bounds.min || kes > bounds.max) {
                setError(
                  new ApiError(400, {
                    code: 'FIELD_OUT_OF_RANGE',
                    category: 'VALIDATION',
                    message: `${label} must be between KES ${bounds.min.toLocaleString()} and ${bounds.max.toLocaleString()}. Nothing was saved.`,
                  }),
                );
                e.target.value = String(Number(policy[key] ?? 0) / 100);
                return;
              }
              const cents = Math.round(kes * 100);
              if (cents !== Number(policy[key])) void save({ [key]: cents });
            }}
          />
          <span className="muted small" style={{ alignSelf: 'center' }}>KES</span>
        </div>
        {hint && <span className="small muted">{hint}</span>}
      </label>
    );
  };

  return (
    <>
      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}

      <Card title="Payment limits" footer={<span className="small muted">{busy ? 'Saving…' : 'Changes save on field blur — every change is audited and bound into future release manifests.'}</span>}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          {numberField('maxInstructionAmountCents', 'Max per instruction', 'M-PESA hard cap: KES 250,000')}
          {numberField('maxBatchTotalCents', 'Max batch total')}
          {numberField('highValueThresholdCents', 'High-value threshold', 'Above this, the ceremony requires an extra acknowledgement')}
          {numberField('dailyDisbursementCeilingCents', 'Daily disbursement ceiling', '0 disables the circuit breaker')}
        </div>
      </Card>

      <Card title="Workflow controls">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
          <label className="field">
            <span className="field-label">Cooling-off after edit (seconds)</span>
            <input
              className="input"
              type="number"
              defaultValue={Number(policy.coolingOffSeconds ?? 300)}
              min={0}
              max={86400}
              onBlur={(e) => {
                const raw = e.target.value.trim();
                if (raw === '') return; // mid-edit; do not save an empty field
                const v = Number(raw);
                if (!Number.isFinite(v) || v < 0 || v > 86400) {
                  setError(
                    new ApiError(400, {
                      code: 'FIELD_OUT_OF_RANGE',
                      category: 'VALIDATION',
                      message: 'Cooling-off must be between 0 and 86,400 seconds. Nothing was saved.',
                    }),
                  );
                  e.target.value = String(Number(policy.coolingOffSeconds ?? 300));
                  return;
                }
                if (v !== Number(policy.coolingOffSeconds)) void save({ coolingOffSeconds: v });
              }}
            />
          </label>
          <label className="field">
            <span className="field-label">Release cut-off (EAT, HH:MM)</span>
            <input
              className="input"
              placeholder="17:00 or empty"
              defaultValue={String(policy.releaseCutoffLocalTime ?? '')}
              onBlur={(e) => {
                const v = e.target.value.trim();
                if (v !== String(policy.releaseCutoffLocalTime ?? '') && (v === '' || /^\d{2}:\d{2}$/.test(v))) void save({ releaseCutoffLocalTime: v });
              }}
            />
          </label>
          <label className="field">
            <span className="field-label">Risk band that blocks release</span>
            <select
              className="select"
              defaultValue={String(policy.blockingRiskBand ?? 'CRITICAL')}
              onChange={(e) => void save({ blockingRiskBand: e.target.value })}
            >
              <option value="NEVER">Never (advisory only)</option>
              <option value="HIGH">High and above</option>
              <option value="CRITICAL">Critical only</option>
            </select>
          </label>
        </div>
      </Card>
    </>
  );
}

// ---------------------------------------------------------------------------
// Dynamic permission engine (AC-17)
// ---------------------------------------------------------------------------

function PermissionsTab() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.admin.permissions.overview>> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.admin.permissions.overview().then(setData).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  async function toggle(level: 'L1' | 'L2', permission: string, effect: 'GRANT' | 'REVOKE') {
    const reason = window.prompt(`Reason for ${effect === 'GRANT' ? 'granting' : 'revoking'} “${permission}” for ${level}? (kept in the audit trail)`);
    if (!reason || reason.trim().length < 3) return;
    try {
      const result = await api.admin.permissions.override({ level, permission, effect, reason });
      setNotice(result.note);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  async function reset() {
    const reason = window.prompt('Reason for restoring the baseline permission matrix?');
    if (!reason || reason.trim().length < 3) return;
    try {
      await api.admin.permissions.reset(reason);
      setNotice('Baseline matrix restored.');
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  if (error && !data) return <ErrorPane error={error} />;
  if (!data) return <Loading />;

  const ceilingSet = new Set([...(data.ceilings['L1'] ?? []), ...(data.ceilings['L2'] ?? [])]);

  return (
    <>
      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}

      <Notice tone="info">
        Changes are live immediately (every request recomputes the effective matrix) and are audited as
        high-severity authority events. Ceiling-protected capabilities can never be granted — the engine
        refuses them regardless of who asks. Level 3 authority itself is not configurable.
      </Notice>

      {(['L1', 'L2'] as const).map((level) => (
        <Card key={level} title={`${level} effective permissions`} footer={
          <button className="button" data-variant="ghost" onClick={() => void reset()}>Restore baseline (both levels)</button>
        }>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 4 }}>
            {data.catalogue
              .filter((p) => !(data.baseline[level] ?? []).includes(p) || (data.effective[level] ?? []).includes(p))
              .map((permission) => {
                const held = (data.effective[level] ?? []).includes(permission);
                const ceiling = ceilingSet.has(permission);
                return (
                  <label key={permission} className="checkbox" style={{ opacity: ceiling ? 0.45 : 1 }}>
                    <input
                      type="checkbox"
                      checked={held}
                      disabled={ceiling}
                      onChange={(e) => void toggle(level, permission, e.target.checked ? 'GRANT' : 'REVOKE')}
                    />
                    <span>
                      <span className="mono small">{permission}</span>
                      {ceiling && <span className="small muted"> — ceiling-protected</span>}
                    </span>
                  </label>
                );
              })}
          </div>
        </Card>
      ))}

      {data.overrides.length > 0 && (
        <Card title="Override history (versioned)">
          <ul className="timeline">
            {data.overrides.slice(0, 15).map((o) => (
              <li key={o.id}>
                <time>{relativeTime(o.createdAt)}</time>
                <div>
                  <span className={`chip`} data-tone={o.superseded ? 'neutral' : o.effect === 'GRANT' ? 'success' : 'warning'}>
                    {o.effect}{o.superseded ? ' (superseded)' : ''}
                  </span>{' '}
                  <span className="mono small">{o.permission}</span> for <strong>{o.level}</strong> · v{o.version}
                  <div className="small muted">“{o.reason}”</div>
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

function TemplatesTab() {
  const [templates, setTemplates] = useState<Awaited<ReturnType<typeof api.admin.templates.list>>['templates'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.admin.templates.list().then((d) => setTemplates(d.templates)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  if (error) return <ErrorPane error={error} />;
  if (!templates) return <Loading />;

  return (
    <Card title="Recurring batch templates">
      {templates.length === 0 ? (
        <Empty title="No templates" hint="Templates are created by the API today; scheduling and materialization run automatically once enabled." />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Schedule</th>
                <th className="num">Items</th>
                <th>Next run</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {templates.map((t) => (
                <tr key={t.templateId}>
                  <td>
                    <div className="strong">{t.name}</div>
                    <div className="small muted">{t.purpose}</div>
                  </td>
                  <td className="mono small">{t.scheduleCron}</td>
                  <td className="num">{t.itemCount}</td>
                  <td className="small muted">{t.nextRunAt ? new Date(t.nextRunAt).toLocaleString() : '—'}</td>
                  <td>
                    <span className="chip" data-tone={t.scheduleEnabled ? 'success' : 'neutral'}>
                      {t.scheduleEnabled ? 'enabled' : 'disabled'}
                    </span>
                  </td>
                  <td>
                    <button
                      className="button button-sm"
                      onClick={() => void api.admin.templates.setEnabled(t.templateId, !t.scheduleEnabled).then(() => setReloadKey((k) => k + 1)).catch((e) => setError(e instanceof ApiError ? e : null))}
                    >
                      {t.scheduleEnabled ? 'Disable' : 'Enable'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
