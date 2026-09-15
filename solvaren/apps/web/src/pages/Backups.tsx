/**
 * Backups (spec §13, §22): connection status, schedule, retention, last success/failure,
 * Run Backup Now, attempt history with artifact metadata. The UI clearly separates
 * REQUESTED / RUNNING / SUCCESS / FAILED (§13.7).
 */

import { useEffect, useState } from 'react';
import { api, ApiError } from '../lib/api.js';
import { Card, Empty, ErrorPane, Loading, Modal, Notice, PageHeader, Stat, relativeTime } from '../components/primitives.js';

export function BackupsPage({ onRan }: { onRan: (reference: string) => void }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.admin.backups.overview>> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [configureOpen, setConfigureOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.admin.backups.overview().then(setData).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  // Auto-refresh while a backup is running.
  useEffect(() => {
    if (data?.latestResult?.status === 'RUNNING' || data?.latestResult?.status === 'QUEUED') {
      const timer = setInterval(() => setReloadKey((k) => k + 1), 4000);
      return () => clearInterval(timer);
    }
  }, [data]);

  async function run() {
    try {
      const result = await api.admin.backups.run();
      onRan(result.attemptReference);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  async function test() {
    try {
      const result = await api.admin.backups.test();
      setNotice(result.ok ? `Connection test passed: ${result.message}` : `Connection test FAILED: ${result.message}`);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  if (error && !data) return <ErrorPane error={error} />;
  if (!data) return <Loading label="Loading backups" />;

  const config = data.configuration;
  const latest = data.latestResult;

  return (
    <>
      <PageHeader
        title="Backups"
        subtitle="Offsite full-database snapshots to S3-compatible storage"
        actions={
          <>
            {config && <button className="button" onClick={() => void test()}>Test connection</button>}
            <button className="button" data-variant="primary" onClick={() => void run()} disabled={!config}>
              Run backup now
            </button>
          </>
        }
      />

      {notice && <Notice tone={notice.includes('FAILED') ? 'danger' : 'success'}>{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}

      {!config ? (
        <Card title="No backup target configured">
          <Empty title="Connect S3-compatible storage" hint="Configure a bucket, test the connection, then enable the schedule." />
          <div className="card-footer">
            <button className="button" data-variant="primary" onClick={() => setConfigureOpen(true)}>Connect storage</button>
          </div>
        </Card>
      ) : (
        <>
          {latest && (
            <Card title="Latest result">
              <div className="stat-grid">
                <Stat
                  label="Status"
                  value={
                    <span className={`chip`} data-tone={latest.status === 'SUCCESS' ? 'success' : latest.status === 'FAILED' || latest.status === 'MISSED' ? 'danger' : 'warning'}>
                      {latest.status}
                    </span>
                  }
                  hint={`${latest.trigger} · ${latest.startedAt ? relativeTime(latest.startedAt) : '—'}`}
                />
                {latest.sizeBytes !== null && <Stat label="Size" value={`${(latest.sizeBytes / 1024 / 1024).toFixed(1)} MB`} />}
                {latest.checksum && <Stat label="SHA-256" value={<span className="mono small">{latest.checksum.slice(0, 16)}…</span>} />}
                {latest.errorMessage && (
                  <div className="notice notice-danger" style={{ gridColumn: '1 / -1' }}>
                    <div className="strong">Backup failed</div>
                    <div className="small">{latest.errorMessage}</div>
                  </div>
                )}
              </div>
            </Card>
          )}

          <Card
            title="Schedule & retention"
            footer={
              <button
                className="button"
                onClick={() => {
                  const enabled = !config.scheduleEnabled;
                  void api.admin.backups
                    .schedule({ enabled, ...(enabled ? { localTime: config.scheduleLocalTime } : {}) })
                    .then(() => setNotice(enabled ? 'Schedule enabled.' : 'Schedule disabled.'))
                    .then(() => setReloadKey((k) => k + 1))
                    .catch((e) => setError(e instanceof ApiError ? e : null));
                }}
                disabled={config.scheduleEnabled && false}
              >
                {config.scheduleEnabled ? 'Disable schedule' : 'Enable schedule'}
              </button>
            }
          >
            <div className="stat-grid">
              <Stat label="Daily at (local)" value={config.scheduleLocalTime} hint={config.scheduleTimezone} />
              <Stat label="Next scheduled" value={config.nextScheduledRunAt ? new Date(config.nextScheduledRunAt).toLocaleString() : '—'} />
              <Stat label="Retention" value={`${config.retentionMaxCount} backups`} hint="Oldest deleted after each success" />
              <Stat
                label="Target"
                value={config.bucket}
                hint={`${config.pathPrefix} · ${config.accessKeyMasked}`}
              />
              <Stat
                label="Connection"
                value={
                  <span className={`chip`} data-tone={config.lastTestOk ? 'success' : config.lastTestOk === false ? 'danger' : 'neutral'}>
                    {config.lastTestOk === null ? 'not tested' : config.lastTestOk ? 'verified' : 'failed'}
                  </span>
                }
                hint={config.lastTestAt ? `tested ${relativeTime(config.lastTestAt)}` : undefined}
              />
              {config.suspended && (
                <Stat label="Suspended" value="yes" tone="danger" hint={config.suspensionReason ?? undefined} />
              )}
            </div>
          </Card>

          <Card title="Attempt history">
            {data.history.length === 0 ? (
              <Empty title="No backups yet" />
            ) : (
              <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Reference</th>
                      <th>Trigger</th>
                      <th>Status</th>
                      <th>Started</th>
                      <th className="num">Size</th>
                      <th>Object</th>
                      <th>Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.history.map((h) => (
                      <tr key={h.attemptReference}>
                        <td className="mono small">{h.attemptReference}</td>
                        <td className="small">{h.trigger}</td>
                        <td>
                          <span className={`chip`} data-tone={h.status === 'SUCCESS' ? 'success' : h.status === 'FAILED' || h.status === 'MISSED' ? 'danger' : 'warning'}>
                            {h.status}
                          </span>
                        </td>
                        <td className="small muted">{h.startedAt ? relativeTime(h.startedAt) : '—'}</td>
                        <td className="num small">{h.sizeBytes ? `${(h.sizeBytes / 1024 / 1024).toFixed(1)} MB` : '—'}</td>
                        <td className="small">{h.objectRetained ? 'retained' : h.status === 'SUCCESS' ? 'retired' : '—'}</td>
                        <td className="small" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={h.errorMessage ?? ''}>
                          {h.errorMessage ?? ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="small muted" style={{ marginTop: 8 }}>
              {data.restoreValidationNote}
            </p>
          </Card>
        </>
      )}

      {configureOpen && (
        <ConfigureBackupModal
          onClose={() => setConfigureOpen(false)}
          onConfigured={() => {
            setConfigureOpen(false);
            setNotice('Target configured. Run a connection test before enabling the schedule.');
            setReloadKey((k) => k + 1);
          }}
        />
      )}
    </>
  );
}

function ConfigureBackupModal({ onClose, onConfigured }: { onClose: () => void; onConfigured: () => void }) {
  const [providerLabel, setProviderLabel] = useState('S3-compatible');
  const [endpoint, setEndpoint] = useState('');
  const [region, setRegion] = useState('');
  const [bucket, setBucket] = useState('');
  const [pathPrefix, setPathPrefix] = useState('solvaren/backups');
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [retention, setRetention] = useState(30);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.admin.backups.configure({
        providerLabel,
        ...(endpoint.trim() ? { endpoint: endpoint.trim() } : {}),
        ...(region.trim() ? { region: region.trim() } : {}),
        bucket,
        ...(pathPrefix ? { pathPrefix } : {}),
        accessKeyId,
        secretAccessKey,
        retentionMaxCount: retention,
      });
      onConfigured();
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal open onClose={onClose}>
      <h2>Connect S3-compatible storage</h2>
      <p className="muted small">Credentials are encrypted at rest and masked in every response thereafter.</p>
      {error && <Notice tone="danger">{error.message}</Notice>}
      <form onSubmit={submit}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <label className="field">
            <span className="field-label">Provider label</span>
            <input className="input" value={providerLabel} onChange={(e) => setProviderLabel(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Bucket</span>
            <input className="input mono" value={bucket} onChange={(e) => setBucket(e.target.value)} required />
          </label>
          <label className="field">
            <span className="field-label">Endpoint (for R2/MinIO)</span>
            <input className="input mono" placeholder="https://account.r2.cloudflarestorage.com" value={endpoint} onChange={(e) => setEndpoint(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Region</span>
            <input className="input" placeholder="auto" value={region} onChange={(e) => setRegion(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Access key ID</span>
            <input className="input mono" value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} required />
          </label>
          <label className="field">
            <span className="field-label">Secret access key</span>
            <input className="input mono" type="password" value={secretAccessKey} onChange={(e) => setSecretAccessKey(e.target.value)} required />
          </label>
          <label className="field">
            <span className="field-label">Path prefix</span>
            <input className="input mono" value={pathPrefix} onChange={(e) => setPathPrefix(e.target.value)} />
          </label>
          <label className="field">
            <span className="field-label">Retention count</span>
            <input className="input" type="number" min={1} max={3650} value={retention} onChange={(e) => setRetention(Number(e.target.value))} />
          </label>
        </div>
        <div className="card-footer">
          <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button" data-variant="primary" disabled={busy}>{busy ? 'Saving…' : 'Save target'}</button>
        </div>
      </form>
    </Modal>
  );
}
