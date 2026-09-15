/**
 * Security center (spec §22): devices, security events, the audit viewer with chain
 * verification, notifications, and operator queue diagnostics (spec §10).
 */

import { useEffect, useState } from 'react';
import type { Permission } from '@solvaren/core';
import { api, ApiError } from '../lib/api.js';
import { Card, Empty, ErrorPane, Loading, Notice, PageHeader, relativeTime } from '../components/primitives.js';

export function SecurityPage({ level, capabilities }: { level: 'L1' | 'L2' | 'L3'; capabilities: Record<Permission, boolean> }) {
  const [tab, setTab] = useState<'events' | 'audit' | 'devices' | 'queue'>('events');
  const [error, setError] = useState<ApiError | null>(null);

  const tabs: { id: typeof tab; label: string; visible: boolean }[] = [
    { id: 'events', label: 'Security events', visible: true },
    { id: 'audit', label: 'Audit trail', visible: true },
    { id: 'devices', label: 'Trusted devices', visible: capabilities['admin:security'] },
    { id: 'queue', label: 'Queue diagnostics', visible: capabilities['ops:queue_read'] },
  ];
  const visibleTabs = tabs.filter((t) => t.visible);

  return (
    <>
      <PageHeader title="Security center" subtitle="Authentication, devices, security events, audit evidence" />

      {error && <ErrorPane error={error} />}

      <div className="filters" style={{ gap: 8 }}>
        {visibleTabs.map((t) => (
          <button key={t.id} className="button button-sm" data-variant={tab === t.id ? 'primary' : 'ghost'} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'events' && <SecurityEventsTab />}
      {tab === 'audit' && <AuditTab level={level} />}
      {tab === 'devices' && <DevicesTab />}
      {tab === 'queue' && <QueueTab />}
    </>
  );
}

function SecurityEventsTab() {
  const [events, setEvents] = useState<Awaited<ReturnType<typeof api.security.events>>['events'] | null>(null);
  const [severity, setSeverity] = useState('');
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void api.security.events(severity || undefined).then((d) => setEvents(d.events)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [severity]);

  if (error) return <ErrorPane error={error} />;

  return (
    <Card
      title="Security events"
      footer={
        <select className="select" style={{ width: 'auto' }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="WARNING">Warning</option>
          <option value="INFO">Info</option>
        </select>
      }
    >
      {!events ? (
        <Loading />
      ) : events.length === 0 ? (
        <Empty title="No security events" hint="Failed sign-ins, blocked devices and policy denials appear here." />
      ) : (
        <div className="table-wrap" style={{ maxHeight: 500, overflowY: 'auto' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Event</th>
                <th>Description</th>
                <th>User</th>
                <th>IP</th>
                <th>When</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.eventId}>
                  <td>
                    <span className={`chip`} data-tone={e.severity === 'CRITICAL' ? 'danger' : e.severity === 'WARNING' ? 'warning' : 'neutral'}>
                      {e.severity}
                    </span>
                  </td>
                  <td className="mono small">{e.eventType}</td>
                  <td className="small">{e.description}</td>
                  <td className="small">{e.userName ?? '—'}</td>
                  <td className="mono small">{e.ip ?? '—'}</td>
                  <td className="small muted">{relativeTime(e.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function AuditTab({ level }: { level: 'L1' | 'L2' | 'L3' }) {
  const [events, setEvents] = useState<Awaited<ReturnType<typeof api.security.audit>>['events'] | null>(null);
  const [eventClass, setEventClass] = useState('');
  const [verification, setVerification] = useState<Awaited<ReturnType<typeof api.security.verifyAuditChain>> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    void api.security.audit({ eventClass: eventClass || undefined }).then((d) => setEvents(d.events)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [eventClass]);

  async function verify() {
    setBusy(true);
    try {
      setVerification(await api.security.verifyAuditChain(1, 2000));
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  if (error) return <ErrorPane error={error} />;

  return (
    <>
      {level === 'L3' && (
        <Card
          title="Chain verification"
          footer={
            <button className="button" onClick={() => void verify()} disabled={busy}>
              {busy ? 'Verifying…' : 'Verify audit chain integrity'}
            </button>
          }
        >
          {verification ? (
            <Notice tone={verification.valid ? 'success' : 'danger'} live="assertive">
              {verification.interpretation}
              {verification.verifiedCount > 0 && <div className="small muted">{verification.verifiedCount} events verified.</div>}
            </Notice>
          ) : (
            <p className="muted small">
              Recomputes every event digest and chain link. A break is reported at the exact event where verification failed.
            </p>
          )}
        </Card>
      )}

      <Card
        title="Audit trail"
        footer={
          <select className="select" style={{ width: 'auto' }} value={eventClass} onChange={(e) => setEventClass(e.target.value)}>
            <option value="">All classes</option>
            <option value="IDENTITY">Identity</option>
            <option value="AUTHORITY">Authority</option>
            <option value="PAYMENT">Payment</option>
            <option value="INTEGRATION">Integration</option>
            <option value="SECURITY">Security</option>
            <option value="BACKUP">Backup</option>
            <option value="ADMINISTRATION">Administration</option>
            <option value="DATA_EXPORT">Data export</option>
          </select>
        }
      >
        {!events ? (
          <Loading />
        ) : events.length === 0 ? (
          <Empty title="No audit events" />
        ) : (
          <div className="table-wrap" style={{ maxHeight: 500, overflowY: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Class</th>
                  <th>Action</th>
                  <th>Actor</th>
                  <th>Outcome</th>
                  <th>Object</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_reference}>
                    <td className="small muted">{e.sequence}</td>
                    <td className="small">{e.event_class}</td>
                    <td className="mono small">{e.action}</td>
                    <td className="mono small">{e.actor_id}</td>
                    <td>
                      <span className="chip" data-tone={e.outcome === 'SUCCESS' ? 'success' : e.outcome === 'DENIED' ? 'warning' : 'danger'}>
                        {e.outcome}
                      </span>
                    </td>
                    <td className="mono small">{e.object_id ?? '—'}</td>
                    <td className="small muted">{relativeTime(e.occurred_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}

function DevicesTab() {
  const [devices, setDevices] = useState<Awaited<ReturnType<typeof api.security.devices>>['devices'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.security.devices().then((d) => setDevices(d.devices)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  if (error) return <ErrorPane error={error} />;

  return (
    <Card title="Trusted devices">
      {!devices ? (
        <Loading />
      ) : devices.length === 0 ? (
        <Empty title="No registered devices" hint="Devices register automatically when a security key is used to sign in." />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Device</th>
                <th>Status</th>
                <th>Last IP</th>
                <th>Last active</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.deviceId}>
                  <td>{d.userName}</td>
                  <td className="small">
                    {d.friendlyName}
                    <div className="muted small" style={{ maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {d.userAgent ?? ''}
                    </div>
                  </td>
                  <td>
                    <span className="chip" data-tone={d.trustStatus === 'TRUSTED' ? 'success' : d.trustStatus === 'BLOCKED' || d.revoked ? 'danger' : 'warning'}>
                      {d.revoked ? 'REVOKED' : d.trustStatus}
                    </span>
                  </td>
                  <td className="mono small">{d.lastSeenIp ?? '—'}</td>
                  <td className="small muted">{relativeTime(d.lastActivityAt)}</td>
                  <td>
                    {!d.revoked && (
                      <button
                        className="button button-sm"
                        data-variant="danger"
                        onClick={() => {
                          const reason = window.prompt('Reason for revoking this device?');
                          if (reason && reason.length >= 3) {
                            void api.security.revokeDevice(d.deviceId, reason).then(() => setReloadKey((k) => k + 1));
                          }
                        }}
                      >
                        Revoke
                      </button>
                    )}
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

function QueueTab() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.security.queue>> | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.security.queue().then(setData).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  // Auto-refresh: this is the operator's live view.
  useEffect(() => {
    const timer = setInterval(() => setReloadKey((k) => k + 1), 5000);
    return () => clearInterval(timer);
  }, []);

  if (error) return <ErrorPane error={error} />;

  return (
    <>
      {data && (
        <Card title="Queue summary">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Queue</th>
                  <th>Status</th>
                  <th className="num">Jobs</th>
                  <th>Oldest</th>
                </tr>
              </thead>
              <tbody>
                {data.summary.map((s, i) => (
                  <tr key={i}>
                    <td className="mono small">{s.queue}</td>
                    <td>
                      <span className="chip" data-tone={s.status === 'DEAD_LETTERED' ? 'danger' : s.status === 'PENDING' ? 'info' : s.status === 'SUCCEEDED' ? 'success' : 'neutral'}>
                        {s.status}
                      </span>
                    </td>
                    <td className="num">{s.count}</td>
                    <td className="small muted">{s.oldest ? relativeTime(s.oldest) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      <Card title="Stuck and dead-lettered jobs">
        {!data ? (
          <Loading />
        ) : data.stuckJobs.length === 0 ? (
          <Empty title="Nothing stuck" hint="Dead-lettered, expired-lease and long-pending jobs appear here." />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Queue</th>
                  <th>Status</th>
                  <th className="num">Attempts</th>
                  <th>Last error</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.stuckJobs.map((j) => (
                  <tr key={j.jobId}>
                    <td className="mono small">{j.queue}</td>
                    <td>
                      <span className="chip" data-tone={j.status === 'DEAD_LETTERED' ? 'danger' : 'warning'}>
                        {j.status}
                      </span>
                    </td>
                    <td className="num">
                      {j.attempts}/{j.maxAttempts}
                    </td>
                    <td className="small" title={j.lastError ?? ''} style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {j.lastError ?? '—'}
                    </td>
                    <td className="small muted">{relativeTime(j.createdAt)}</td>
                    <td>
                      {j.status === 'DEAD_LETTERED' && (
                        <button
                          className="button button-sm"
                          onClick={() => {
                            const reason = window.prompt('Reason for requeueing this job?');
                            if (reason && reason.length >= 3) {
                              void api.security.requeueJob(j.jobId, reason).then(() => setReloadKey((k) => k + 1));
                            }
                          }}
                        >
                          Requeue
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
