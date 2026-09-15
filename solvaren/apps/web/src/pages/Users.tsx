/**
 * Users administration (spec §4.3): create, disable/reactivate, unlock, reset password,
 * assign levels, controlled admin recovery (§8.3). The full user-management surface the
 * previous system never exposed.
 */

import { useEffect, useState } from 'react';
import { api, ApiError } from '../lib/api.js';
import { Card, Empty, ErrorPane, Loading, Modal, Notice, PageHeader, relativeTime } from '../components/primitives.js';

export function UsersPage() {
  const [users, setUsers] = useState<Awaited<ReturnType<typeof api.admin.users.list>>['users'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void api.admin.users.list().then((d) => setUsers(d.users)).catch((err) => setError(err instanceof ApiError ? err : null));
  }, [reloadKey]);

  async function patch(id: string, body: Parameters<typeof api.admin.users.update>[1], message: string) {
    try {
      await api.admin.users.update(id, body);
      setNotice(message);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  async function adminRecovery(id: string) {
    const reason = window.prompt('Reason for administrative recovery? (Minimum 10 characters — fully audited)');
    if (!reason || reason.trim().length < 10) return;
    const pin = window.prompt('Confirm YOUR Frontier Authorization PIN:');
    if (!pin) return;
    try {
      const result = await api.admin.users.adminRecovery(id, reason, pin);
      setNotice(`Recovery complete. ${result.nextStep}`);
      setReloadKey((k) => k + 1);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  if (error && !users) return <ErrorPane error={error} />;
  if (!users) return <Loading label="Loading users" />;

  return (
    <>
      <PageHeader
        title="Users"
        subtitle="Create accounts, assign authority levels, control access"
        actions={
          <button className="button" data-variant="primary" onClick={() => setCreateOpen(true)}>
            Create user
          </button>
        }
      />

      {notice && <Notice tone="success">{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}

      {users.length === 0 ? (
        <Card>
          <Empty title="No users" />
        </Card>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Email</th>
                <th>Level</th>
                <th>Status</th>
                <th className="num">Keys</th>
                <th className="num">Sessions</th>
                <th>Last sign-in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.userId}>
                  <td className="strong">{u.fullName}</td>
                  <td className="small">{u.email}</td>
                  <td>
                    <span className={`chip`} data-tone={u.level === 'L3' ? 'danger' : u.level === 'L2' ? 'info' : 'neutral'}>
                      {u.level}
                    </span>
                  </td>
                  <td>
                    <span className={`chip`} data-tone={u.status === 'ACTIVE' ? 'success' : u.status === 'DISABLED' ? 'danger' : 'warning'}>
                      {u.status}
                    </span>
                  </td>
                  <td className="num">{u.webauthnCredentials}</td>
                  <td className="num">{u.activeSessions}</td>
                  <td className="small muted">{u.lastLoginAt ? relativeTime(u.lastLoginAt) : 'never'}</td>
                  <td>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {u.status === 'LOCKED' && (
                        <button className="button button-sm" onClick={() => void patch(u.userId, { unlock: true, status: 'ACTIVE' }, 'Account unlocked.')}>
                          Unlock
                        </button>
                      )}
                      {u.status === 'ACTIVE' ? (
                        <button className="button button-sm" data-variant="danger" onClick={() => void patch(u.userId, { status: 'DISABLED' }, 'User disabled; sessions revoked.')}>
                          Disable
                        </button>
                      ) : (
                        u.status === 'DISABLED' && (
                          <button className="button button-sm" onClick={() => void patch(u.userId, { status: 'ACTIVE' }, 'User reactivated.')}>
                            Reactivate
                          </button>
                        )
                      )}
                      <button
                        className="button button-sm"
                        data-variant="ghost"
                        onClick={() => {
                          const pw = window.prompt('New temporary password (min 12 characters):');
                          if (pw && pw.length >= 12) void patch(u.userId, { resetPassword: pw, revokeSessions: true }, 'Password reset; all sessions revoked.');
                          else if (pw) window.alert('Password must be at least 12 characters.');
                        }}
                      >
                        Reset password
                      </button>
                      <button className="button button-sm" data-variant="ghost" onClick={() => void adminRecovery(u.userId)}>
                        Admin recovery
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <CreateUserModal
          onClose={() => setCreateOpen(false)}
          onCreated={(message) => {
            setCreateOpen(false);
            setNotice(message);
            setReloadKey((k) => k + 1);
          }}
        />
      )}
    </>
  );
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: (message: string) => void }) {
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [authorityLevel, setAuthorityLevel] = useState<'L1' | 'L2' | 'L3'>('L1');
  const [temporaryPassword, setTemporaryPassword] = useState('');
  const [authorizationPin, setAuthorizationPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.admin.users.create({
        email,
        fullName,
        authorityLevel,
        temporaryPassword,
        ...(authorityLevel !== 'L1' && authorizationPin ? { authorizationPin } : {}),
      });
      onCreated(result.nextStep);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    } finally {
      setBusy(false);
    }
  }

  const privileged = authorityLevel !== 'L1';

  return (
    <Modal open onClose={onClose}>
      <h2>Create user</h2>
      {error && <Notice tone="danger">{error.message}</Notice>}
      {privileged && (
        <Notice tone="warning">
          {authorityLevel} accounts require a security key at every sign-in and an Authorization PIN for
          payment authority. The account activates when the user enrols their key at first sign-in.
        </Notice>
      )}
      <form onSubmit={submit}>
        <label className="field">
          <span className="field-label">Full name</span>
          <input className="input" value={fullName} onChange={(e) => setFullName(e.target.value)} required />
        </label>
        <label className="field">
          <span className="field-label">Email</span>
          <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </label>
        <label className="field">
          <span className="field-label">Authority level</span>
          <select className="select" value={authorityLevel} onChange={(e) => setAuthorityLevel(e.target.value as 'L1' | 'L2' | 'L3')}>
            <option value="L1">L1 — Payment Operations</option>
            <option value="L2">L2 — Finance Control & Review</option>
            <option value="L3">L3 — Chief / Executive Payment Authority</option>
          </select>
        </label>
        <label className="field">
          <span className="field-label">Temporary password (min 12 chars)</span>
          <input className="input mono" type="text" value={temporaryPassword} onChange={(e) => setTemporaryPassword(e.target.value)} required minLength={12} />
          <span className="small muted">Share securely; the user should change it.</span>
        </label>
        {privileged && (
          <label className="field">
            <span className="field-label">Frontier Authorization PIN (6–12 digits)</span>
            <input
              className="input mono"
              inputMode="numeric"
              value={authorizationPin}
              onChange={(e) => setAuthorizationPin(e.target.value.replace(/\D/g, '').slice(0, 12))}
              required={privileged}
            />
            <span className="small muted">Bound to this user; required at every payment release or credential rotation.</span>
          </label>
        )}
        <div className="card-footer">
          <button type="button" className="button" data-variant="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="button" data-variant="primary" disabled={busy}>{busy ? 'Creating…' : 'Create user'}</button>
        </div>
      </form>
    </Modal>
  );
}
