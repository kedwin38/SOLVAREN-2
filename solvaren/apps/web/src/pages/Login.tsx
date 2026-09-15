/**
 * Login (spec §7): two-stage authentication.
 *
 * L1 signs in with a password. L2/L3 complete a WebAuthn assertion before any session
 * exists. Includes WebAuthn enrolment for accounts that need it, the step-up flow for
 * privileged actions, and the recovery-code redemption path (spec §8.3) — the complete
 * identity surface the previous system never finished.
 */

import { useEffect, useRef, useState } from 'react';
import {
  api,
  ApiError,
  setSessionToken,
  requestWebAuthnAssertion,
  createWebAuthnRegistration,
  type SessionResponse,
} from '../lib/api.js';
import { Loading, Notice } from '../components/primitives.js';

type Phase =
  | { kind: 'credentials' }
  | { kind: 'webauthn'; ticket: string; level: string }
  | { kind: 'enrolment'; token: string }
  | { kind: 'recovery' }
  | { kind: 'busy' };

export function Login({ onAuthenticated }: { onAuthenticated: (session: SessionResponse) => void }) {
  const [phase, setPhase] = useState<Phase>({ kind: 'credentials' });
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [pin, setPinValue] = useState('');
  const [error, setError] = useState<ApiError | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
  }, []);

  async function submitCredentials(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setPhase({ kind: 'busy' });
    try {
      const result = await api.auth.login(email, password);
      if (result.stage === 'AUTHENTICATED') {
        setSessionToken(result.token);
        const me = await api.auth.session();
        if (me.session.webauthnVerified === false && me.user.level !== 'L1') {
          // Privileged account with no enrolled key: force enrolment before anything else.
          setPhase({ kind: 'enrolment', token: result.token });
          setInfo('Your account requires a security key. Enrol one now to continue.');
          return;
        }
        onAuthenticated(me);
        return;
      }
      setPhase({ kind: 'webauthn', ticket: result.ticket, level: result.level });
      setInfo('Touch your security key or approve the passkey prompt to finish signing in.');
      // Immediately invoke the browser prompt for a smooth flow.
      void completeWebAuthn(result.ticket, result.options);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
      setPhase({ kind: 'credentials' });
    }
  }

  async function completeWebAuthn(ticket: string, options?: { challenge: string; rpId?: string; allowCredentials?: { id: string; type: 'public-key' }[] }) {
    setError(null);
    setPhase({ kind: 'busy' });
    try {
      const assertion = await requestWebAuthnAssertion(
        options ?? { challenge: '' },
      );
      const result = await api.auth.completeWebAuthn(ticket, assertion);
      setSessionToken(result.token);
      const me = await api.auth.session();
      onAuthenticated(me);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'WEBAUTHN_CANCELLED') {
        setError(err);
        setPhase({ kind: 'credentials' });
        return;
      }
      setError(
        err instanceof ApiError
          ? err
          : new ApiError(400, {
              code: 'WEBAUTHN_CANCELLED',
              category: 'AUTHENTICATION',
              message:
                'The security key prompt was dismissed or timed out. No payment has been released. Try again when ready.',
            }),
      );
      setPhase({ kind: 'credentials' });
    }
  }

  async function enrol() {
    setError(null);
    setInfo('Follow the browser prompt to create your security key or passkey.');
    setPhase({ kind: 'busy' });
    try {
      const options = await api.auth.webauthnRegisterOptions();
      const registration = await createWebAuthnRegistration(options);
      await api.auth.webauthnRegister(registration, 'My security key');
      // Key enrolled — the account activates. Prompt for the FPAC PIN for privileged levels.
      setInfo('Security key enrolled. Now set your Frontier Authorization PIN — it authorizes every payment release.');
      setPhase({ kind: 'pin-setup' as never });
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
      setPhase({ kind: 'credentials' });
    }
  }

  async function submitPin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPhase({ kind: 'busy' });
    try {
      await api.auth.setAuthorizationPin(password, pin);
      const me = await api.auth.session();
      onAuthenticated(me);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
      setPhase({ kind: 'credentials' });
    }
  }

  async function redeemRecovery(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPhase({ kind: 'busy' });
    try {
      const result = await api.auth.recoveryRedeem(email, password, recoveryCode);
      setSessionToken(result.token);
      setInfo(`${result.nextStep} (Recovery session active — enrolment only.)`);
      const options = await api.auth.webauthnRegisterOptions();
      const registration = await createWebAuthnRegistration(options);
      await api.auth.webauthnRegister(registration, 'Recovery key');
      // After enrolment the account reactivates; sign in normally.
      setSessionToken(null);
      setInfo('New security key enrolled. Sign in with your password and the new key.');
      setPhase({ kind: 'credentials' });
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
      setPhase({ kind: 'recovery' });
    }
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
          <svg width="36" height="36" viewBox="0 0 32 32" aria-hidden="true">
            <rect x="1" y="1" width="30" height="30" rx="8" fill="var(--accent)" />
            <path d="M10 20.5 L16 12.5 L22 20.5" fill="none" stroke="var(--ink-inverse)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M10 25 L22 25" stroke="var(--ink-inverse)" strokeWidth="2.4" strokeLinecap="round" opacity="0.55" />
          </svg>
          <div>
            <div style={{ fontWeight: 750, fontSize: 18 }}>SOLVAREN</div>
            <div className="small muted">Move money with certainty</div>
          </div>
        </div>

        {error && (
          <Notice tone="danger" live="assertive">
            {error.message}
            {error.correlationId && (
              <div className="small muted" style={{ marginTop: 4 }}>
                Correlation id: {error.correlationId}
              </div>
            )}
          </Notice>
        )}
        {info && (
          <Notice tone="info" live="polite">
            {info}
          </Notice>
        )}

        {phase.kind === 'busy' && <Loading label="Working" />}

        {phase.kind === 'credentials' && (
          <form onSubmit={submitCredentials}>
            <label className="field">
              <span className="field-label">Email</span>
              <input
                ref={emailRef}
                className="input"
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </label>
            <label className="field">
              <span className="field-label">Password</span>
              <input
                className="input"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </label>
            <button className="button" data-variant="primary" style={{ width: '100%', justifyContent: 'center' }} type="submit">
              Sign in
            </button>
            <button
              type="button"
              className="button"
              data-variant="ghost"
              style={{ width: '100%', justifyContent: 'center', marginTop: 8 }}
              onClick={() => setPhase({ kind: 'recovery' })}
            >
              Recover access with a recovery code
            </button>
          </form>
        )}

        {phase.kind === 'recovery' && (
          <form onSubmit={redeemRecovery}>
            <Notice tone="warning">
              Recovery requires your password AND one unused recovery code — two independent
              factors. SOLVAREN never uses SMS or email for recovery.
            </Notice>
            <label className="field">
              <span className="field-label">Email</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </label>
            <label className="field">
              <span className="field-label">Password</span>
              <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            </label>
            <label className="field">
              <span className="field-label">Recovery code</span>
              <input
                className="input mono"
                placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value.toUpperCase())}
                required
              />
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="button" data-variant="primary" type="submit" style={{ flex: 1, justifyContent: 'center' }}>
                Recover and re-enrol
              </button>
              <button className="button" data-variant="ghost" type="button" onClick={() => setPhase({ kind: 'credentials' })}>
                Back
              </button>
            </div>
          </form>
        )}

        {(phase.kind === 'enrolment' || (phase as { kind?: string }).kind === 'pin-setup') &&
          ((phase as { kind: string }).kind === 'enrolment' ? (
            <div>
              <p className="muted">
                Level 2 and Level 3 accounts must enrol a security key (FIDO2/passkey). This
                key will be required at every sign-in and cryptographically signs every
                payment release.
              </p>
              <button className="button" data-variant="primary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => void enrol()}>
                Enrol security key
              </button>
            </div>
          ) : (
            <form onSubmit={submitPin}>
              <label className="field">
                <span className="field-label">Confirm your password</span>
                <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </label>
              <label className="field">
                <span className="field-label">Frontier Authorization PIN (6–12 digits)</span>
                <input
                  className="input mono"
                  inputMode="numeric"
                  pattern="\d{6,12}"
                  value={pin}
                  onChange={(e) => setPinValue(e.target.value.replace(/\D/g, '').slice(0, 12))}
                  required
                />
              </label>
              <button className="button" data-variant="primary" type="submit" style={{ width: '100%', justifyContent: 'center' }}>
                Set PIN and continue
              </button>
            </form>
          ))}
      </div>
    </div>
  );
}
