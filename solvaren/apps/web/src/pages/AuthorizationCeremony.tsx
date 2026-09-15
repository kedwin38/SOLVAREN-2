/**
 * The payment release ceremony (spec §6.3, §7.5, NFR-UX-001).
 *
 * This is the screen where money leaves the organisation. Everything about it is designed
 * to make the authorizer *read before acting*, because the failure mode here is not a
 * technical one — it is an experienced officer clicking through a familiar dialog.
 *
 *   - The amount is the largest element on the screen, by a wide margin.
 *   - The recipient count and batch reference sit directly beneath it, unabbreviated.
 *   - The release control is visually distinct from every other button in the product.
 *   - Each acknowledgement is a separate checkbox carrying the exact sentence the server
 *     will require back, so ticking is a real confirmation rather than a formality.
 *   - The button stays disabled until every gate is satisfied, and the disabled state
 *     says which gate is outstanding rather than leaving the officer to guess.
 *
 * The security itself is all server-side. This screen cannot weaken it: skipping a step
 * here produces a refusal, not a release. If the session's authentication is stale, the
 * step-up dialog collects the password + security key inline and retries.
 */

import { useEffect, useState } from 'react';
import { formatCents } from '@solvaren/core';
import {
  api,
  ApiError,
  requestWebAuthnAssertion,
  type CeremonyResponse,
} from '../lib/api.js';
import { Amount, Loading, Modal, Notice, SeverityChip } from '../components/primitives.js';

interface Props {
  batchId: string;
  onClose: () => void;
  onReleased: (summary: { batchReference: string; instructionsQueued: number; totalAmountCents: number; message: string }) => void;
}

type Phase = 'loading' | 'review' | 'signing' | 'releasing' | 'error';

export function AuthorizationCeremony({ batchId, onClose, onReleased }: Props) {
  const [phase, setPhase] = useState<Phase>('loading');
  const [ceremony, setCeremony] = useState<CeremonyResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [acknowledged, setAcknowledged] = useState<Set<string>>(new Set());
  const [pin, setPin] = useState('');
  const [manifestConfirmed, setManifestConfirmed] = useState(false);
  const [secondsRemaining, setSecondsRemaining] = useState<number | null>(null);

  // ---- Open the ceremony ---------------------------------------------------
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const result = await api.authorization.begin(batchId);
        if (cancelled) return;
        setCeremony(result);
        setPhase('review');
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? err : null);
        setPhase('error');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [batchId]);

  // ---- Challenge expiry ------------------------------------------------------
  // Shown as a live countdown: a ceremony that silently expires and then fails on
  // submit is a confusing experience during a payroll run.
  useEffect(() => {
    if (!ceremony) return;
    const expiry = new Date(ceremony.expiresAt).getTime();
    const tick = () => setSecondsRemaining(Math.max(0, Math.floor((expiry - Date.now()) / 1000)));
    tick();
    const timer = setInterval(tick, 1000);
    return () => clearInterval(timer);
  }, [ceremony]);

  async function abandon() {
    try {
      await api.authorization.abandon(batchId, 'Closed by the authorizer');
    } catch {
      // The housekeeping job expires abandoned ceremonies regardless; closing the dialog
      // must not be blocked by a failed cleanup call.
    }
    onClose();
  }

  async function release() {
    if (!ceremony) return;
    setPhase('signing');
    setError(null);

    try {
      // ---- WebAuthn assertion over the manifest-bound challenge ------------------
      const assertion = await requestWebAuthnAssertion({
        challenge: ceremony.webauthnChallenge,
        rpId: window.location.hostname,
      });

      setPhase('releasing');
      const result = await api.authorization.release(batchId, {
        challengeId: ceremony.challengeId,
        webauthnResponse: assertion,
        authorizationPin: pin,
        acknowledgements: [...acknowledged],
      });

      onReleased({
        batchReference: result.batchReference,
        instructionsQueued: result.instructionsQueued,
        totalAmountCents: result.totalAmountCents,
        message: result.message,
      });
    } catch (err) {
      // A stale-session refusal (STEP_UP_REQUIRED) never reaches here: the request layer
      // runs the global passkey confirmation and retries the release automatically.
      if (err instanceof ApiError) {
        setError(err);
      } else if (err instanceof Error && err.name === 'NotAllowedError') {
        setError(
          new ApiError(400, {
            code: 'WEBAUTHN_CANCELLED',
            category: 'AUTHENTICATION',
            message: 'The security key prompt was dismissed or timed out. No payment has been released. Try again when ready.',
          }),
        );
      } else {
        setError(
          new ApiError(500, {
            code: 'RELEASE_FAILED',
            category: 'INTERNAL',
            message: 'The release could not be completed. No payment has been released unless this screen says otherwise.',
          }),
        );
      }
      setPhase('review');
      // The PIN is cleared on any failure: re-entering it is a small cost, and leaving
      // it in a field after a failed attempt is not something a payment console should do.
      setPin('');
    }
  }

  const expired = secondsRemaining !== null && secondsRemaining <= 0;
  const allAcknowledged =
    ceremony?.acknowledgementsRequired.every((statement) => acknowledged.has(statement)) ?? false;
  const pinValid = /^\d{6,12}$/.test(pin);
  const busy = phase === 'signing' || phase === 'releasing';

  const blockingReason = !ceremony
    ? 'Loading the payment manifest'
    : expired
      ? 'This authorization has expired — close and start again'
      : !manifestConfirmed
        ? 'Confirm you have checked the amount and recipient count'
        : !allAcknowledged
          ? 'Confirm every acknowledgement above'
          : !pinValid
            ? 'Enter your Frontier Authorization PIN'
            : null;

  return (
    <Modal open onClose={abandon} labelledBy="ceremony-title" dismissible={!busy} wide>
      {phase === 'loading' ? (
        <Loading label="Opening authorization ceremony" />
      ) : phase === 'error' && !ceremony ? (
        <div>
          <h2 id="ceremony-title">Authorization cannot open</h2>
          {error && <Notice tone="danger">{error.message}</Notice>}
          <div className="card-footer">
            <button className="button" onClick={abandon}>Close</button>
          </div>
        </div>
      ) : ceremony ? (
        <div>
          <h2 id="ceremony-title" className="screen-reader-only">Payment authorization ceremony</h2>

          {error && (
            <Notice tone="danger" live="assertive">
              {error.message}
            </Notice>
          )}

          <div style={{ textAlign: 'center', padding: 'var(--s5) 0' }}>
            <div className="small muted" style={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              Release payment
            </div>
            <div className="ceremony-headline">{ceremony.confirmation.headline}</div>
            <div className="muted">
              Batch <span className="mono strong">{ceremony.manifest.batchReference}</span> · version {ceremony.manifest.batchVersion} · approval{' '}
              <span className="mono">{ceremony.manifest.approvalId}</span>
            </div>
            <div className="manifest-digest">manifest {ceremony.manifest.manifestHash.slice(0, 24)}…</div>
          </div>

          <div className="ceremony-countdown" style={{ textAlign: 'center' }}>
            {expired ? (
              <span style={{ color: 'var(--danger)', fontWeight: 600 }}>EXPIRED — close and start a new authorization</span>
            ) : (
              <>Authorization expires in {Math.floor((secondsRemaining ?? 0) / 60)}:{String((secondsRemaining ?? 0) % 60).padStart(2, '0')}</>
            )}
          </div>

          <div className="ceremony-warning">{ceremony.confirmation.warning}</div>

          {ceremony.risk.signals.length > 0 && (
            <div style={{ marginBottom: 'var(--s4)' }}>
              <div className="small strong" style={{ marginBottom: 'var(--s2)' }}>
                Risk assessment: {ceremony.risk.score} ({ceremony.risk.band})
              </div>
              {ceremony.risk.signals.slice(0, 5).map((s, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, marginBottom: 4, alignItems: 'flex-start' }}>
                  <SeverityChip severity={s.severity} />
                  <span className="small">{s.summary}</span>
                </div>
              ))}
              {ceremony.risk.signals.length > 5 && (
                <div className="small muted">+{ceremony.risk.signals.length - 5} more finding(s)</div>
              )}
            </div>
          )}

          <label className="checkbox">
            <input
              type="checkbox"
              checked={manifestConfirmed}
              onChange={(e) => setManifestConfirmed(e.target.checked)}
            />
            <span>
              I have verified the amount of <strong>KES {formatCents(ceremony.manifest.totalAmountCents)}</strong> and{' '}
              <strong>{ceremony.manifest.recipientCount} recipients</strong> in batch {ceremony.manifest.batchReference}.
            </span>
          </label>

          {ceremony.acknowledgementsRequired.length > 0 && (
            <div className="ack-list">
              {ceremony.acknowledgementsRequired.map((statement) => (
                <label key={statement} className="checkbox">
                  <input
                    type="checkbox"
                    checked={acknowledged.has(statement)}
                    onChange={(e) => {
                      const next = new Set(acknowledged);
                      if (e.target.checked) next.add(statement);
                      else next.delete(statement);
                      setAcknowledged(next);
                    }}
                  />
                  <span>{statement}</span>
                </label>
              ))}
            </div>
          )}

          <label className="field" style={{ maxWidth: 260 }}>
            <span className="field-label">Frontier Authorization PIN</span>
            <input
              className="input mono"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, '').slice(0, 12))}
              disabled={busy}
              aria-label="Frontier Authorization PIN"
            />
          </label>

          <div className="card-footer" style={{ flexDirection: 'column', alignItems: 'stretch', gap: 'var(--s2)' }}>
            {blockingReason && !busy && (
              <div className="small muted" style={{ textAlign: 'center' }}>
                {blockingReason}
              </div>
            )}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="button" onClick={abandon} disabled={busy}>
                Abandon
              </button>
              <button
                className="button button-release"
                onClick={() => void release()}
                disabled={busy || blockingReason !== null}
              >
                {phase === 'signing'
                  ? 'Waiting for security key…'
                  : phase === 'releasing'
                    ? 'Releasing…'
                    : 'Authorize & Release'}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </Modal>
  );
}
