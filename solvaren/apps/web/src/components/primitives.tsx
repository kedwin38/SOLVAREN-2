/**
 * Interface primitives. Each component exists because a plain HTML element would be
 * wrong in a specific, nameable way for a payment console — not for the sake of a
 * component library.
 */

import { useEffect, useId, useRef, type ReactNode } from 'react';
import { formatCents, statusTone, type TxnState } from '@solvaren/core';

// ---------------------------------------------------------------------------
// Money
// ---------------------------------------------------------------------------

/**
 * Render an amount. `aria-label` spells the figure out because a screen reader
 * pronouncing "45,000.00" as "forty five thousand point zero zero" in a column of
 * fifty is exhausting, and the currency belongs in the announcement.
 */
export function Amount({ cents, size = 'normal', showCurrency = true }: { cents: number; size?: 'normal' | 'large' | 'xl'; showCurrency?: boolean }) {
  const formatted = formatCents(cents);
  return (
    <span
      className={size === 'xl' ? 'amount amount-xl' : size === 'large' ? 'amount amount-lg' : 'amount'}
      aria-label={`${formatted} Kenyan shillings`}
    >
      {showCurrency && (
        <span className="amount-currency" aria-hidden="true">
          KES
        </span>
      )}
      <span aria-hidden="true">{formatted}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

const STATUS_LABELS: Record<string, string> = {
  PENDING: 'Pending',
  SUBMITTED: 'Submitted',
  AWAITING_CALLBACK: 'Awaiting result',
  PROCESSING: 'Processing',
  RECONCILING: 'Reconciling',
  SUCCESS: 'Paid',
  FAILED: 'Failed',
  TIMEOUT: 'Timed out',
  CANCELLED: 'Cancelled',
};

const BATCH_STATE_LABELS: Record<string, string> = {
  DRAFT: 'Draft',
  VALIDATED: 'Validated',
  SUBMITTED_TO_L2: 'Awaiting review',
  L2_REVIEW: 'In review',
  RETURNED_FOR_CORRECTION: 'Returned',
  L3_READY: 'Awaiting authorization',
  AUTHORIZATION_PENDING: 'Authorization open',
  AUTHORIZED: 'Authorized',
  QUEUED: 'Queued',
  SUBMITTED: 'Submitted',
  PROCESSING: 'Processing',
  SUCCESS: 'Complete',
  PARTIAL_SUCCESS: 'Partial',
  FAILED: 'Failed',
  TIMEOUT: 'Timed out',
  ON_HOLD: 'On hold',
  REJECTED: 'Rejected',
  CANCELLED: 'Cancelled',
};

/** A status chip. Colour is reinforced by the label, never the only signal (WCAG 1.4.1). */
export function StatusChip({ status }: { status: string }) {
  const tone = statusTone(status as TxnState);
  return (
    <span className="chip" data-tone={tone}>
      {STATUS_LABELS[status] ?? status}
    </span>
  );
}

export function BatchStateChip({ state }: { state: string }) {
  const tone =
    state === 'SUCCESS'
      ? 'success'
      : state === 'FAILED'
        ? 'danger'
        : state === 'TIMEOUT' || state === 'PARTIAL_SUCCESS'
          ? 'warning'
          : state === 'ON_HOLD' || state === 'REJECTED' || state === 'CANCELLED'
            ? 'neutral'
            : 'info';
  return (
    <span className="chip" data-tone={tone}>
      {BATCH_STATE_LABELS[state] ?? state}
    </span>
  );
}

export function SeverityChip({ severity }: { severity: string }) {
  const tone =
    severity === 'CRITICAL' ? 'danger' : severity === 'HIGH' ? 'warning' : severity === 'MEDIUM' ? 'info' : 'neutral';
  return (
    <span className="chip" data-tone={tone}>
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Notices and structure
// ---------------------------------------------------------------------------

export function Notice({
  tone,
  children,
  live,
}: {
  tone: 'info' | 'success' | 'danger' | 'warning';
  children: ReactNode;
  live?: 'polite' | 'assertive' | false;
}) {
  return (
    <div className={`notice notice-${tone}`} role={live === 'assertive' ? 'alert' : live === 'polite' ? 'status' : undefined}>
      {children}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Card({ title, children, footer }: { title?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <section className="card">
      {title && <h2 className="card-title">{title}</h2>}
      {children}
      {footer && <div className="card-footer">{footer}</div>}
    </section>
  );
}

export function Stat({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: string; tone?: 'success' | 'danger' | 'warning' }) {
  return (
    <div className="stat" data-tone={tone}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modal with focus trap
// ---------------------------------------------------------------------------

export function Modal({
  open,
  onClose,
  labelledBy,
  children,
  dismissible = true,
  wide,
}: {
  open: boolean;
  onClose: () => void;
  labelledBy?: string;
  children: ReactNode;
  dismissible?: boolean;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    if (!open) return;
    const previouslyFocused = document.activeElement as HTMLElement | null;
    ref.current?.focus();

    const trap = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && dismissible) {
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !ref.current) return;
      const focusable = ref.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0]!;
      const last = focusable[focusable.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', trap);
    return () => {
      document.removeEventListener('keydown', trap);
      previouslyFocused?.focus();
    };
  }, [open, onClose, dismissible]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && dismissible && onClose()}>
      <div
        ref={ref}
        className={`modal ${wide ? 'modal-wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={labelledBy ?? titleId}
        tabIndex={-1}
      >
        <span id={labelledBy ?? titleId} className="screen-reader-only">
          Dialog
        </span>
        {children}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading / empty
// ---------------------------------------------------------------------------

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}…
    </div>
  );
}

export function Empty({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="empty">
      <div className="empty-title">{title}</div>
      {hint && <div className="muted">{hint}</div>}
    </div>
  );
}

export function ErrorPane({ error, onRetry }: { error: { message: string; code?: string; correlationId?: string | null }; onRetry?: () => void }) {
  return (
    <div className="error-pane" role="alert">
      <div className="error-message">{error.message}</div>
      {error.correlationId && <div className="muted small">Correlation id: {error.correlationId}</div>}
      {onRetry && (
        <button className="button" data-variant="ghost" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const date = new Date(iso);
  const diffMs = Date.now() - date.getTime();
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return date.toLocaleDateString();
}

export { STATUS_LABELS, BATCH_STATE_LABELS };
