/**
 * Application shell.
 *
 * Routing is hash-based and hand-rolled. A router library would add weight to carry a
 * dozen routes, and a payment console opened on a phone over a mobile network during a
 * payroll run is exactly the case where that matters.
 *
 * The navigation renders from the capability payload the server issued at sign-in, so an
 * L1 officer never sees a Daraja settings link. That is a courtesy, not a control: every
 * endpoint re-checks authority server-side against the live matrix (spec §4 HARD CONTROL).
 */

import { useCallback, useEffect, useState } from 'react';
import { LEVEL_TITLES, type TxnState } from '@solvaren/core';
import {
  api,
  ApiError,
  setSessionToken,
  requestWebAuthnAssertion,
  type SessionResponse,
} from './lib/api.js';
import { Login } from './pages/Login.js';
import { Dashboard } from './pages/Dashboard.js';
import { BatchesPage } from './pages/Batches.js';
import { TransactionsExplorer } from './pages/TransactionsExplorer.js';
import { RecipientsPage } from './pages/Recipients.js';
import { AnalyticsPage } from './pages/Analytics.js';
import { SecurityPage } from './pages/Security.js';
import { SettingsPage } from './pages/Settings.js';
import { BackupsPage } from './pages/Backups.js';
import { UsersPage } from './pages/Users.js';
import { ReconciliationPage } from './pages/Reconciliation.js';
import { ReportsPage } from './pages/Reports.js';
import { Notice } from './components/primitives.js';

export type Route =
  | 'dashboard'
  | 'batches'
  | 'transactions'
  | 'recipients'
  | 'analytics'
  | 'reconciliation'
  | 'reports'
  | 'security'
  | 'settings'
  | 'backups'
  | 'users';

interface NavEntry {
  route: Route;
  label: string;
  icon: string;
  requires?: string;
  group: 'Operations' | 'Control' | 'Administration';
}

const NAVIGATION: NavEntry[] = [
  { route: 'dashboard', label: 'Dashboard', icon: '◫', group: 'Operations' },
  { route: 'batches', label: 'Payment batches', icon: '▤', requires: 'batch:read', group: 'Operations' },
  { route: 'transactions', label: 'Transactions', icon: '⇄', requires: 'transactions:read', group: 'Operations' },
  { route: 'recipients', label: 'Recipients', icon: '☺', requires: 'recipients:read', group: 'Operations' },
  { route: 'reconciliation', label: 'Reconciliation', icon: '⟳', requires: 'reconciliation:read', group: 'Operations' },
  { route: 'analytics', label: 'Analytics', icon: '◊', requires: 'analytics:basic', group: 'Control' },
  { route: 'reports', label: 'Reports', icon: '▥', requires: 'reports:operational', group: 'Control' },
  {
    route: 'security',
    label: 'Security center',
    icon: '⛨',
    requires: 'audit:read_own_scope',
    group: 'Administration',
  },
  { route: 'users', label: 'Users', icon: '+#', requires: 'admin:users', group: 'Administration' },
  { route: 'settings', label: 'Settings', icon: '⚙', requires: 'admin:policies', group: 'Administration' },
  { route: 'backups', label: 'Backups', icon: '⛃', requires: 'admin:backups', group: 'Administration' },
];

const ROUTES: Route[] = NAVIGATION.map((n) => n.route);

export function App() {
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [booting, setBooting] = useState(true);
  const [route, setRoute] = useState<Route>(readRoute());
  const [explorerFilter, setExplorerFilter] = useState<{ statuses?: TxnState[]; batchId?: string }>({});
  const [banner, setBanner] = useState<{ tone: 'success' | 'danger' | 'info' | 'warning'; message: string } | null>(null);
  const [unreadCount, setUnreadCount] = useState(0);
  const [theme, setTheme] = useState<'light' | 'dark'>(
    (document.documentElement.dataset.theme as 'light' | 'dark') ?? 'light',
  );

  useEffect(() => {
    const onHashChange = () => setRoute(readRoute());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // Poll unread notifications while signed in (spec §13.7 visible operational warnings).
  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const data = await api.notifications.list();
        if (!cancelled) setUnreadCount(data.notifications.length);
      } catch {
        /* transient */
      }
    };
    void tick();
    const timer = setInterval(tick, 30_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [session]);

  // Attempt silent session restore from an in-memory token (same tab only).
  useEffect(() => {
    if (!booting) return;
    void (async () => {
      try {
        if (sessionTokenHeld()) {
          const me = await api.auth.session();
          setSession(me);
        }
      } catch {
        setSessionToken(null);
      } finally {
        setBooting(false);
      }
    })();
  }, [booting]);

  const navigate = useCallback((next: Route) => {
    window.location.hash = `#/${next}`;
    setRoute(next);
    // Move focus to the main region so a keyboard user is not left at the nav item they
    // just activated, hunting for where the page went.
    document.getElementById('main-content')?.focus();
  }, []);

  const drillDown = useCallback(
    (statuses: TxnState[]) => {
      setExplorerFilter({ statuses });
      navigate('transactions');
    },
    [navigate],
  );

  const drillToBatch = useCallback(
    (batchId: string) => {
      setExplorerFilter({ batchId });
      navigate('transactions');
    },
    [navigate],
  );

  async function signOut() {
    try {
      await api.auth.logout();
    } catch {
      // Even if the call fails, the local token must go.
    }
    setSessionToken(null);
    setSession(null);
    setBanner(null);
  }

  function toggleTheme() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    document.documentElement.dataset.theme = next;
    localStorage.setItem('solvaren.theme', next);
  }

  if (booting) {
    return (
      <div className="login-shell">
        <div className="loading">Starting SOLVAREN…</div>
      </div>
    );
  }

  if (!session) {
    return (
      <Login
        onAuthenticated={(me) => {
          setSession(me);
          setBanner(null);
        }}
      />
    );
  }

  const { user, capabilities } = session;
  const visible = NAVIGATION.filter((entry) => !entry.requires || capabilities[entry.requires as never]);
  const groups = ['Operations', 'Control', 'Administration'] as const;

  return (
    <div className="shell">
      <nav className="sidebar" aria-label="Main">
        <div className="brand">
          <BrandMark />
          <div>
            <div className="brand-name">SOLVAREN</div>
            <div className="brand-tagline">Move money with certainty</div>
          </div>
        </div>

        <div className="nav">
          {groups.map((group) => {
            const entries = visible.filter((entry) => entry.group === group);
            if (entries.length === 0) return null;
            return (
              <div key={group}>
                <div className="nav-group-label">{group}</div>
                {entries.map((entry) => (
                  <button
                    key={entry.route}
                    className="nav-item"
                    aria-current={route === entry.route ? 'page' : undefined}
                    onClick={() => {
                      if (entry.route === 'transactions') setExplorerFilter({});
                      navigate(entry.route);
                    }}
                  >
                    <span className="nav-item-icon" aria-hidden="true">
                      {entry.icon}
                    </span>
                    {entry.label}
                    {entry.route === 'security' && unreadCount > 0 && (
                      <span className="badge" aria-label={`${unreadCount} unread notifications`}>
                        {unreadCount > 99 ? '99+' : unreadCount}
                      </span>
                    )}
                  </button>
                ))}
              </div>
            );
          })}
        </div>

        <div style={{ marginBlockStart: 'auto', paddingInline: 'var(--s4)', display: 'flex', flexDirection: 'column', gap: 'var(--s2)' }}>
          <div className="small strong">{user.fullName}</div>
          <div className="small muted">{LEVEL_TITLES[user.level]}</div>
          <div style={{ display: 'flex', gap: 'var(--s2)', marginTop: 'var(--s2)' }}>
            <button className="button button-sm" data-variant="ghost" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === 'dark' ? '☀' : '☾'}
            </button>
            <button className="button button-sm" data-variant="ghost" onClick={() => void signOut()}>
              Sign out
            </button>
          </div>
        </div>
      </nav>

      <main className="main" id="main-content" tabIndex={-1}>
        {banner && (
          <div style={{ marginBlockEnd: 'var(--s5)' }}>
            <Notice tone={banner.tone} live="polite">
              {banner.message}
            </Notice>
          </div>
        )}

        {route === 'dashboard' && (
          <Dashboard
            capabilities={capabilities}
            level={user.level}
            fullName={user.fullName}
            onDrillDown={drillDown}
          />
        )}

        {route === 'transactions' && (
          <TransactionsExplorer
            capabilities={capabilities}
            initialStatuses={explorerFilter.statuses}
            initialBatchId={explorerFilter.batchId}
          />
        )}

        {route === 'batches' && (
          <BatchesPage
            capabilities={capabilities}
            level={user.level}
            onReleased={(summary) =>
              setBanner({
                tone: 'success',
                message: `${summary.batchReference} released. ${summary.message}`,
              })
            }
            onViewTransactions={drillToBatch}
          />
        )}

        {route === 'recipients' && <RecipientsPage capabilities={capabilities} />}
        {route === 'reconciliation' && <ReconciliationPage capabilities={capabilities} level={user.level} />}
        {route === 'analytics' && <AnalyticsPage level={user.level} capabilities={capabilities} />}
        {route === 'reports' && <ReportsPage />}
        {route === 'security' && <SecurityPage level={user.level} capabilities={capabilities} />}
        {route === 'settings' && <SettingsPage />}
        {route === 'backups' && (
          <BackupsPage
            onRan={(reference) =>
              setBanner({ tone: 'info', message: `Backup ${reference} queued. Watch its progress below.` })
            }
          />
        )}
        {route === 'users' && <UsersPage />}
      </main>
    </div>
  );
}

function readRoute(): Route {
  const hash = window.location.hash.replace(/^#\/?/, '');
  return (ROUTES as string[]).includes(hash) ? (hash as Route) : 'dashboard';
}

function sessionTokenHeld(): boolean {
  // The api module holds the token in memory; expose a probe without leaking it.
  try {
    return window.history.state?.solvarenSession === true;
  } catch {
    return false;
  }
}

/** Global escape hatch for the step-up flow: any page can trigger the password prompt. */
export async function performStepUp(password: string): Promise<void> {
  try {
    await api.auth.stepUp(password);
  } catch (err) {
    if (err instanceof ApiError && err.code === 'WEBAUTHN_REQUIRED') {
      // Privileged step-up needs the security key too: generate + verify in one cycle.
      // The server issues options only after the password checks out, so the flow is:
      // rethrow a friendly instruction and let the caller prompt for WebAuthn via
      // api.auth.stepUp with the assertion.
      throw err;
    }
    throw err;
  }
}

/** Helper re-exported for pages that need to prompt WebAuthn generically. */
export { requestWebAuthnAssertion };

/**
 * The SOLVAREN mark: two offset chevrons forming an upward path through a boundary.
 * Drawn inline so it costs no request and inherits the theme's accent colour.
 */
function BrandMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 32 32" role="img" aria-label="SOLVAREN">
      <rect x="1" y="1" width="30" height="30" rx="8" fill="var(--accent)" />
      <path
        d="M10 20.5 L16 12.5 L22 20.5"
        fill="none"
        stroke="var(--ink-inverse)"
        strokeWidth="2.4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path d="M10 25 L22 25" stroke="var(--ink-inverse)" strokeWidth="2.4" strokeLinecap="round" opacity="0.55" />
    </svg>
  );
}

export { ApiError };
