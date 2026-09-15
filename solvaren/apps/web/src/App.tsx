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

import { useCallback, useEffect, useState, type ReactElement } from 'react';
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
  { route: 'dashboard', label: 'Dashboard', icon: 'dashboard', group: 'Operations' },
  { route: 'batches', label: 'Payment batches', icon: 'layers', requires: 'batch:read', group: 'Operations' },
  { route: 'transactions', label: 'Transactions', icon: 'swap', requires: 'transactions:read', group: 'Operations' },
  { route: 'recipients', label: 'Recipients', icon: 'users', requires: 'recipients:read', group: 'Operations' },
  { route: 'reconciliation', label: 'Reconciliation', icon: 'rotate', requires: 'reconciliation:read', group: 'Operations' },
  { route: 'analytics', label: 'Analytics', icon: 'chart', requires: 'analytics:basic', group: 'Control' },
  { route: 'reports', label: 'Reports', icon: 'file', requires: 'reports:operational', group: 'Control' },
  {
    route: 'security',
    label: 'Security center',
    icon: 'shield',
    requires: 'audit:read_own_scope',
    group: 'Administration',
  },
  { route: 'users', label: 'Users', icon: 'usercog', requires: 'admin:users', group: 'Administration' },
  { route: 'settings', label: 'Settings', icon: 'sliders', requires: 'admin:policies', group: 'Administration' },
  { route: 'backups', label: 'Backups', icon: 'database', requires: 'admin:backups', group: 'Administration' },
];

/**
 * Navigation icons — a hand-drawn 24×24 stroke set. One visual weight, round caps,
 * no fills: the rail should read as engraved labels, not emoji.
 */
const NAV_ICONS: Record<string, ReactElement> = {
  dashboard: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </>
  ),
  layers: (
    <>
      <path d="M12 3.5 21 8l-9 4.5L3 8l9-4.5Z" />
      <path d="m4.6 11.6-1.6.9 9 4.5 9-4.5-1.6-.9" />
      <path d="m4.6 15.8-1.6.9 9 4.5 9-4.5-1.6-.9" />
    </>
  ),
  swap: (
    <>
      <path d="M4 8h13.5" />
      <path d="m14.5 5 3 3-3 3" />
      <path d="M20 16H6.5" />
      <path d="m9.5 13-3 3 3 3" />
    </>
  ),
  users: (
    <>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M3.5 19.5c.7-3 2.9-4.5 5.5-4.5s4.8 1.5 5.5 4.5" />
      <path d="M16 5.4a3.2 3.2 0 0 1 0 5.9" />
      <path d="M17.5 15.4c1.6.6 2.7 1.9 3.2 4.1" />
    </>
  ),
  rotate: (
    <>
      <path d="M20 12a8 8 0 1 1-2.34-5.66" />
      <path d="M20 4v4.5h-4.5" />
    </>
  ),
  chart: (
    <>
      <path d="M4 20h16" />
      <path d="M7 20v-6" />
      <path d="M12 20V9" />
      <path d="M17 20V4.5" />
    </>
  ),
  file: (
    <>
      <path d="M6 3.5h8L19 8.5v12H6v-17Z" />
      <path d="M14 3.5V9h5" />
      <path d="M9 13h7" />
      <path d="M9 16.5h5" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3.5 5 6v5c0 4.5 3 7.8 7 9.5 4-1.7 7-5 7-9.5V6l-7-2.5Z" />
      <path d="m9 11.5 2.2 2.2 4-4.2" />
    </>
  ),
  usercog: (
    <>
      <circle cx="10" cy="8" r="3.2" />
      <path d="M4.5 19.5c.7-3 2.9-4.5 5.5-4.5 1 0 2 .2 2.8.6" />
      <circle cx="17.5" cy="15.5" r="2" />
      <path d="M17.5 12.4v1.1M17.5 17.5v1.1M14.8 13.9l1 .5M19.3 16.5l1 .5M14.8 17.9l1-.5M19.3 15.3l1-.5" />
    </>
  ),
  sliders: (
    <>
      <path d="M5 6.5h14M5 12h14M5 17.5h14" />
      <circle cx="9.5" cy="6.5" r="1.8" fill="var(--surface)" />
      <circle cx="15" cy="12" r="1.8" fill="var(--surface)" />
      <circle cx="8" cy="17.5" r="1.8" fill="var(--surface)" />
    </>
  ),
  database: (
    <>
      <ellipse cx="12" cy="5.5" rx="7" ry="2.5" />
      <path d="M5 5.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6" />
      <path d="M5 11.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6" />
    </>
  ),
};

function NavIcon({ name }: { name: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {NAV_ICONS[name] ?? NAV_ICONS.dashboard}
    </svg>
  );
}

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
                    <span className="nav-item-icon">
                      <NavIcon name={entry.icon} />
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

        <div className="nav-user">
          <div className="nav-user-row">
            <span className="nav-user-avatar" aria-hidden="true">
              {user.fullName
                .split(' ')
                .map((w) => w[0])
                .filter(Boolean)
                .slice(0, 2)
                .join('')
                .toUpperCase()}
            </span>
            <div>
              <div className="nav-user-name">{user.fullName}</div>
              <div className="nav-user-level">{LEVEL_TITLES[user.level]}</div>
            </div>
          </div>
          <div className="nav-user-actions">
            <button className="button button-sm" data-variant="ghost" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === 'dark' ? 'Light mode' : 'Dark mode'}
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
