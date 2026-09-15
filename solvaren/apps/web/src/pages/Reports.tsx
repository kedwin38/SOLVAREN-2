/**
 * Reports (spec §12): the catalogue-driven report generator. Async generation with
 * history and download; every report leaves an audited export record server-side.
 */

import { useEffect, useState } from 'react';
import { api, ApiError } from '../lib/api.js';
import { Card, Empty, ErrorPane, Loading, Notice, PageHeader, relativeTime } from '../components/primitives.js';

export function ReportsPage() {
  const [catalogue, setCatalogue] = useState<Awaited<ReturnType<typeof api.reports.catalogue>>['reports'] | null>(null);
  const [history, setHistory] = useState<Awaited<ReturnType<typeof api.reports.history>>['jobs'] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    void (async () => {
      try {
        const [cat, hist] = await Promise.all([api.reports.catalogue(), api.reports.history()]);
        setCatalogue(cat.reports);
        setHistory(hist.jobs);
      } catch (err) {
        setError(err instanceof ApiError ? err : null);
      }
    })();
  }, [reloadKey]);

  async function generate(family: string) {
    try {
      const result = await api.reports.request(family, {
        ...(dateFrom ? { dateFrom } : {}),
        ...(dateTo ? { dateTo } : {}),
      });
      setNotice(result.message);
      setTimeout(() => setReloadKey((k) => k + 1), 2000);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  async function download(id: string) {
    try {
      const { blob, filename } = await api.reports.download(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof ApiError ? err : null);
    }
  }

  if (error && !catalogue) return <ErrorPane error={error} />;

  return (
    <>
      <PageHeader title="Reports" subtitle="Generated from the authoritative ledger; every export is audited" />

      {notice && <Notice tone="info">{notice}</Notice>}
      {error && <Notice tone="danger">{error.message}</Notice>}

      <div className="filters">
        <label className="field">
          <span className="field-label">From</span>
          <input className="input" type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
        </label>
        <label className="field">
          <span className="field-label">To</span>
          <input className="input" type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
        </label>
      </div>

      {!catalogue ? (
        <Loading label="Loading report catalogue" />
      ) : (
        <Card title="Report families">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {catalogue.map((r) => (
              <div key={r.family} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 12, opacity: r.available ? 1 : 0.5 }}>
                <div className="strong">{r.title}</div>
                <div className="small muted" style={{ minHeight: 32 }}>{r.description}</div>
                <button className="button button-sm" style={{ marginTop: 8 }} disabled={!r.available} onClick={() => void generate(r.family)}>
                  Generate
                </button>
              </div>
            ))}
          </div>
        </Card>
      )}

      {history && history.length > 0 && (
        <Card title="Recent reports">
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Family</th>
                  <th>Status</th>
                  <th className="num">Rows</th>
                  <th>Requested</th>
                  <th>Completed</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {history.map((j) => (
                  <tr key={j.reportJobId}>
                    <td className="small strong">{j.family}</td>
                    <td>
                      <span className={`chip`} data-tone={j.status === 'COMPLETED' ? 'success' : j.status === 'FAILED' ? 'danger' : 'warning'}>
                        {j.status}
                      </span>
                    </td>
                    <td className="num">{j.rowCount ?? '—'}</td>
                    <td className="small muted">{relativeTime(j.requestedAt)}</td>
                    <td className="small muted">{j.completedAt ? relativeTime(j.completedAt) : '—'}</td>
                    <td>
                      {j.status === 'COMPLETED' && (
                        <button className="button button-sm" onClick={() => void download(j.reportJobId)}>
                          Download CSV
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </>
  );
}
