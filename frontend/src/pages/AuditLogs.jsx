import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { formatTime } from "../utils/format.js";
import { fetchAuditLogs, exportAuditLogs } from "../services/audit.js";
import { getApiError } from "../services/api.js";

const PAGE_SIZES = [25, 50, 100];

const EMPTY_FILTERS = { search: "", action: "", username: "" };

export default function AuditLogs() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FILTERS);
  const [page, setPage] = useState({ limit: 50, offset: 0 });
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  const download = async () => {
    setExporting(true);
    setExportError("");
    try {
      await exportAuditLogs(applied);
    } catch {
      setExportError("Export failed. Please try again.");
    } finally {
      setExporting(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    const params = { ...applied, limit: page.limit, skip: page.offset };
    setLoading(true);
    fetchAuditLogs(params)
      .then((res) => {
        if (!cancelled) setData(res);
      })
      .catch((err) => {
        if (!cancelled) setError(getApiError(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [applied, page.limit, page.offset]);

  const pageNum = Math.floor(page.offset / page.limit) + 1;
  const totalPages = Math.max(1, Math.ceil(data.total / page.limit));

  const updateFilter = (key, value) => setFilters((f) => ({ ...f, [key]: value }));
  const applyFilters = () => {
    setApplied(filters);
    setPage((p) => ({ ...p, offset: 0 }));
  };
  const resetFilters = () => {
    setFilters(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
    setPage((p) => ({ ...p, offset: 0 }));
  };

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Audit Logs</h2>
          <p className="page-subtitle">Who did what, when — every security-sensitive action is recorded here.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field grow">
            <label className="field-label">Search</label>
            <input
              placeholder="User, action or resource ID…"
              value={filters.search}
              onChange={(e) => updateFilter("search", e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Action</label>
            <input
              placeholder="e.g. LOGIN_SUCCESS"
              value={filters.action}
              onChange={(e) => updateFilter("action", e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Username</label>
            <input
              placeholder="Analyst or admin…"
              value={filters.username}
              onChange={(e) => updateFilter("username", e.target.value)}
            />
          </div>
          <div className="field mt-auto">
            <div className="btn-row">
              <button className="btn btn-primary" onClick={applyFilters}>Apply filters</button>
              <button className="btn btn-outline" onClick={resetFilters}>Reset</button>
            </div>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading audit trail…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : data.items.length === 0 ? (
        <EmptyState
          title="Audit trail is empty"
          message="Security-sensitive actions will appear here as they happen."
        />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Entries ({data.total})</h3>
            <div className="toolbar">
              <button className="btn btn-outline btn-sm" disabled={exporting} onClick={download}>
                {exporting ? "Exporting…" : "Export CSV"}
              </button>
              {exportError && <span className="dim-cell">{exportError}</span>}
              <select
                value={page.limit}
                aria-label="Entries per page"
                onChange={(e) => setPage({ limit: Number(e.target.value), offset: 0 })}
              >
                {PAGE_SIZES.map((n) => (
                  <option key={n} value={n}>{n} per page</option>
                ))}
              </select>
              <button
                className="btn btn-outline btn-sm"
                disabled={pageNum <= 1}
                onClick={() => setPage((p) => ({ ...p, offset: Math.max(0, p.offset - p.limit) }))}
              >
                Prev
              </button>
              <span className="dim-cell">Page {pageNum} / {totalPages}</span>
              <button
                className="btn btn-outline btn-sm"
                disabled={pageNum >= totalPages}
                onClick={() => setPage((p) => ({ ...p, offset: p.offset + p.limit }))}
              >
                Next
              </button>
            </div>
          </div>
          <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>When</th>
                <th>User</th>
                <th>Action</th>
                <th>Resource</th>
                <th>IP</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((entry) => (
                <tr key={entry.id}>
                  <td className="dim-cell">{formatTime(entry.timestamp)}</td>
                  <td className="mono">{entry.username || "system"}</td>
                  <td>
                    <span className="badge">{entry.action}</span>
                  </td>
                  <td>
                    <span className="mono">{entry.resource_type || "—"}</span>
                    {entry.resource_id && <span className="dim-cell"> #{entry.resource_id}</span>}
                  </td>
                  <td className="mono">{entry.ip_address || "—"}</td>
                  <td className="dim-cell" style={{ maxWidth: 360 }}>
                    {entry.details && Object.keys(entry.details).length > 0
                      ? JSON.stringify(entry.details)
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}
    </div>
  );
}