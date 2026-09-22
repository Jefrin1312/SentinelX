import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { formatTime } from "../utils/format.js";
import { fetchAlerts, exportAlerts } from "../services/alerts.js";
import { getApiError } from "../services/api.js";

const STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED"];
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const PAGE_SIZES = [10, 25, 50, 100];

const EMPTY_FILTERS = {
  search: "",
  status: "",
  severity: "",
  source_ip: "",
};

export default function Alerts() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FILTERS);
  const [page, setPage] = useState({ limit: 25, offset: 0 });
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  const download = async () => {
    setExporting(true);
    setExportError("");
    try {
      await exportAlerts(applied);
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
    fetchAlerts(params)
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
          <h2 className="page-title">Alerts</h2>
          <p className="page-subtitle">Detections raised by the engine — triage, investigate, resolve.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field grow">
            <label className="field-label">Search</label>
            <input
              placeholder="Type, description or source IP…"
              value={filters.search}
              onChange={(e) => updateFilter("search", e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Status</label>
            <select value={filters.status} onChange={(e) => updateFilter("status", e.target.value)}>
              <option value="">All</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label className="field-label">Severity</label>
            <select value={filters.severity} onChange={(e) => updateFilter("severity", e.target.value)}>
              <option value="">All</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label className="field-label">Source IP</label>
            <input
              placeholder="e.g. 203.0.113.10"
              value={filters.source_ip}
              onChange={(e) => updateFilter("source_ip", e.target.value)}
            />
          </div>
          <div className="field mt-auto">
            <button className="btn btn-primary" onClick={applyFilters}>Apply filters</button>
            <button className="btn btn-outline" style={{ marginLeft: 8 }} onClick={resetFilters}>Reset</button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading alerts…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : data.items.length === 0 ? (
        <EmptyState
          title="No alerts raised yet"
          message="Import a sample log to see the detection engine fire on attack signatures."
        />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Alerts ({data.total})</h3>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <button className="btn btn-outline btn-sm" disabled={exporting} onClick={download}>
                {exporting ? "Exporting…" : "Export CSV"}
              </button>
              {exportError && <span className="dim-cell">{exportError}</span>}
              <select
                value={page.limit}
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
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Alert</th>
                <th>Source IP</th>
                <th>Rule</th>
                <th>Status</th>
                <th>Raised</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((a) => (
                <tr key={a.id}>
                  <td><SeverityBadge severity={a.severity} /></td>
                  <td><Link to={`/alerts/${a.id}`}>{a.alert_type}</Link></td>
                  <td className="mono">{a.source_ip || "—"}</td>
                  <td className="dim-cell">{a.rule_name || "—"}</td>
                  <td><StatusBadge status={a.status} /></td>
                  <td className="dim-cell">{formatTime(a.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}