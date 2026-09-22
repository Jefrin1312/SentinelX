import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { formatTime } from "../utils/format.js";
import { fetchInvestigations } from "../services/investigations.js";
import { getApiError } from "../services/api.js";

const STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED"];
const PAGE_SIZES = [10, 25, 50, 100];

const EMPTY_FILTERS = { search: "", status: "" };

export default function Investigations() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FILTERS);
  const [page, setPage] = useState({ limit: 25, offset: 0 });
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params = { ...applied, limit: page.limit, skip: page.offset };
    setLoading(true);
    fetchInvestigations(params)
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
          <h2 className="page-title">Investigations</h2>
          <p className="page-subtitle">The triage thread behind every alert — notes, owner, and resolution state.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field grow">
            <label className="field-label">Search</label>
            <input
              placeholder="Summary or investigation ID…"
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
          <div className="field mt-auto">
            <button className="btn btn-primary" onClick={applyFilters}>Apply filters</button>
            <button className="btn btn-outline" style={{ marginLeft: 8 }} onClick={resetFilters}>Reset</button>
          </div>
        </div>
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading investigations…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : data.items.length === 0 ? (
        <EmptyState
          title="No investigations yet"
          message="Open an investigation from any alert to start the triage workflow."
        />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Investigations ({data.total})</h3>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
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
                <th>ID</th>
                <th>Alert</th>
                <th>Status</th>
                <th>Assignee</th>
                <th>Summary</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((i) => (
                <tr key={i.id}>
                  <td className="mono">
                    <Link to={`/investigations/${i.id}`}>#{i.id}</Link>
                  </td>
                  <td className="mono">
                    <Link className="link-muted" to={`/alerts/${i.alert_id}`}>{i.alert_id}</Link>
                  </td>
                  <td><StatusBadge status={i.status} /></td>
                  <td>{i.assignee_username || <span className="dim-cell">Unassigned</span>}</td>
                  <td className="dim-cell">{i.summary || <span className="dim-cell">—</span>}</td>
                  <td className="dim-cell">{formatTime(i.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}