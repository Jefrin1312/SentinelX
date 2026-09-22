import { useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { formatDateTime } from "../utils/format.js";
import {
  useLogs,
  ingestLines,
  uploadLogFile,
  importSample,
  exportEvents,
} from "../services/logs.js";
import { getApiError } from "../services/api.js";

const EVENT_TYPES = [
  "SSH_LOGIN_FAILURE",
  "SSH_LOGIN_SUCCESS",
  "AUTH_FAILURE",
  "SUDO_COMMAND",
  "USER_CREATED",
  "USER_DELETED",
  "HTTP_REQUEST",
  "HTTP_SUSPICIOUS_REQUEST",
  "UNKNOWN",
];

const STATUSES = ["SUCCESS", "FAILED", "DENIED", "ERROR", "SUSPICIOUS", "UNKNOWN"];
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SOURCES = ["MANUAL", "FILE", "SAMPLE:ssh", "SAMPLE:apache", "SAMPLE:nginx", "SAMPLE:auth"];

const SAMPLES = ["ssh", "apache", "nginx", "auth"];

const PAGE_SIZES = [10, 25, 50, 100];

const EMPTY_FILTERS = {
  search: "",
  event_type: "",
  source_ip: "",
  username: "",
  status: "",
  severity: "",
  source: "",
};

export default function Logs() {
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [applied, setApplied] = useState(EMPTY_FILTERS);
  const [page, setPage] = useState({ limit: 25, offset: 0 });
  const [selected, setSelected] = useState(null);

  const [sample, setSample] = useState("ssh");
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState("");

  const download = async () => {
    setExporting(true);
    setExportError("");
    try {
      await exportEvents(applied);
    } catch {
      setExportError("Export failed. Please try again.");
    } finally {
      setExporting(false);
    }
  };

  const { data, loading, error } = useLogs(applied, page);
  const pageNum = Math.floor(page.offset / page.limit) + 1;
  const totalPages = Math.max(1, Math.ceil(data.total / page.limit));

  const runAction = async (promise) => {
    setBusy(true);
    setActionError("");
    setActionNotice("");
    try {
      const res = await promise;
      const alertCount = res.alerts_created ?? 0;
      setActionNotice(
        `${res.events_created} events parsed (${res.parsed} recognised, ${res.unknown} unknown)${alertCount ? ` and ${alertCount} alert${alertCount === 1 ? "" : "s"} raised.` : "."}`
      );
      setPage((p) => ({ ...p, offset: 0 }));
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const applyFilters = () => {
    setApplied(filters);
    setPage((p) => ({ ...p, offset: 0 }));
  };

  const resetFilters = () => {
    setFilters(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
    setPage((p) => ({ ...p, offset: 0 }));
  };

  const updateFilter = (key, value) => setFilters((f) => ({ ...f, [key]: value }));

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Security Logs</h2>
          <p className="page-subtitle">Parsed, normalised event stream from the ingestion pipeline.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field grow">
            <label className="field-label">Search</label>
            <input
              placeholder="Message, IP or username…"
              value={filters.search}
              onChange={(e) => updateFilter("search", e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Event type</label>
            <select value={filters.event_type} onChange={(e) => updateFilter("event_type", e.target.value)}>
              <option value="">All</option>
              {EVENT_TYPES.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
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
            <label className="field-label">Source</label>
            <select value={filters.source} onChange={(e) => updateFilter("source", e.target.value)}>
              <option value="">All</option>
              {SOURCES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="field-row" style={{ marginTop: 8 }}>
          <div className="field">
            <label className="field-label">Source IP</label>
            <input
              placeholder="e.g. 203.0.113.10"
              value={filters.source_ip}
              onChange={(e) => updateFilter("source_ip", e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Username</label>
            <input
              placeholder="e.g. admin"
              value={filters.username}
              onChange={(e) => updateFilter("username", e.target.value)}
            />
          </div>
          <div className="field mt-auto">
            <button className="btn btn-primary" onClick={applyFilters}>Apply filters</button>
            <button className="btn btn-outline" style={{ marginLeft: 8 }} onClick={resetFilters}>Reset</button>
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <h3 className="card-title">Ingest data</h3>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <select value={sample} onChange={(e) => setSample(e.target.value)}>
              {SAMPLES.map((s) => (
                <option key={s} value={s}>sample_logs/{s}.log</option>
              ))}
            </select>
            <button className="btn btn-outline btn-sm" disabled={busy} onClick={() => runAction(importSample(sample))}>
              Import sample
            </button>
            <label className="btn btn-outline btn-sm" style={{ cursor: "pointer" }}>
              Upload file
              <input
                type="file"
                style={{ display: "none" }}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) runAction(uploadLogFile(file));
                  e.target.value = "";
                }}
              />
            </label>
            <button className="btn btn-outline btn-sm" onClick={() => setPasteOpen((v) => !v)}>
              {pasteOpen ? "Hide paste" : "Paste lines"}
            </button>
          </div>
        </div>
        {actionError && <ErrorMessage message={actionError} />}
        {actionNotice && <p className="text-good" style={{ padding: "8px 16px" }}>{actionNotice}</p>}
        {pasteOpen && (
          <div className="card-body">
            <textarea
              className="paste-area"
              rows={6}
              placeholder={"Paste raw log lines, one per line (e.g. SSH, Apache, syslog)."}
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
            />
            <button
              className="btn btn-primary btn-sm"
              style={{ marginTop: 8 }}
              disabled={busy || !pasteText.trim()}
              onClick={() =>
                runAction(
                  ingestLines(pasteText.split("\n").filter((l) => l.trim()), "MANUAL").then((res) => {
                    setPasteText("");
                    return res;
                  })
                )
              }
            >
              Ingest pasted lines
            </button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading events…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : data.items.length === 0 ? (
        <EmptyState
          title="No matching events"
          message="Import a sample log or upload a file to start the pipeline."
        />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Events ({data.total})</h3>
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
                <th>Time</th>
                <th>Type</th>
                <th>Source IP</th>
                <th>Username</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((e) => (
                <tr key={e.id} onClick={() => setSelected(selected?.id === e.id ? null : e)} className={selected?.id === e.id ? "row-active" : ""}>
                  <td className="dim-cell">{formatDateTime(e.timestamp)}</td>
                  <td className="mono">{e.event_type}</td>
                  <td className="mono">{e.source_ip || "—"}</td>
                  <td>{e.username || "—"}</td>
                  <td><StatusBadge status={e.status} /></td>
                  <td><SeverityBadge severity={e.severity} /></td>
                  <td className="mono">{e.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card" style={{ marginTop: 16 }}>
          <div className="card-header">
            <h3 className="card-title">
              Event #{selected.id}
              {" "}<SeverityBadge severity={selected.severity} />
              {" "}<StatusBadge status={selected.status} />
            </h3>
            <button className="btn btn-outline btn-sm" onClick={() => setSelected(null)}>Close</button>
          </div>
          <div className="card-body">
            <p className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{selected.message}</p>
            <div className="meta-grid">
              <div>
                <span className="dim-cell">Recorded</span>
                <div>{formatDateTime(selected.timestamp)}</div>
              </div>
              <div>
                <span className="dim-cell">Source</span>
                <div>{selected.source}</div>
              </div>
              <div>
                <span className="dim-cell">Source IP</span>
                <div className="mono">{selected.source_ip || "—"}</div>
              </div>
              <div>
                <span className="dim-cell">Username</span>
                <div>{selected.username || "—"}</div>
              </div>
            </div>
            {selected.metadata && Object.keys(selected.metadata).length > 0 && (
              <pre className="meta-json">{JSON.stringify(selected.metadata, null, 2)}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}