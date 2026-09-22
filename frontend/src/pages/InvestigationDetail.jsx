import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { formatDateTime } from "../utils/format.js";
import {
  addInvestigationNote,
  fetchInvestigation,
  updateInvestigation,
} from "../services/investigations.js";
import { getApiError } from "../services/api.js";

const STATUS_OPTIONS = [
  { value: "OPEN", label: "Reopen" },
  { value: "INVESTIGATING", label: "In progress" },
  { value: "RESOLVED", label: "Resolve" },
];

export default function InvestigationDetail() {
  const { investigationId } = useParams();
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [summary, setSummary] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [actionNotice, setActionNotice] = useState("");

  const load = () => {
    setLoading(true);
    fetchInvestigation(investigationId)
      .then((res) => {
        setInvestigation(res);
        setSummary(res.summary || "");
        setActionNotice("");
      })
      .catch((err) => setError(getApiError(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, [investigationId]);

  const transition = async (status) => {
    setBusy(true);
    setActionError("");
    try {
      const saved = await updateInvestigation(investigationId, { status });
      setInvestigation((prev) => ({ ...prev, ...saved }));
      setActionNotice(`Investigation moved to ${saved.status}.`);
      load();
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const saveSummary = async () => {
    setBusy(true);
    setActionError("");
    try {
      const saved = await updateInvestigation(investigationId, { summary: summary.trim() || null });
      setInvestigation((prev) => ({ ...prev, summary: saved.summary }));
      setActionNotice("Summary updated.");
      load();
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const submitNote = async (e) => {
    e.preventDefault();
    if (!note.trim()) return;
    setBusy(true);
    setActionError("");
    try {
      await addInvestigationNote(investigationId, note.trim());
      setNote("");
      setActionNotice("Note added.");
      load();
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusy(false);
    }
  };

  if (loading) {
    return (
      <div className="page-center">
        <LoadingSpinner label="Loading investigation…" />
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="page-pad">
        <ErrorMessage message={error || "Investigation not found."} />
        <Link className="link-muted" to="/investigations">← Back to investigations</Link>
      </div>
    );
  }

  const alert = investigation.alert || {};

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <span className="dim-cell" style={{ fontSize: 12 }}>Investigation #{investigation.id}</span>
          <h2 className="page-title"><StatusBadge status={investigation.status} /></h2>
          <p className="page-subtitle">
            {investigation.summary || "No summary set."} — created {formatDateTime(investigation.created_at)}
          </p>
        </div>
        <Link className="btn btn-outline btn-sm" to="/investigations">← Back to investigations</Link>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Linked alert</h3>
          {alert.id && <Link className="link-muted" to={`/alerts/${alert.id}`}>Open alert →</Link>}
        </div>
        {alert.id ? (
          <div className="card-body">
            <div className="meta-grid">
              <div>
                <span className="dim-cell">Alert</span>
                <div>
                  <SeverityBadge severity={alert.severity} />{" "}
                  <Link to={`/alerts/${alert.id}`}>{alert.alert_type || `#${alert.id}`}</Link>
                </div>
              </div>
              <div>
                <span className="dim-cell">Source IP</span>
                <div className="mono">{alert.source_ip || "—"}</div>
              </div>
              <div>
                <span className="dim-cell">Rule</span>
                <div>{alert.rule_name || "—"}</div>
              </div>
              <div>
                <span className="dim-cell">Assignee</span>
                <div>{investigation.assignee_username || <span className="dim-cell">Unassigned</span>}</div>
              </div>
            </div>
            {alert.description && <p className="dim-cell" style={{ marginTop: 12 }}>{alert.description}</p>}
          </div>
        ) : (
          <div className="card-body"><p className="dim-cell">No alert linked.</p></div>
        )}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <h3 className="card-title">Status & summary</h3>
        </div>
        <div className="card-body">
          <div className="field-row" style={{ alignItems: "flex-end" }}>
            <div className="field" style={{ minWidth: 1, flex: 1 }}>
              <label className="field-label">Summary</label>
              <input
                placeholder="What is this investigation following up on?"
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
              />
            </div>
            <button className="btn btn-outline btn-sm" onClick={saveSummary}>Save summary</button>
            {STATUS_OPTIONS.map(({ value, label }) => (
              <button
                key={value}
                className="btn btn-outline btn-sm"
                disabled={busy || investigation.status === value}
                onClick={() => transition(value)}
              >
                {label}
              </button>
            ))}
          </div>
          {actionError && <ErrorMessage message={actionError} />}
          {actionNotice && <p className="text-good" style={{ padding: "8px 0" }}>{actionNotice}</p>}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <h3 className="card-title">Note thread ({investigation.notes?.length || 0})</h3>
        </div>
        <div className="card-body">
          <form className="field-row" style={{ alignItems: "flex-end" }} onSubmit={submitNote}>
            <div className="field" style={{ minWidth: 1, flex: 1 }}>
              <input
                placeholder="Add a finding, hypothesis, or next step…"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !note.trim()}>
              Add note
            </button>
          </form>
          {investigation.notes?.length > 0 && (
            <div className="notes-thread" style={{ marginTop: 16 }}>
              {[...investigation.notes].reverse().map((n) => (
                <div key={n.id} className="note-entry" style={{ borderTop: "1px solid var(--line)", padding: "10px 0" }}>
                  <div className="meta-grid">
                    <div>
                      <span className="dim-cell">{n.author_username || "System"}</span>
                    </div>
                    <div className="dim-cell">{formatDateTime(n.created_at)}</div>
                  </div>
                  <p style={{ marginTop: 6, whiteSpace: "pre-wrap" }}>{n.note}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}