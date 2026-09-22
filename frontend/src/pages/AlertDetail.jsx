import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import { formatDateTime } from "../utils/format.js";
import { fetchAlert, updateAlertStatus } from "../services/alerts.js";
import { createInvestigation } from "../services/investigations.js";
import { getApiError } from "../services/api.js";

const STATUS_OPTIONS = [
  { value: "OPEN", label: "Reopen" },
  { value: "INVESTIGATING", label: "Start investigation" },
  { value: "RESOLVED", label: "Resolve" },
];

export default function AlertDetail() {
  const { alertId } = useParams();
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [actionNotice, setActionNotice] = useState("");
  const [opening, setOpening] = useState(false);

  const load = () => {
    setLoading(true);
    fetchAlert(alertId)
      .then((res) => {
        setAlert(res);
        setActionNotice("");
      })
      .catch((err) => setError(getApiError(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, [alertId]);

  const transition = async (status) => {
    setBusy(true);
    setActionError("");
    try {
      const saved = await updateAlertStatus(alertId, status, note.trim() || null);
      setAlert((prev) => ({ ...prev, status: saved.status, resolved_at: saved.resolved_at }));
      setNote("");
      setActionNotice(`Alert moved to ${saved.status}.`);
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusy(false);
    }
  };

  const openInvestigation = async () => {
    setOpening(true);
    setActionError("");
    try {
      await createInvestigation({
        alert_id: alert.id,
        summary: note.trim() || null,
      });
      setNote("");
      setActionNotice("Investigation opened — alert moved to INVESTIGATING.");
      load();
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setOpening(false);
    }
  };

  if (loading) {
    return (
      <div className="page-center">
        <LoadingSpinner label="Loading alert…" />
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="page-pad">
        <ErrorMessage message={error || "Alert not found."} />
        <Link className="link-muted" to="/alerts">← Back to alerts</Link>
      </div>
    );
  }

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <span className="dim-cell" style={{ fontSize: 12 }}>Alert #{alert.id}</span>
          <h2 className="page-title">{alert.alert_type}</h2>
          <p className="page-subtitle">{alert.description}</p>
        </div>
        <Link className="btn btn-outline btn-sm" to="/alerts">← Back to alerts</Link>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <h3 className="card-title">
            <SeverityBadge severity={alert.severity} />
            {" "}<StatusBadge status={alert.status} />
          </h3>
        </div>
        <div className="card-body">
          <div className="meta-grid">
            <div>
              <span className="dim-cell">Raised</span>
              <div>{formatDateTime(alert.created_at)}</div>
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
              <span className="dim-cell">Resolved</span>
              <div>{formatDateTime(alert.resolved_at)}</div>
            </div>
          </div>
          {alert.metadata && Object.keys(alert.metadata).length > 0 && (
            <>
              <div className="field-label" style={{ marginTop: 16 }}>Rule context</div>
              <pre className="meta-json">{JSON.stringify(alert.metadata, null, 2)}</pre>
            </>
          )}

          <div className="field-row" style={{ marginTop: 16, alignItems: "flex-end" }}>
            <div className="field" style={{ minWidth: 240 }}>
              <label className="field-label">Triage note (optional)</label>
              <input
                placeholder="Why this status change?"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </div>
            <div className="field-row" style={{ gap: 8 }}>
              {STATUS_OPTIONS.map(({ value, label }) => (
                <button
                  key={value}
                  className="btn btn-outline btn-sm"
                  disabled={busy || alert.status === value}
                  onClick={() => transition(value)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          {actionError && <ErrorMessage message={actionError} />}
          {actionNotice && <p className="text-good" style={{ padding: "8px 0" }}>{actionNotice}</p>}

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <h3 className="card-title">
                Investigation
                {alert.investigation && <StatusBadge status={alert.investigation.status} />}
              </h3>
              {alert.investigation && (
                <Link className="link-muted" to={`/investigations/${alert.investigation.id}`}>
                  Open investigation →
                </Link>
              )}
            </div>
            {alert.investigation ? (
              <div className="card-body">
                <div className="meta-grid">
                  <div>
                    <span className="dim-cell">Investigation</span>
                    <div className="mono">#{alert.investigation.id}</div>
                  </div>
                  <div>
                    <span className="dim-cell">Assignee</span>
                    <div>{alert.investigation.assignee_username || <span className="dim-cell">Unassigned</span>}</div>
                  </div>
                  <div>
                    <span className="dim-cell">Opened</span>
                    <div>{formatDateTime(alert.investigation.created_at)}</div>
                  </div>
                </div>
                {alert.investigation.summary && (
                  <p className="dim-cell" style={{ marginTop: 12 }}>{alert.investigation.summary}</p>
                )}
              </div>
            ) : (
              <div className="card-body">
                <p className="dim-cell" style={{ marginBottom: 12 }}>
                  No investigation is linked to this alert yet. Opening one moves it to INVESTIGATING.
                </p>
                <button
                  className="btn btn-primary btn-sm"
                  disabled={opening}
                  onClick={openInvestigation}
                >
                  {opening ? "Opening…" : "Open investigation"}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Related Event</h3>
          {alert.event && <Link className="link-muted" to="/logs">View log stream →</Link>}
        </div>
        {alert.event ? (
          <div className="card-body">
            <div className="meta-grid">
              <div>
                <span className="dim-cell">Recorded</span>
                <div>{formatDateTime(alert.event.timestamp)}</div>
              </div>
              <div>
                <span className="dim-cell">Event type</span>
                <div className="mono">{alert.event.event_type}</div>
              </div>
              <div>
                <span className="dim-cell">Source IP</span>
                <div className="mono">{alert.event.source_ip || "—"}</div>
              </div>
              <div>
                <span className="dim-cell">Username</span>
                <div>{alert.event.username || "—"}</div>
              </div>
            </div>
            <p className="mono" style={{ marginTop: 12, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {alert.event.message}
            </p>
          </div>
        ) : (
          <div className="card-body">
            <p className="dim-cell">No event is linked to this alert.</p>
          </div>
        )}
      </div>
    </div>
  );
}