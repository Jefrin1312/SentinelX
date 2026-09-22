import { useEffect, useState } from "react";
import EmptyState from "../components/EmptyState.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { fetchRules, reloadRules, setRuleEnabled } from "../services/rules.js";
import { getApiError } from "../services/api.js";

const CATEGORIES = ["authentication", "ssh", "web", "system"];

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [category, setCategory] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [notice, setNotice] = useState("");

  const load = () => {
    setLoading(true);
    fetchRules({ category: category || undefined, limit: 500 })
      .then((res) => {
        setRules(res.items);
        setTotal(res.total);
      })
      .catch((err) => setError(getApiError(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, [category]);

  const toggle = async (rule) => {
    setBusyId(rule.id);
    setNotice("");
    try {
      const saved = await setRuleEnabled(rule.id, !rule.enabled);
      setRules((items) => items.map((r) => (r.id === rule.id ? saved : r)));
      setNotice(`${saved.name} ${saved.enabled ? "enabled" : "disabled"}.`);
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setBusyId(null);
    }
  };

  const reload = async () => {
    setError("");
    setNotice("");
    try {
      const result = await reloadRules();
      setNotice(`Rules reloaded from disk (${result.loaded} loaded, ${result.updated} updated).`);
      load();
    } catch (err) {
      setError(getApiError(err));
    }
  };

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Detection Rules</h2>
          <p className="page-subtitle">Declarative threshold rules evaluated against every ingested event.</p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={reload}>Reload from disk</button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field">
            <label className="field-label">Category</label>
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">All categories</option>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>
        </div>
        {notice && <p className="text-good" style={{ padding: "8px 16px" }}>{notice}</p>}
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading rules…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : rules.length === 0 ? (
        <EmptyState title="No rules to show" message="Rules are loaded from the rules/ YAML bundles at startup." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Ruleset ({total})</h3>
          </div>
          <table className="data-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Threshold</th>
                <th>Window</th>
                <th>Status</th>
                <th style={{ textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <div>{rule.name}</div>
                    <div className="dim-cell" style={{ fontSize: 12, maxWidth: 420 }}>{rule.description}</div>
                  </td>
                  <td className="mono">{rule.category}</td>
                  <td><SeverityBadge severity={rule.severity} /></td>
                  <td className="mono">{rule.threshold}</td>
                  <td className="mono">{rule.time_window}s</td>
                  <td>
                    <span className={`badge ${rule.enabled ? "" : ""}`} style={rule.enabled
                      ? { color: "var(--good)", borderColor: "var(--good)", background: "var(--good)18" }
                      : { color: "var(--text-dim)", borderColor: "var(--text-dim)", background: "var(--text-dim)18" }}>
                      {rule.enabled ? "ENABLED" : "DISABLED"}
                    </span>
                  </td>
                  <td style={{ textAlign: "right" }}>
                    <button
                      className="btn btn-outline btn-sm"
                      disabled={busyId === rule.id}
                      onClick={() => toggle(rule)}
                    >
                      {busyId === rule.id ? "…" : rule.enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}