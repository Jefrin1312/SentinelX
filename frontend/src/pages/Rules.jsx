import { useEffect, useState } from "react";
import EmptyState from "../components/EmptyState.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { createRule, fetchRules, reloadRules, setRuleEnabled } from "../services/rules.js";
import { getApiError } from "../services/api.js";
import { useAuth } from "../context/AuthContext.jsx";

const CATEGORIES = ["authentication", "ssh", "web", "system", "general"];
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const KEYS = ["source_ip", "username"];

const EMPTY_FORM = {
  name: "",
  description: "",
  category: "general",
  severity: "MEDIUM",
  threshold: "5",
  time_window: "300",
  event_type: "",
  key: "source_ip",
  status: "",
};

export default function Rules() {
  const { user } = useAuth();
  const isAdmin = user?.role === "ADMIN";
  const [rules, setRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [category, setCategory] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [notice, setNotice] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [form, setForm] = useState(EMPTY_FORM);
  const [formBusy, setFormBusy] = useState(false);
  const [formError, setFormError] = useState("");

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

  const updateForm = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  const submitForm = async (e) => {
    e.preventDefault();
    setFormBusy(true);
    setFormError("");
    try {
      const ruleDefinition = {
        event_type: form.event_type.trim(),
        key: form.key,
      };
      if (form.status.trim()) ruleDefinition.status = form.status.trim();
      await createRule({
        name: form.name.trim(),
        description: form.description.trim() || null,
        category: form.category,
        severity: form.severity,
        threshold: Number(form.threshold),
        time_window: Number(form.time_window),
        rule_definition: ruleDefinition,
      });
      setForm(EMPTY_FORM);
      setFormOpen(false);
      setNotice(`${form.name.trim()} created.`);
      load();
    } catch (err) {
      setFormError(getApiError(err));
    } finally {
      setFormBusy(false);
    }
  };

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
        <div style={{ display: "flex", gap: 8 }}>
          {isAdmin && (
            <button className="btn btn-primary btn-sm" onClick={() => { setFormOpen((v) => !v); setFormError(""); }}>
              {formOpen ? "Hide form" : "New rule"}
            </button>
          )}
          <button className="btn btn-outline btn-sm" onClick={reload}>Reload from disk</button>
        </div>
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

      {formOpen && isAdmin && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-header">
            <h3 className="card-title">New detection rule</h3>
          </div>
          <form className="field-row" style={{ alignItems: "flex-end" }} onSubmit={submitForm}>
            <div className="field" style={{ minWidth: 220, flex: 1 }}>
              <label className="field-label">Name</label>
              <input
                placeholder="e.g. Suspicious Sudo Burst"
                value={form.name}
                onChange={(e) => updateForm("name", e.target.value)}
                required
                minLength={3}
                maxLength={120}
              />
            </div>
            <div className="field" style={{ minWidth: 180, flex: 1 }}>
              <label className="field-label">Description</label>
              <input
                placeholder="What this rule detects"
                value={form.description}
                onChange={(e) => updateForm("description", e.target.value)}
                maxLength={2000}
              />
            </div>
            <div className="field">
              <label className="field-label">Category</label>
              <select value={form.category} onChange={(e) => updateForm("category", e.target.value)}>
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="field-label">Severity</label>
              <select value={form.severity} onChange={(e) => updateForm("severity", e.target.value)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div className="field" style={{ minWidth: 110 }}>
              <label className="field-label">Threshold</label>
              <input
                type="number"
                min={1}
                max={100000}
                value={form.threshold}
                onChange={(e) => updateForm("threshold", e.target.value)}
                required
              />
            </div>
            <div className="field" style={{ minWidth: 130 }}>
              <label className="field-label">Window (s)</label>
              <input
                type="number"
                min={1}
                max={604800}
                value={form.time_window}
                onChange={(e) => updateForm("time_window", e.target.value)}
                required
              />
            </div>
            <div className="field" style={{ minWidth: 200 }}>
              <label className="field-label">Event type</label>
              <input
                placeholder="e.g. SSH_LOGIN_FAILURE"
                value={form.event_type}
                onChange={(e) => updateForm("event_type", e.target.value)}
                required
              />
            </div>
            <div className="field">
              <label className="field-label">Group by</label>
              <select value={form.key} onChange={(e) => updateForm("key", e.target.value)}>
                {KEYS.map((k) => (
                  <option key={k} value={k}>{k}</option>
                ))}
              </select>
            </div>
            <div className="field" style={{ minWidth: 140 }}>
              <label className="field-label">Status filter</label>
              <input
                placeholder="optional"
                value={form.status}
                onChange={(e) => updateForm("status", e.target.value)}
              />
            </div>
            <button className="btn btn-primary btn-sm" type="submit" disabled={formBusy}>
              {formBusy ? "Creating…" : "Create rule"}
            </button>
          </form>
          {formError && <ErrorMessage message={formError} />}
        </div>
      )}

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