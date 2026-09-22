import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import { fetchSettings } from "../services/settings.js";
import { getApiError } from "../services/api.js";

function Row({ label, value }) {
  return (
    <div className="field-row" style={{ padding: "10px 16px", borderTop: "1px solid var(--line)", minHeight: 44 }}>
      <span className="dim-cell" style={{ minWidth: 220 }}>{label}</span>
      <span className="mono">{value}</span>
    </div>
  );
}

export default function Settings() {
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = () => {
    setLoading(true);
    fetchSettings()
      .then((res) => setSettings(res))
      .catch((err) => setError(getApiError(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Settings</h2>
          <p className="page-subtitle">Read-only view of the platform configuration. Secrets are never exposed.</p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={load}>Refresh</button>
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading settings…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : settings ? (
        <>
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Platform</h3>
            </div>
            <Row label="Application" value={settings.app_name} />
            <Row label="Version" value={settings.app_version} />
            <Row label="Environment" value={settings.app_env} />
            <Row label="API prefix" value={settings.api_prefix} />
            <Row label="Debug mode" value={settings.debug ? "enabled" : "disabled"} />
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <h3 className="card-title">Ingestion</h3>
            </div>
            <Row label="Max upload size" value={`${settings.max_upload_mb} MB`} />
            <Row label="Max upload lines" value={settings.max_upload_lines} />
            <Row label="Sample logs directory" value={settings.sample_logs_dir} />
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <h3 className="card-title">Security & detection</h3>
            </div>
            <Row label="Session lifetime" value={`${settings.jwt_expire_minutes} minutes`} />
            <Row label="Login rate limit" value={settings.login_rate_limit} />
            <Row label="Rules directory" value={settings.rules_dir} />
            <Row label="Detection rules loaded" value={settings.rule_count} />
            <Row label="Registered users" value={settings.user_count} />
          </div>
        </>
      ) : null}
    </div>
  );
}