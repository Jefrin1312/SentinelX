import { useEffect, useState } from "react";
import { api, getApiError } from "../services/api.js";

export default function Home() {
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .get("/health")
      .then((res) => setHealth(res.data))
      .catch((err) => setError(getApiError(err)))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark">SX</span>
          <span className="brand-name">SentinelX</span>
        </div>
        <nav className="sidebar-nav">
          <span className="nav-item active">Dashboard</span>
        </nav>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <h1>SentinelX — Security Log Analysis &amp; Threat Detection</h1>
        </header>
        <section className="content">
          <div className="hero">
            <h2>Backend Connectivity</h2>
            {loading && <p className="loading">Checking backend health…</p>}
            {error && <p className="error-text">Backend unavailable: {error}</p>}
            {health && (
              <div className="health-grid">
                <div className="stat-card">
                  <span className="stat-label">Application</span>
                  <span className="stat-value">{health.application}</span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">Environment</span>
                  <span className="stat-value">{health.environment}</span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">Database</span>
                  <span className={`stat-value ${health.database === "up" ? "text-good" : "text-bad"}`}>
                    {health.database}
                  </span>
                </div>
                <div className="stat-card">
                  <span className="stat-label">API</span>
                  <a className="stat-value link" href="/api/docs" target="_blank" rel="noreferrer">
                    Swagger Docs
                  </a>
                </div>
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}