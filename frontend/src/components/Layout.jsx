import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import SeverityBadge from "./SeverityBadge.jsx";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: "◈" },
  { to: "/logs", label: "Security Logs", icon: "▤" },
  { to: "/alerts", label: "Alerts", icon: "⚠" },
  { to: "/investigations", label: "Investigations", icon: "◇" },
  { to: "/reports", label: "Reports", icon: "▦" },
];

const ADMIN_ITEMS = [
  { to: "/rules", label: "Detection Rules", icon: "⚙" },
  { to: "/users", label: "Users", icon: "◉" },
  { to: "/audit-logs", label: "Audit Logs", icon: "◨" },
  { to: "/settings", label: "Settings", icon: "⚙" },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  const isAdmin = user?.role === "ADMIN";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <span className="brand-mark">SX</span>
          <span className="brand-name">SentinelX</span>
        </div>
        <nav className="sidebar-nav">
          <span className="nav-label">Security</span>
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
          {isAdmin && (
            <>
              <span className="nav-label">Administration</span>
              {ADMIN_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
                >
                  <span className="nav-icon">{item.icon}</span>
                  {item.label}
                </NavLink>
              ))}
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <span className="user-avatar">{(user?.username || "?").slice(0, 2).toUpperCase()}</span>
            <div className="user-meta">
              <span className="user-name">{user?.username}</span>
              <SeverityBadge severity={user?.role === "ADMIN" ? "HIGH" : "LOW"} />
              <span className="user-role">{user?.role}</span>
            </div>
          </div>
          <button className="btn btn-outline btn-sm" onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <div className="topbar-status">
            <span className="status-dot"></span>
            Monitoring
          </div>
          <div className="topbar-spacer"></div>
          <span className="topbar-version">SentinelX v0.4</span>
        </header>
        <section className="content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}