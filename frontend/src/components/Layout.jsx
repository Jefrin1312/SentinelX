import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";
import SeverityBadge from "./SeverityBadge.jsx";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: "◈" },
  { to: "/assistant", label: "Security Assistant", icon: "✦" },
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
  const location = useLocation();
  const [navOpen, setNavOpen] = useState(false);

  const closeNav = () => setNavOpen(false);

  const handleLogout = async () => {
    setNavOpen(false);
    await logout();
    navigate("/login", { replace: true });
  };

  useEffect(() => {
    closeNav();
  }, [location.pathname]);

  useEffect(() => {
    if (!navOpen) return undefined;
    document.body.classList.add("drawer-open");
    const onKeyDown = (e) => {
      if (e.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.classList.remove("drawer-open");
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [navOpen]);

  const isAdmin = user?.role === "ADMIN";

  return (
    <div className={`app-shell ${navOpen ? "sidebar-open" : ""}`}>
      <button
        className="sidebar-backdrop"
        aria-label="Close navigation"
        onClick={closeNav}
        tabIndex={navOpen ? 0 : -1}
      />
      <aside className="sidebar" aria-label="Primary">
        <div className="sidebar-brand">
          <span className="brand-mark">SX</span>
          <span className="brand-name">SentinelX</span>
          <button className="sidebar-close" aria-label="Close navigation" onClick={closeNav}>
            ✕
          </button>
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
          <button className="btn btn-outline btn-sm" style={{ marginTop: 8 }} onClick={() => navigate("/profile")}>
            Profile
          </button>
          <button className="btn btn-outline btn-sm" style={{ marginTop: 8 }} onClick={handleLogout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <button
            className="menu-btn"
            aria-label={navOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={navOpen}
            onClick={() => setNavOpen((v) => !v)}
          >
            {navOpen ? "✕" : "☰"}
          </button>
          <span className="topbar-brand">SentinelX</span>
          <div className="topbar-status">
            <span className="status-dot"></span>
            <span>Monitoring</span>
          </div>
          <div className="topbar-spacer"></div>
          <span className="topbar-version">v0.4.0</span>
        </header>
        <section className="content">
          <Outlet />
        </section>
      </main>
    </div>
  );
}