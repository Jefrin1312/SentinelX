import { useEffect, useState } from "react";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { formatTime } from "../utils/format.js";
import { fetchUsers, updateUser } from "../services/users.js";
import { getApiError } from "../services/api.js";

const ROLES = ["ADMIN", "ANALYST"];
const PAGE_SIZES = [10, 25, 50];

export default function Users() {
  const [search, setSearch] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [role, setRole] = useState("");
  const [appliedRole, setAppliedRole] = useState("");
  const [page, setPage] = useState({ limit: 25, offset: 0 });
  const [data, setData] = useState({ total: 0, items: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");

  useEffect(() => {
    let cancelled = false;
    const params = { limit: page.limit, skip: page.offset };
    if (appliedSearch) params.search = appliedSearch;
    if (appliedRole) params.role = appliedRole;
    setLoading(true);
    fetchUsers(params)
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
  }, [appliedSearch, appliedRole, page.limit, page.offset]);

  const pageNum = Math.floor(page.offset / page.limit) + 1;
  const totalPages = Math.max(1, Math.ceil(data.total / page.limit));

  const applyFilters = () => {
    setAppliedSearch(search.trim());
    setAppliedRole(role);
    setPage((p) => ({ ...p, offset: 0 }));
  };
  const resetFilters = () => {
    setSearch("");
    setRole("");
    setAppliedSearch("");
    setAppliedRole("");
    setPage((p) => ({ ...p, offset: 0 }));
  };

  const persist = async (user, payload) => {
    setBusyId(user.id);
    setActionError("");
    setNotice("");
    try {
      const saved = await updateUser(user.id, payload);
      setData((d) => ({
        ...d,
        items: d.items.map((u) => (u.id === saved.id ? saved : u)),
      }));
      setNotice(`${saved.username} updated.`);
    } catch (err) {
      setActionError(getApiError(err));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Users</h2>
          <p className="page-subtitle">Manage accounts, roles, and access to the platform.</p>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="field-row">
          <div className="field grow">
            <label className="field-label">Search</label>
            <input
              placeholder="Username or email…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <div className="field">
            <label className="field-label">Role</label>
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="">All roles</option>
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="field mt-auto">
            <div className="btn-row">
              <button className="btn btn-primary" onClick={applyFilters}>Apply filters</button>
              <button className="btn btn-outline" onClick={resetFilters}>Reset</button>
            </div>
          </div>
        </div>
        {notice && <p className="text-good" style={{ padding: "8px 16px 0" }}>{notice}</p>}
        {actionError && <div style={{ padding: "8px 16px 0" }}><ErrorMessage message={actionError} /></div>}
      </div>

      {loading ? (
        <div className="page-center" style={{ minHeight: 160 }}>
          <LoadingSpinner label="Loading users…" />
        </div>
      ) : error ? (
        <ErrorMessage message={error} />
      ) : data.items.length === 0 ? (
        <EmptyState title="No users match" message="Adjust the filters to see accounts." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Accounts ({data.total})</h3>
            <div className="toolbar">
              <select
                value={page.limit}
                aria-label="Users per page"
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
          <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Joined</th>
                <th style={{ textAlign: "right" }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((u) => (
                <tr key={u.id} style={u.is_active ? undefined : { opacity: 0.55 }}>
                  <td className="mono dim-cell">{u.id}</td>
                  <td className="mono">{u.username}</td>
                  <td>{u.email || "—"}</td>
                  <td>
                    <select
                      value={u.role}
                      disabled={busyId === u.id}
                      onChange={(e) => persist(u, { role: e.target.value })}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <span
                      className="badge"
                      style={u.is_active
                        ? { color: "var(--good)", borderColor: "var(--good)", background: "var(--good)18" }
                        : { color: "var(--text-dim)", borderColor: "var(--text-dim)", background: "var(--text-dim)18" }}
                    >
                      {u.is_active ? "ACTIVE" : "DISABLED"}
                    </span>
                  </td>
                  <td className="dim-cell">{formatTime(u.created_at)}</td>
                  <td style={{ textAlign: "right" }}>
                    {u.is_active ? (
                      <button
                        className="btn btn-outline btn-sm"
                        disabled={busyId === u.id}
                        onClick={() => persist(u, { is_active: false })}
                      >
                        Disable
                      </button>
                    ) : (
                      <button
                        className="btn btn-outline btn-sm"
                        disabled={busyId === u.id}
                        onClick={() => persist(u, { is_active: true })}
                      >
                        Enable
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </div>
      )}
    </div>
  );
}