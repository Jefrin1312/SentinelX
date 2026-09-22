import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import StatCard from "../components/StatCard.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import StatusBadge from "../components/StatusBadge.jsx";
import ChartCard from "../components/ChartCard.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { useDashboard } from "../services/dashboard.js";
import { formatTime } from "../utils/format.js";

const SEVERITY_FILL = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
};

export default function Dashboard() {
  const { summary, timeline, loading, error } = useDashboard();

  if (loading) {
    return (
      <div className="page-center">
        <LoadingSpinner label="Loading dashboard…" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="page-pad">
        <h2 className="page-title">Security Dashboard</h2>
        <ErrorMessage message={error} />
      </div>
    );
  }

  if (!summary) return null;

  const severityData = Object.entries(summary.severity).map(([name, value]) => ({
    name: name.toUpperCase(),
    value,
  }));

  const timelineData = timeline.map((p) => ({
    ...p,
    hour: new Date(p.bucket).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
  }));

  const statusData = Object.entries(summary.status).reduce(
    (acc, [name, value]) => ({ ...acc, [name]: value }),
    {}
  );

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Security Dashboard</h2>
          <p className="page-subtitle">Real-time posture from the event pipeline and detection engine.</p>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard label="Total Events" value={summary.total_events} icon="▤" />
        <StatCard label="Total Alerts" value={summary.total_alerts} icon="⚠" />
        <StatCard
          label="Critical Alerts"
          value={summary.severity.critical}
          tone="critical"
          icon="✖"
          hint={summary.severity.critical > 0 ? "Action required" : undefined}
        />
        <StatCard
          label="High Alerts"
          value={summary.severity.high}
          tone="high"
          icon="▲"
        />
        <StatCard
          label="Open Alerts"
          value={statusData.open}
          tone="info"
          icon="○"
        />
        <StatCard
          label="Events · 24h"
          value={summary.events_last_24h}
          icon="◔"
        />
      </div>

      <div className="grid-2col">
        <ChartCard title="Attack Timeline" subtitle="Events and alerts per hour (last 24h)">
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="gEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gAlerts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--critical)" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="var(--critical)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="hour" stroke="var(--text-dim)" fontSize={11} tickCount={8} />
              <YAxis stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                labelStyle={{ color: "var(--text)" }}
              />
              <Legend />
              <Area type="monotone" dataKey="events" name="Events" stroke="var(--accent)" fill="url(#gEvents)" />
              <Area type="monotone" dataKey="alerts" name="Alerts" stroke="var(--critical)" fill="url(#gAlerts)" />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Alert Severity" subtitle="Distribution of alerts by severity">
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={3}>
                {severityData.map((entry) => (
                  <Cell key={entry.name} fill={SEVERITY_FILL[entry.name] || "var(--text-dim)"} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
              />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="grid-2col">
        <ChartCard title="Top Source IPs" subtitle="Most active source addresses in the event stream">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={summary.top_source_ips} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis type="number" stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="source_ip" stroke="var(--text-dim)" fontSize={11} width={120} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                cursor={{ fill: "rgba(56,189,248,0.06)" }}
              />
              <Bar dataKey="count" name="Events" fill="var(--accent)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
          {summary.top_source_ips.length === 0 && <EmptyState title="No source IPs yet" />}
        </ChartCard>

        <ChartCard title="Top Event Types" subtitle="Frequently seen normalised event types">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={summary.top_event_types} margin={{ left: 10 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="event_type" stroke="var(--text-dim)" fontSize={11} interval={0} angle={-18} textAnchor="end" height={60} />
              <YAxis stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                cursor={{ fill: "rgba(56,189,248,0.06)" }}
              />
              <Bar dataKey="count" name="Events" fill="var(--high)" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
          {summary.top_event_types.length === 0 && <EmptyState title="No event types yet" />}
        </ChartCard>
      </div>

      <div className="grid-2col">
        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Alerts</h3>
            <Link className="link-muted" to="/alerts">View all →</Link>
          </div>
          {summary.recent_alerts.length === 0 ? (
            <EmptyState title="No alerts yet" message="Alerts appear when the detection engine flags suspicious activity." />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_alerts.slice(0, 8).map((a) => (
                  <tr key={a.id}>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td><Link to={`/alerts/${a.id}`}>{a.alert_type}</Link></td>
                    <td className="mono">{a.source_ip || "—"}</td>
                    <td><StatusBadge status={a.status} /></td>
                    <td className="dim-cell">{formatTime(a.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3 className="card-title">Recent Security Events</h3>
            <Link className="link-muted" to="/logs">View all →</Link>
          </div>
          {summary.recent_events.length === 0 ? (
            <EmptyState title="No events yet" message="Ingest logs to start the analysis pipeline." />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Source</th>
                  <th>Username</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {summary.recent_events.slice(0, 8).map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{e.event_type}</td>
                    <td className="mono">{e.source_ip || "—"}</td>
                    <td>{e.username || "—"}</td>
                    <td className="dim-cell">{formatTime(e.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}