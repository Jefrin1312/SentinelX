import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import StatCard from "../components/StatCard.jsx";
import ChartCard from "../components/ChartCard.jsx";
import LoadingSpinner from "../components/LoadingSpinner.jsx";
import ErrorMessage from "../components/ErrorMessage.jsx";
import { fetchReportSummary } from "../services/reports.js";
import { getApiError } from "../services/api.js";

const DAY_OPTIONS = [7, 14, 30, 90];
const SEVERITY_FILL = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
};
const STATUS_FILL = {
  OPEN: "var(--accent)",
  INVESTIGATING: "var(--high)",
  RESOLVED: "var(--good)",
};

export default function Reports() {
  const [days, setDays] = useState(14);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchReportSummary({ days })
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
  }, [days]);

  if (loading && !data) {
    return (
      <div className="page-center">
        <LoadingSpinner label="Building reports…" />
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="page-pad">
        <h2 className="page-title">Reports</h2>
        <ErrorMessage message={error} />
      </div>
    );
  }

  if (!data) return null;

  const trend = data.by_day_alerts.map((p, idx) => ({
    ...p,
    events: data.by_day_events[idx]?.events || 0,
  }));

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">Reports</h2>
          <p className="page-subtitle">Trends and breakdowns aggregated live from the event pipeline and detection engine.</p>
        </div>
        <div className="field-row" style={{ gap: 8 }}>
          {DAY_OPTIONS.map((d) => (
            <button
              key={d}
              className={`btn btn-sm ${days === d ? "btn-primary" : "btn-outline"}`}
              onClick={() => setDays(d)}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      <div className="stats-grid">
        <StatCard label="Events in window" value={data.total_events} icon="▤" />
        <StatCard label="Alerts in window" value={data.total_alerts} icon="⚠" />
        <StatCard
          label="Avg resolution"
          value={data.avg_resolution_minutes != null ? `${data.avg_resolution_minutes}m` : "—"}
          icon="◷"
        />
        <StatCard label="Window" value={`${data.days} days`} icon="◔" />
      </div>

      <div className="grid-2col">
        <ChartCard title="Daily Volume" subtitle={`Events and alerts per day (last ${data.days} days)`}>
          <ResponsiveContainer width="100%" height={260}>
            <ComposedChart data={trend}>
              <defs>
                <linearGradient id="gEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--accent)" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="var(--accent)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="day" stroke="var(--text-dim)" fontSize={11} tickCount={Math.min(data.days, 8)} />
              <YAxis stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                labelStyle={{ color: "var(--text)" }}
              />
              <Legend />
              <Area type="monotone" dataKey="events" name="Events" stroke="var(--accent)" fill="url(#gEvents)" />
              <Line type="monotone" dataKey="alerts" name="Alerts" stroke="var(--critical)" strokeWidth={2} dot={false} />
            </ComposedChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Top Alert Types" subtitle="Most frequent detections in the window">
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={data.top_alert_types} layout="vertical" margin={{ left: 10 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis type="number" stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="alert_type" stroke="var(--text-dim)" fontSize={11} width={180} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                cursor={{ fill: "rgba(248,113,113,0.06)" }}
              />
              <Bar dataKey="count" name="Alerts" fill="var(--critical)" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="grid-2col">
        <ChartCard title="Alerts by Severity" subtitle="Distribution of detections by priority">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data.by_severity} margin={{ left: 10 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="severity" stroke="var(--text-dim)" fontSize={11} />
              <YAxis stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                cursor={{ fill: "rgba(56,189,248,0.06)" }}
              />
              <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                {data.by_severity.map((entry) => (
                  <Cell key={entry.severity} fill={SEVERITY_FILL[entry.severity] || "var(--text-dim)"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Alerts by Status" subtitle="Triage pipeline health in the window">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={data.by_status} margin={{ left: 10 }}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis dataKey="status" stroke="var(--text-dim)" fontSize={11} />
              <YAxis stroke="var(--text-dim)" fontSize={11} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", borderRadius: 8 }}
                cursor={{ fill: "rgba(56,189,248,0.06)" }}
              />
              <Bar dataKey="count" name="Alerts" radius={[4, 4, 0, 0]}>
                {data.by_status.map((entry) => (
                  <Cell key={entry.status} fill={STATUS_FILL[entry.status] || "var(--text-dim)"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </div>
  );
}