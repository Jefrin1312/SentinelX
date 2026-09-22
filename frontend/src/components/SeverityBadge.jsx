const SEVERITY_COLORS = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
};

export default function SeverityBadge({ severity }) {
  const color = SEVERITY_COLORS[severity] || "var(--text-dim)";
  return (
    <span className="badge" style={{ color, borderColor: color, background: `${color}18` }}>
      {severity || "UNKNOWN"}
    </span>
  );
}

export { SEVERITY_COLORS };