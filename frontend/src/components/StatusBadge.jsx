const STATUS_COLORS = {
  OPEN: "var(--open)",
  INVESTIGATING: "var(--investigating)",
  RESOLVED: "var(--resolved)",
};

export default function StatusBadge({ status, label }) {
  const color = STATUS_COLORS[status] || "var(--text-dim)";
  return (
    <span className="badge" style={{ color, borderColor: color, background: `${color}18` }}>
      {label || status || "—"}
    </span>
  );
}

export { STATUS_COLORS };