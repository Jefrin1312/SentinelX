export default function StatCard({ label, value, tone, icon, hint }) {
  return (
    <div className="stat-card">
      <div className="stat-top">
        {icon && <span className="stat-icon">{icon}</span>}
        <span className="stat-label">{label}</span>
      </div>
      <span className={`stat-value ${tone ? `stat-tone-${tone}` : ""}`}>{value}</span>
      {hint && <span className="stat-hint">{hint}</span>}
    </div>
  );
}