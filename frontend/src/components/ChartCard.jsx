export default function ChartCard({ title, subtitle, children, className }) {
  return (
    <div className={`card chart-card ${className || ""}`}>
      <div className="card-header">
        <div>
          <h3 className="card-title">{title}</h3>
          {subtitle && <p className="card-subtitle">{subtitle}</p>}
        </div>
      </div>
      <div className="card-body">{children}</div>
    </div>
  );
}