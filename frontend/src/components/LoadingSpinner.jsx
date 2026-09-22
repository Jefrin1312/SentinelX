export default function LoadingSpinner({ label = "Loading…" }) {
  return (
    <div className="loading-spinner">
      <div className="spinner" aria-hidden="true"></div>
      <span>{label}</span>
    </div>
  );
}