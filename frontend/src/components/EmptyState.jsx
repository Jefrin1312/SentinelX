export default function EmptyState({ title = "Nothing here yet", message }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">◎</div>
      <h4>{title}</h4>
      {message && <p>{message}</p>}
    </div>
  );
}