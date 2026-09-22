import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext.jsx";

export default function Dashboard() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login", { replace: true });
  };

  return (
    <div className="page-center">
      <div className="hero centered">
        <h2>Welcome, {user?.username}</h2>
        <p>
          Role: <strong>{user?.role}</strong> — {user?.email}
        </p>
        <p className="dim">The security dashboard arrives in the next build milestone.</p>
        <button className="btn btn-outline" onClick={handleLogout}>
          Sign out
        </button>
      </div>
    </div>
  );
}