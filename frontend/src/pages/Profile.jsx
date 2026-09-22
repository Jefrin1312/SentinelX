import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ErrorMessage from "../components/ErrorMessage.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { formatDateTime } from "../utils/format.js";
import { useAuth } from "../context/AuthContext.jsx";
import { changePassword, updateProfile } from "../services/auth.js";
import { getApiError } from "../services/api.js";

export default function Profile() {
  const { user, setUser, logout } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState(user?.email || "");
  const [profileBusy, setProfileBusy] = useState(false);
  const [profileError, setProfileError] = useState("");
  const [profileNotice, setProfileNotice] = useState("");

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [passwordError, setPasswordError] = useState("");
  const [passwordNotice, setPasswordNotice] = useState("");

  const saveProfile = async (e) => {
    e.preventDefault();
    setProfileBusy(true);
    setProfileError("");
    setProfileNotice("");
    try {
      const saved = await updateProfile({ email: email.trim() });
      setUser((prev) => ({ ...prev, email: saved.email }));
      setProfileNotice("Profile updated.");
    } catch (err) {
      setProfileError(getApiError(err));
    } finally {
      setProfileBusy(false);
    }
  };

  const submitPassword = async (e) => {
    e.preventDefault();
    setPasswordError("");
    setPasswordNotice("");
    if (newPassword !== confirmPassword) {
      setPasswordError("New passwords do not match.");
      return;
    }
    setPasswordBusy(true);
    try {
      await changePassword(currentPassword, newPassword);
      setPasswordNotice("Password changed. Signing you back in…");
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTimeout(() => {
        logout().finally(() => navigate("/login", { replace: true }));
      }, 800);
    } catch (err) {
      setPasswordError(getApiError(err));
    } finally {
      setPasswordBusy(false);
    }
  };

  return (
    <div className="page-pad">
      <div className="page-head">
        <div>
          <h2 className="page-title">My Account</h2>
          <p className="page-subtitle">Update your contact details and credentials.</p>
        </div>
        <SeverityBadge severity={user?.role === "ADMIN" ? "HIGH" : "LOW"} />
      </div>

      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Profile</h3>
        </div>
        <div className="card-body">
          <div className="meta-grid" style={{ marginBottom: 16 }}>
            <div>
              <span className="dim-cell">Username</span>
              <div className="mono">{user?.username}</div>
            </div>
            <div>
              <span className="dim-cell">Role</span>
              <div>{user?.role}</div>
            </div>
            <div>
              <span className="dim-cell">Account status</span>
              <div>{user?.is_active ? "Active" : "Disabled"}</div>
            </div>
            <div>
              <span className="dim-cell">Member since</span>
              <div>{formatDateTime(user?.created_at)}</div>
            </div>
          </div>

          <form className="field-row" style={{ alignItems: "flex-end" }} onSubmit={saveProfile}>
            <div className="field" style={{ minWidth: 280, flex: 1 }}>
              <label className="field-label">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <button className="btn btn-primary btn-sm" type="submit" disabled={profileBusy}>
              {profileBusy ? "Saving…" : "Save profile"}
            </button>
          </form>
          {profileError && <ErrorMessage message={profileError} />}
          {profileNotice && <p className="text-good" style={{ padding: "8px 0" }}>{profileNotice}</p>}
        </div>
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <h3 className="card-title">Change password</h3>
        </div>
        <div className="card-body">
          <p className="dim-cell" style={{ marginBottom: 12 }}>
            After a successful change your current session is invalidated and you will be asked to sign in again.
          </p>
          <form className="field-row" style={{ alignItems: "flex-end", flexWrap: "wrap", gap: 16 }} onSubmit={submitPassword}>
            <div className="field" style={{ minWidth: 220 }}>
              <label className="field-label">Current password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
              />
            </div>
            <div className="field" style={{ minWidth: 220 }}>
              <label className="field-label">New password</label>
              <input
                type="password"
                placeholder="10+ characters"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="field" style={{ minWidth: 220 }}>
              <label className="field-label">Confirm new password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
            <button className="btn btn-primary btn-sm" type="submit" disabled={passwordBusy}>
              {passwordBusy ? "Updating…" : "Change password"}
            </button>
          </form>
          {passwordError && <ErrorMessage message={passwordError} />}
          {passwordNotice && <p className="text-good" style={{ padding: "8px 0" }}>{passwordNotice}</p>}
        </div>
      </div>
    </div>
  );
}