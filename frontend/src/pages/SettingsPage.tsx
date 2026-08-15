import { useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api, ApiError } from "../api";

export default function SettingsPage() {
  const { user, logout } = useAuth();

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand">nettle</Link>
        <span className="muted">{user?.email}</span>
      </div>

      <h1>Settings</h1>

      <div className="card">
        <h2>Account</h2>
        <div className="settings-row">
          <span className="settings-label">Email</span>
          <span>{user?.email}</span>
        </div>
        <div className="settings-row">
          <span className="settings-label">Plan</span>
          <span className="plan-badge">{user?.plan === "free" ? "Free" : user?.plan}</span>
        </div>
        <div className="settings-row">
          <span className="settings-label">Member since</span>
          <span>{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : "—"}</span>
        </div>
      </div>

      <ChangePasswordCard />

      <div className="card">
        <h2>Danger zone</h2>
        <button className="destructive" onClick={() => logout()}>
          Log out
        </button>
      </div>
    </div>
  );
}

function ChangePasswordCard() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);

    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters");
      return;
    }
    if (newPassword !== confirm) {
      setError("Passwords don't match");
      return;
    }

    setSubmitting(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setSuccess(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirm("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h2>Change password</h2>
      {error && <div className="error-banner">{error}</div>}
      {success && <div className="success-banner">Password updated successfully</div>}
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="current">Current password</label>
          <input
            id="current"
            type="password"
            required
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="newpw">New password</label>
          <input
            id="newpw"
            type="password"
            required
            minLength={8}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="confirm">Confirm new password</label>
          <input
            id="confirm"
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? "Updating…" : "Update password"}
        </button>
      </form>
    </div>
  );
}
