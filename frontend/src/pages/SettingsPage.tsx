import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api, ApiError, setToken, type SessionInfo } from "../api";
import NettleLogo from "../components/NettleLogo";
import { AppBar, BottomNav, Icons, type TabItem } from "../components/MobileChrome";
import { useIsMobile } from "../useIsMobile";
import { useNavigate } from "react-router-dom";
import { PLAN_LABELS } from "../plans";

export default function SettingsPage() {
  const { user, logout, refreshUser } = useAuth();
  const isMobile = useIsMobile();
  const navigate = useNavigate();

  const body = (
    <>
      <div className="card">
        <h2>Account</h2>
        <div className="settings-row">
          <span className="settings-label">Email</span>
          <span>{user?.email}</span>
        </div>
        <div className="settings-row">
          <span className="settings-label">Plan</span>
          <span className="plan-badge">{PLAN_LABELS[user?.plan ?? "free"] ?? user?.plan}</span>
        </div>
        <div className="settings-row">
          <span className="settings-label">Member since</span>
          <span>{user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : "—"}</span>
        </div>
      </div>
      <ChangeEmailCard onUpdated={refreshUser} />
      <ChangePasswordCard />
      <SessionsCard />
      <DangerZoneCard />
    </>
  );

  if (isMobile) {
    const navItems: TabItem[] = [
      { key: "projects", label: "Projects", icon: Icons.projects },
      { key: "account", label: "Account", icon: Icons.account },
    ];
    return (
      <>
        <AppBar
          title="Account"
          subtitle={user?.email}
          action={<button className="link-btn" onClick={() => logout()}>Log out</button>}
        />
        <div className="shell m-has-bottomnav">{body}</div>
        <BottomNav
          items={navItems}
          active="account"
          onSelect={(k) => { if (k === "projects") navigate("/"); }}
        />
      </>
    );
  }

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand"><NettleLogo size={22} title="" />nettle</Link>
        <span className="muted">{user?.email}</span>
      </div>

      <h1>Settings</h1>

      {body}
    </div>
  );
}

function ChangeEmailCard({ onUpdated }: { onUpdated: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setSubmitting(true);
    try {
      await api.changeEmail(email, password);
      setSuccess(true);
      setEmail("");
      setPassword("");
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h2>Change email</h2>
      {error && <div className="error-banner">{error}</div>}
      {success && <div className="success-banner">Email updated</div>}
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="new-email">New email</label>
          <input id="new-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="email-pw">Password (to confirm)</label>
          <input id="email-pw" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button type="submit" disabled={submitting}>{submitting ? "Updating…" : "Update email"}</button>
      </form>
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
          <input id="current" type="password" required value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="newpw">New password</label>
          <input id="newpw" type="password" required minLength={8} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="confirm">Confirm new password</label>
          <input id="confirm" type="password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </div>
        <button type="submit" disabled={submitting}>{submitting ? "Updating…" : "Update password"}</button>
      </form>
    </div>
  );
}

function SessionsCard() {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listSessions().then(({ sessions }) => setSessions(sessions)).catch(() => {});
  }, []);

  async function revoke(prefix: string) {
    setRevoking(prefix);
    setError(null);
    try {
      await api.revokeSession(prefix);
      setSessions((prev) => prev?.filter((s) => s.tokenPrefix !== prefix) ?? null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to revoke session");
    } finally {
      setRevoking(null);
    }
  }

  async function revokeAll() {
    setError(null);
    try {
      const { token } = await api.revokeAllSessions();
      setToken(token);
      const { sessions } = await api.listSessions();
      setSessions(sessions);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to revoke sessions");
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ margin: 0 }}>Active sessions</h2>
        {sessions && sessions.length > 1 && (
          <button className="small destructive" onClick={revokeAll}>Revoke all others</button>
        )}
      </div>
      {error && <div className="error-banner">{error}</div>}
      {sessions === null && <p className="muted">Loading…</p>}
      {sessions?.map((s) => (
        <div key={s.tokenPrefix} className="settings-row" style={{ alignItems: "center" }}>
          <div>
            <code>{s.tokenPrefix}…</code>
            {s.current && <span className="plan-badge" style={{ marginLeft: 8 }}>current</span>}
            <span className="muted" style={{ marginLeft: 8 }}>
              expires {new Date(s.expiresAt).toLocaleDateString()}
            </span>
          </div>
          {!s.current && (
            <button
              className="small destructive"
              disabled={revoking === s.tokenPrefix}
              onClick={() => revoke(s.tokenPrefix)}
            >
              Revoke
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

function DangerZoneCard() {
  const { logout } = useAuth();
  const [showDelete, setShowDelete] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function handleDelete(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setDeleting(true);
    try {
      await api.deleteAccount(password);
      logout();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to delete account");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="card">
      <h2>Danger zone</h2>
      <div className="settings-row">
        <div>
          <strong>Delete account</strong>
          <p className="muted" style={{ margin: "4px 0 0" }}>Permanently removes your account and all projects, scans, and alerts.</p>
        </div>
        <button className="destructive" onClick={() => setShowDelete(!showDelete)}>
          {showDelete ? "Cancel" : "Delete account…"}
        </button>
      </div>
      {showDelete && (
        <form onSubmit={handleDelete} style={{ marginTop: 12 }}>
          {error && <div className="error-banner">{error}</div>}
          <div className="field">
            <label htmlFor="del-pw">Enter your password to confirm</label>
            <input id="del-pw" type="password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <button type="submit" className="destructive" disabled={deleting}>
            {deleting ? "Deleting…" : "Permanently delete my account"}
          </button>
        </form>
      )}
    </div>
  );
}
