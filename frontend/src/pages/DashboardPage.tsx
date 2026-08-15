import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, type OverviewData } from "../api";
import { useAuth } from "../AuthContext";
import BadgePill from "../components/BadgePill";

function scoreLabel(score: number): string {
  if (score >= 90) return "READY";
  if (score >= 75) return "REVIEW";
  if (score >= 50) return "NEEDS WORK";
  return "NOT READY";
}

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function refresh() {
    const data = await api.overview();
    setOverview(data);
  }

  useEffect(() => {
    refresh().catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load dashboard"));
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      await api.createProject(newName);
      setNewName("");
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create project");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="shell">
      <div className="topbar">
        <span className="brand">nettle</span>
        <div className="topbar-right">
          <Link to="/settings" className="settings-link">Settings</Link>
          <span>{user?.email}</span>
          <button className="secondary" onClick={() => logout()}>
            Log out
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {overview && (
        <div className="stats-grid">
          <div className="stat-card">
            <span className="stat-value">
              {overview.latestScore !== null ? overview.latestScore : "—"}
            </span>
            <span className="stat-label">
              {overview.latestScore !== null ? scoreLabel(overview.latestScore) : "No scans yet"}
            </span>
            <span className="stat-sublabel">Latest score</span>
          </div>
          <div className="stat-card">
            <span className="stat-value stat-critical">
              {overview.totalCriticalFindings}
            </span>
            <span className="stat-label">Critical findings</span>
            <span className="stat-sublabel">Across all projects</span>
          </div>
          <div className="stat-card">
            <span className="stat-value stat-warning">
              {overview.totalNewAlerts}
            </span>
            <span className="stat-label">Active alerts</span>
            <span className="stat-sublabel">Unresolved</span>
          </div>
          <div className="stat-card">
            <span className="stat-value">{overview.totalProjects}</span>
            <span className="stat-label">Projects</span>
            <span className="stat-sublabel">
              {overview.latestScanAt
                ? `Last scan ${new Date(overview.latestScanAt).toLocaleDateString()}`
                : "No scans yet"}
            </span>
          </div>
        </div>
      )}

      <div className="card">
        <h2>New project</h2>
        <form onSubmit={handleCreate} style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div className="field" style={{ flex: 1, marginBottom: 0 }}>
            <label htmlFor="name">Name</label>
            <input id="name" required value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="My App" />
          </div>
          <button type="submit" disabled={creating}>
            {creating ? "Creating…" : "Create"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Projects</h2>
        {overview === null && <p className="muted">Loading…</p>}
        {overview?.projects.length === 0 && <p className="muted">No projects yet — create one above.</p>}
        {overview?.projects.map((p) => (
          <Link key={p.id} to={`/projects/${p.id}`} className="project-row">
            <div className="project-row-left">
              <span className="project-row-name">{p.name}</span>
              {p.latestScore !== null && (
                <span className="muted">{p.latestScore}/100</span>
              )}
              {p.newAlerts > 0 && (
                <span className="alert-count">{p.newAlerts} alert{p.newAlerts > 1 ? "s" : ""}</span>
              )}
            </div>
            <BadgePill state={p.badge} />
          </Link>
        ))}
      </div>
    </div>
  );
}
