import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, type BadgeState, type Project } from "../api";
import { useAuth } from "../AuthContext";
import BadgePill from "../components/BadgePill";

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [badges, setBadges] = useState<Record<string, BadgeState>>({});
  const [newName, setNewName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function refresh() {
    const { projects } = await api.listProjects();
    setProjects(projects);
    const entries = await Promise.all(projects.map(async (p) => [p.id, await api.getBadge(p.id)] as const));
    setBadges(Object.fromEntries(entries));
  }

  useEffect(() => {
    refresh().catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load projects"));
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
          <span>{user?.email}</span>
          <button className="secondary" onClick={() => logout()}>
            Log out
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

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
        {projects === null && <p className="muted">Loading…</p>}
        {projects?.length === 0 && <p className="muted">No projects yet — create one above.</p>}
        {projects?.map((p) => (
          <Link key={p.id} to={`/projects/${p.id}`} className="project-row">
            <span className="project-row-name">{p.name}</span>
            {badges[p.id] && <BadgePill state={badges[p.id]} />}
          </Link>
        ))}
      </div>
    </div>
  );
}
