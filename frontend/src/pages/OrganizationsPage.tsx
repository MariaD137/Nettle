import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, type OrganizationSummary } from "../api";
import { useAuth } from "../AuthContext";
import NettleLogo from "../components/NettleLogo";

export default function OrganizationsPage() {
  const { user } = useAuth();
  const [organizations, setOrganizations] = useState<OrganizationSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);

  function refresh() {
    api
      .listOrganizations()
      .then(({ organizations }) => setOrganizations(organizations))
      .catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load organizations"));
  }

  useEffect(refresh, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      await api.createOrganization(name);
      setName("");
      refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create organization");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand"><NettleLogo size={22} title="" />nettle</Link>
        <div className="topbar-right">
          <Link to="/" className="settings-link">Projects</Link>
          <Link to="/settings" className="settings-link">Settings</Link>
          <span>{user?.email}</span>
        </div>
      </div>

      <h1>Organizations</h1>
      <p className="muted" style={{ marginTop: -8, marginBottom: 24 }}>
        Share projects with teammates. An organization's projects count against the owner's plan — see the
        organization's page for its member limit.
      </p>

      {error && <div className="error-banner">{error}</div>}

      <div className="card">
        <h2>New organization</h2>
        <form onSubmit={handleCreate}>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
            <div className="field" style={{ flex: 1, marginBottom: 0 }}>
              <label htmlFor="org-name">Name</label>
              <input id="org-name" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Acme Corp" />
            </div>
            <button type="submit" disabled={creating}>
              {creating ? "Creating…" : "Create"}
            </button>
          </div>
        </form>
      </div>

      <div className="card">
        <h2>Your organizations</h2>
        {organizations === null && <p className="muted">Loading…</p>}
        {organizations?.length === 0 && <p className="muted">You're not part of any organization yet — create one above.</p>}
        {organizations?.map((org) => (
          <Link key={org.id} to={`/organizations/${org.id}`} className="project-row">
            <div className="project-row-left">
              <span className="project-row-name">{org.name}</span>
              <span className="muted">{org.role === "owner" ? "Owner" : "Member"}</span>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
