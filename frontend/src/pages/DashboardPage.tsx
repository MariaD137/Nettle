import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, type OverviewData, type OrganizationSummary } from "../api";
import { useAuth } from "../AuthContext";
import BadgePill from "../components/BadgePill";
import NettleLogo from "../components/NettleLogo";
import { AppBar, BottomNav, Icons, type TabItem } from "../components/MobileChrome";
import { useIsMobile } from "../useIsMobile";
import { useNavigate } from "react-router-dom";
import { scanUsageCopy } from "../scanUsage";

function scoreLabel(score: number): string {
  if (score >= 90) return "READY";
  if (score >= 75) return "REVIEW";
  if (score >= 50) return "NEEDS WORK";
  return "NOT READY";
}

export default function DashboardPage() {
  const { user, logout } = useAuth();
  const isMobile = useIsMobile();
  const navigate = useNavigate();
  const [showNew, setShowNew] = useState(false);
  const [overview, setOverview] = useState<OverviewData | null>(null);
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newEnv, setNewEnv] = useState("");
  const [newOrgId, setNewOrgId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  async function refresh() {
    const data = await api.overview();
    setOverview(data);
  }

  useEffect(() => {
    refresh().catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load dashboard"));
    api.listOrganizations().then(({ organizations }) => setOrganizations(organizations)).catch(() => {});
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      await api.createProject(newName, {
        url: newUrl || undefined,
        description: newDesc || undefined,
        environment: newEnv || undefined,
        organizationId: newOrgId || undefined,
      });
      setNewName("");
      setNewUrl("");
      setNewDesc("");
      setNewEnv("");
      setNewOrgId("");
      setShowAdvanced(false);
      setShowNew(false);
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create project");
    } finally {
      setCreating(false);
    }
  }

  const orgPicker = organizations.length > 0 && (
    <div className="field">
      <label htmlFor="proj-org">Organization</label>
      <select id="proj-org" value={newOrgId} onChange={(e) => setNewOrgId(e.target.value)}>
        <option value="">Personal (just me)</option>
        {organizations.map((org) => (
          <option key={org.id} value={org.id}>{org.name}</option>
        ))}
      </select>
    </div>
  );

  // --- Mobile: app bar, stat strip, grouped project list, bottom tab bar ---
  if (isMobile) {
    const navItems: TabItem[] = [
      { key: "projects", label: "Projects", icon: Icons.projects },
      { key: "account", label: "Account", icon: Icons.account },
    ];
    return (
      <>
        <AppBar
          title="Projects"
          action={
            <button className="link-btn" onClick={() => setShowNew(!showNew)} aria-label="New project">
              {showNew ? "Close" : "New"}
            </button>
          }
        />
        <div className="shell m-has-bottomnav">
          {error && <div className="error-banner" style={{ margin: "12px 12px 0" }}>{error}</div>}

          {overview && (
            <div className="m-statstrip">
              <div className="m-stat">
                <span className={`m-stat-value ${overview.quota && scanUsageCopy(overview.quota).critical ? "stat-critical" : ""}`}>
                  {overview.quota ? scanUsageCopy(overview.quota).headline : "—"}
                </span>
                <span className="m-stat-label">Scans left</span>
              </div>
              <div className="m-stat">
                <span className="m-stat-value stat-critical">{overview.totalCriticalFindings}</span>
                <span className="m-stat-label">Critical</span>
              </div>
              <div className="m-stat">
                <span className="m-stat-value stat-warning">{overview.totalNewAlerts}</span>
                <span className="m-stat-label">Alerts</span>
              </div>
              <div className="m-stat">
                <span className="m-stat-value">{overview.totalProjects}</span>
                <span className="m-stat-label">Projects</span>
              </div>
            </div>
          )}

          {showNew && (
            <>
              <div className="m-section-title">New project</div>
              <div className="card">
                <form onSubmit={handleCreate}>
                  <div className="field">
                    <label htmlFor="m-name">Name</label>
                    <input id="m-name" required value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="My App" />
                  </div>
                  <div className="field">
                    <label htmlFor="m-url">URL (optional)</label>
                    <input id="m-url" value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://myapp.com" />
                  </div>
                  {orgPicker}
                  <div className="field">
                    <label htmlFor="m-env">Environment (optional)</label>
                    <select id="m-env" value={newEnv} onChange={(e) => setNewEnv(e.target.value)}>
                      <option value="">Select…</option>
                      <option value="development">Development</option>
                      <option value="staging">Staging</option>
                      <option value="production">Production</option>
                    </select>
                  </div>
                  <button type="submit" className="m-fullwidth" disabled={creating}>
                    {creating ? "Creating…" : "Create project"}
                  </button>
                </form>
              </div>
            </>
          )}

          <div className="m-section-title">
            {overview ? `${overview.projects.length} project${overview.projects.length === 1 ? "" : "s"}` : "Projects"}
          </div>
          {overview === null && <p className="muted" style={{ margin: "0 26px" }}>Loading…</p>}
          {overview?.projects.length === 0 && (
            <p className="muted" style={{ margin: "0 26px" }}>No projects yet — tap New to add one.</p>
          )}
          {overview && overview.projects.length > 0 && (
            <div className="m-list">
              {overview.projects.map((p) => (
                <Link key={p.id} to={`/projects/${p.id}`} className="m-row">
                  <div className="m-row-main">
                    <span className="m-row-title">{p.name}</span>
                    <span className="m-row-sub">
                      {p.latestScore !== null ? `${p.latestScore}/100` : "Not yet scanned"}
                      {p.newAlerts > 0 && ` · ${p.newAlerts} alert${p.newAlerts > 1 ? "s" : ""}`}
                    </span>
                  </div>
                  <BadgePill state={p.badge} />
                  <span className="m-chevron">{Icons.chevron}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
        <BottomNav
          items={navItems}
          active="projects"
          onSelect={(k) => { if (k === "account") navigate("/settings"); }}
        />
      </>
    );
  }

  return (
    <div className="shell">
      <div className="topbar">
        <span className="brand"><NettleLogo size={22} title="" />nettle</span>
        <div className="topbar-right">
          <Link to="/explore" className="settings-link">Explore</Link>
          <Link to="/organizations" className="settings-link">Organizations</Link>
          <Link to="/subscribe" className="settings-link">Upgrade</Link>
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
          {overview.quota && (() => {
            const usage = scanUsageCopy(overview.quota!);
            return (
              <div className="stat-card">
                <span className={`stat-value ${usage.critical ? "stat-critical" : ""}`}>{usage.headline}</span>
                <span className="stat-label">
                  {overview.quota!.limit === null ? "Scanning" : overview.quota!.limit === 0 ? "Scanning" : "Scans remaining"}
                </span>
                <span className="stat-sublabel">
                  {usage.detail}
                  {overview.quota!.limit !== null && overview.quota!.limit > 0
                    ? ` · resets ${new Date(overview.quota!.periodEnd).toLocaleDateString()}`
                    : ""}
                </span>
              </div>
            );
          })()}
        </div>
      )}

      <div className="card">
        <h2>New project</h2>
        <form onSubmit={handleCreate}>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
            <div className="field" style={{ flex: 1, marginBottom: 0 }}>
              <label htmlFor="name">Name</label>
              <input id="name" required value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="My App" />
            </div>
            <button type="submit" disabled={creating}>
              {creating ? "Creating…" : "Create"}
            </button>
          </div>
          <button
            type="button"
            className="link-btn"
            onClick={() => setShowAdvanced(!showAdvanced)}
            style={{ marginTop: 8 }}
          >
            {showAdvanced ? "Hide details" : "Add details (optional)"}
          </button>
          {showAdvanced && (
            <div style={{ marginTop: 8 }}>
              <div className="field">
                <label htmlFor="proj-url">URL</label>
                <input id="proj-url" value={newUrl} onChange={(e) => setNewUrl(e.target.value)} placeholder="https://myapp.com" />
              </div>
              <div className="field">
                <label htmlFor="proj-desc">Description</label>
                <input id="proj-desc" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} placeholder="Brief description" />
              </div>
              {orgPicker}
              <div className="field">
                <label htmlFor="proj-env">Environment</label>
                <select id="proj-env" value={newEnv} onChange={(e) => setNewEnv(e.target.value)}>
                  <option value="">Select…</option>
                  <option value="development">Development</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </select>
              </div>
            </div>
          )}
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
