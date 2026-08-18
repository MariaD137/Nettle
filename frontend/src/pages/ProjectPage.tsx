import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  api, ApiError,
  type Alert, type AlertCounts, type AlertStatus, type BadgeState,
  type Finding, type FindingStatus, type Project, type ScanComparison,
  type ScanReport, type StoredFindingStatus, type StoredScan,
} from "../api";
import BadgePill from "../components/BadgePill";
import NettleLogo from "../components/NettleLogo";
import { AppBar, BottomNav, Icons, type TabItem } from "../components/MobileChrome";
import { useIsMobile } from "../useIsMobile";

type Tab = "overview" | "scan" | "findings" | "alerts" | "history" | "settings";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const isMobile = useIsMobile();
  const [tab, setTab] = useState<Tab>("overview");
  const [project, setProject] = useState<Project | null>(null);
  const [badge, setBadge] = useState<BadgeState | null>(null);
  const [alertCounts, setAlertCounts] = useState<AlertCounts | null>(null);
  const [latestScan, setLatestScan] = useState<StoredScan | null>(null);
  const [error, setError] = useState<string | null>(null);

  function refresh() {
    if (!id) return;
    api.getProject(id)
      .then((data) => {
        setProject(data.project);
        setBadge(data.badge);
        setAlertCounts(data.alertCounts);
        setLatestScan(data.latestScan);
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load project"));
  }

  useEffect(() => { refresh(); }, [id]);

  if (!id) return null;
  if (error) return <div className="shell error-banner">{error}</div>;
  if (!project || !badge) return <div className="shell muted">Loading…</div>;

  const tabs: Tab[] = ["overview", "scan", "findings", "alerts", "history", "settings"];

  const content = (
    <>
      {tab === "overview" && <OverviewTab project={project} latestScan={latestScan} />}
      {tab === "scan" && <ScanTab project={project} onScanned={(b) => { setBadge(b); refresh(); }} />}
      {tab === "findings" && <FindingsTab projectId={project.id} latestScan={latestScan} />}
      {tab === "alerts" && <AlertsTab projectId={project.id} onUpdate={(c) => setAlertCounts(c)} />}
      {tab === "history" && <HistoryTab projectId={project.id} />}
      {tab === "settings" && (
        <ProjectSettingsTab
          project={project}
          onUpdated={(p) => setProject(p)}
          onDeleted={() => navigate("/")}
        />
      )}
    </>
  );

  if (isMobile) {
    const navItems: TabItem[] = [
      { key: "overview", label: "Overview", icon: Icons.overview },
      { key: "scan", label: "Scan", icon: Icons.scan },
      { key: "findings", label: "Findings", icon: Icons.findings },
      { key: "alerts", label: "Alerts", icon: Icons.alerts, badge: alertCounts?.new },
      { key: "history", label: "History", icon: Icons.history },
      { key: "settings", label: "Settings", icon: Icons.settings },
    ];
    return (
      <>
        <AppBar
          title={project.name}
          subtitle={badge.label}
          onBack={() => navigate("/")}
        />
        <div className="shell m-has-bottomnav">{content}</div>
        <BottomNav items={navItems} active={tab} onSelect={(k) => setTab(k as Tab)} />
      </>
    );
  }

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand"><NettleLogo size={22} title="" />nettle</Link>
        <div style={{ display: "flex", gap: "16px", alignItems: "center", marginLeft: "auto" }}>
          <Link to={`/projects/${id}/custom-rules`} className="settings-link">Rules</Link>
          <Link to={`/projects/${id}/analytics`} className="settings-link">Analytics</Link>
          <BadgePill state={badge} />
        </div>
      </div>

      <h1>{project.name}</h1>
      <p className="muted">
        Created {new Date(project.createdAt).toLocaleDateString()}
        {project.environment && <span className="plan-badge" style={{ marginLeft: 8 }}>{project.environment}</span>}
        {project.archivedAt && <span className="plan-badge" style={{ marginLeft: 8, background: "#888" }}>archived</span>}
      </p>
      {project.description && <p className="muted">{project.description}</p>}

      <div className="tabs">
        {tabs.map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)} type="button">
            {t[0].toUpperCase() + t.slice(1)}
            {t === "alerts" && alertCounts && alertCounts.new > 0 && (
              <span className="tab-badge">{alertCounts.new}</span>
            )}
          </button>
        ))}
      </div>

      {content}
    </div>
  );
}

function OverviewTab({ project, latestScan }: { project: Project; latestScan: StoredScan | null }) {
  const badgeUrl = api.badgeSvgUrl(project.id);
  const [exportError, setExportError] = useState<string | null>(null);

  async function handleExport(scanId: string) {
    setExportError(null);
    try {
      await api.downloadScanReport(project.id, scanId);
    } catch (err) {
      setExportError(err instanceof ApiError ? err.message : "Export failed");
    }
  }

  return (
    <>
      <div className="card">
        <h2>Trust badge</h2>
        <p className="muted">Embed this on your own site — it updates live as scans and alerts come in.</p>
        <img src={badgeUrl} alt="Nettle status badge" style={{ marginBottom: 10 }} />
        <div className="code-snippet">{`<img src="${badgeUrl}" alt="Nettle status" />`}</div>
      </div>

      <div className="card">
        <h2>Continuous monitoring</h2>
        <p className="muted">Drop this into your own Express app to start reporting live traffic:</p>
        <div className="code-snippet">
          {`import { nettleMonitor } from "./nettleMonitor";\napp.use(nettleMonitor({ apiKey: "${project.apiKey}" }));`}
        </div>
      </div>

      <div className="card">
        <h2>API key</h2>
        <p className="muted">Used by the monitoring middleware and to associate scans with this project.</p>
        <div className="code-snippet">{project.apiKey}</div>
      </div>

      {latestScan && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>Latest scan</h2>
            <button className="small secondary" onClick={() => handleExport(latestScan.id)}>
              Download JSON
            </button>
          </div>
          {exportError && <div className="error-banner">{exportError}</div>}
          <p className="muted">
            {new Date(latestScan.scannedAt).toLocaleString()} — Score: {latestScan.score}/100
          </p>
          <div className="score-counts">
            <span className="count-critical">{latestScan.criticalCount} critical</span>
            <span className="count-high">{latestScan.cautionCount} caution</span>
            <span className="count-clear">{latestScan.clearCount} clear</span>
          </div>
        </div>
      )}
    </>
  );
}

type ScanMethod = "upload" | "repo";

function ScanTab({ project, onScanned }: { project: Project; onScanned: (badge: BadgeState) => void }) {
  const [method, setMethod] = useState<ScanMethod>("upload");
  const [file, setFile] = useState<File | null>(null);
  // Pre-filled from the project's stored repository info (Settings tab) so a
  // repeat scan doesn't need the URL and branch re-typed every time.
  const [repoUrl, setRepoUrl] = useState(project.repoUrl ?? "");
  const [branch, setBranch] = useState(project.repoBranch ?? "");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleScan() {
    setError(null);
    setScanning(true);
    try {
      let result: ScanReport;
      if (method === "repo") {
        if (!repoUrl) { setError("Enter a repository URL"); setScanning(false); return; }
        result = await api.scanRepo(repoUrl, { branch: branch || undefined, apiKey: project.apiKey });
      } else {
        if (!file) { setError("Select a file"); setScanning(false); return; }
        result = await api.scanCodebase(file, project.apiKey);
      }
      setReport(result);
      onScanned(await api.getBadge(project.id));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="card">
      <h2>Launch readiness scan</h2>

      <div className="scan-method-tabs">
        <button
          type="button"
          className={`scan-method-tab ${method === "upload" ? "active" : ""}`}
          onClick={() => setMethod("upload")}
        >
          Upload zip
        </button>
        <button
          type="button"
          className={`scan-method-tab ${method === "repo" ? "active" : ""}`}
          onClick={() => setMethod("repo")}
        >
          Scan repo
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {method === "upload" && (
        <div>
          <p className="muted">Upload a .zip of your codebase.</p>
          <div className="scan-upload-row">
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <button onClick={handleScan} disabled={!file || scanning}>
              {scanning ? "Scanning…" : "Scan"}
            </button>
          </div>
        </div>
      )}

      {method === "repo" && (
        <div>
          <p className="muted">Enter a public GitHub, GitLab, or Bitbucket repo URL.</p>
          <div className="field">
            <label htmlFor="repo-url">Repository URL</label>
            <input
              id="repo-url"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
            />
          </div>
          <div className="field">
            <label htmlFor="repo-branch">Branch (optional)</label>
            <input
              id="repo-branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
            />
          </div>
          <button onClick={handleScan} disabled={!repoUrl || scanning}>
            {scanning ? "Cloning & scanning…" : "Scan repository"}
          </button>
        </div>
      )}

      {report && <ReportView report={report} />}
    </div>
  );
}

function scoreLabel(score: number): string {
  if (score >= 90) return "READY";
  if (score >= 75) return "REVIEW";
  if (score >= 50) return "NEEDS WORK";
  return "NOT READY";
}

function ReportView({ report }: { report: ScanReport }) {
  const bySeverity = (sev: string) => report.findings.filter((f) => f.severity === sev);
  const critical = bySeverity("critical");
  const high = bySeverity("high");
  const medium = bySeverity("medium");
  const low = bySeverity("low");

  return (
    <div>
      <div className="report-header">
        <div className="score-block">
          <span className="score-num">{report.score}</span>
          <span className="muted">/ 100</span>
        </div>
        <div className="score-status">
          <span className={`score-label score-${report.score >= 90 ? "ready" : report.score >= 75 ? "review" : report.score >= 50 ? "work" : "bad"}`}>
            {scoreLabel(report.score)}
          </span>
        </div>
        <div className="score-counts">
          <span className="count-critical">{report.summary.critical} critical</span>
          <span className="count-high">{report.summary.high} high</span>
          <span className="count-medium">{report.summary.medium} medium</span>
          <span className="count-low">{report.summary.low} low</span>
          <span className="count-clear">{report.summary.clear} clear</span>
        </div>
      </div>

      {critical.length > 0 && <FindingGroup title="Critical" findings={critical} />}
      {high.length > 0 && <FindingGroup title="High" findings={high} />}
      {medium.length > 0 && <FindingGroup title="Medium" findings={medium} />}
      {low.length > 0 && <FindingGroup title="Low" findings={low} />}

      {report.passed.length > 0 && (
        <>
          <h2 style={{ marginTop: 24 }}>Passed checks</h2>
          {report.passed.map((p, i) => (
            <div key={i} className="passed-check">
              <span className="passed-icon">&#10003;</span>
              <span>{p.title}</span>
              <span className="finding-cat">{p.category}</span>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

function FindingGroup({ title, findings }: { title: string; findings: Finding[] }) {
  return (
    <>
      <h2 style={{ marginTop: 20 }}>{title}</h2>
      {findings.map((f, i) => (
        <FindingRow key={i} finding={f} />
      ))}
    </>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`finding finding-${finding.severity}`} onClick={() => setExpanded(!expanded)} style={{ cursor: "pointer" }}>
      <div className="finding-top">
        <span className="finding-title">{finding.title}</span>
        <span className="finding-cat">{finding.category}</span>
      </div>
      <p className="finding-detail">{finding.detail}</p>
      {finding.file && (
        <p className="finding-file">
          {finding.file}{finding.line ? `:${finding.line}` : ""}
        </p>
      )}
      {expanded && finding.remediation && (
        <div className="remediation">
          <strong>How to fix:</strong> {finding.remediation}
        </div>
      )}
    </div>
  );
}

const FINDING_STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  in_progress: "In progress",
  resolved: "Resolved",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
};

function FindingsTab({ projectId, latestScan }: { projectId: string; latestScan: StoredScan | null }) {
  const [statuses, setStatuses] = useState<StoredFindingStatus[] | null>(null);
  const [filter, setFilter] = useState<FindingStatus | "all">("all");

  useEffect(() => {
    api.listFindingStatuses(projectId).then(({ findingStatuses }) => setStatuses(findingStatuses));
  }, [projectId]);

  const findings = latestScan?.report.findings ?? [];

  async function updateStatus(findingHash: string, status: FindingStatus) {
    const { findingStatus } = await api.updateFindingStatus(projectId, findingHash, status);
    setStatuses((prev) => {
      if (!prev) return [findingStatus];
      const idx = prev.findIndex((s) => s.findingHash === findingHash);
      if (idx >= 0) return [...prev.slice(0, idx), findingStatus, ...prev.slice(idx + 1)];
      return [...prev, findingStatus];
    });
  }

  function getStatus(finding: Finding): FindingStatus {
    if (!statuses) return "open";
    const hash = hashFinding(finding.category, finding.title, finding.file);
    return statuses.find((s) => s.findingHash === hash)?.status ?? "open";
  }

  const filtered = filter === "all"
    ? findings
    : findings.filter((f) => getStatus(f) === filter);

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Findings ({findings.length})</h2>
        <select className="filter-select" value={filter} onChange={(e) => setFilter(e.target.value as FindingStatus | "all")}>
          <option value="all">All</option>
          <option value="open">Open</option>
          <option value="in_progress">In progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
          <option value="accepted_risk">Accepted risk</option>
        </select>
      </div>
      {findings.length === 0 && <p className="muted">No findings from the latest scan.</p>}
      {filtered.map((f, i) => {
        const hash = hashFinding(f.category, f.title, f.file);
        const status = getStatus(f);
        return (
          <div key={i} className={`finding finding-${f.severity}`}>
            <div className="finding-top">
              <span className="finding-title">{f.title}</span>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span className={`status-pill status-${status}`}>{FINDING_STATUS_LABELS[status]}</span>
                <span className="finding-cat">{f.category}</span>
              </div>
            </div>
            <p className="finding-detail">{f.detail}</p>
            {f.file && <p className="finding-file">{f.file}{f.line ? `:${f.line}` : ""}</p>}
            <div className="alert-actions">
              <select
                className="filter-select"
                value={status}
                onChange={(e) => updateStatus(hash, e.target.value as FindingStatus)}
              >
                {Object.entries(FINDING_STATUS_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function hashFinding(category: string, title: string, file: string | null): string {
  const key = `${category}::${title}::${file ?? ""}`;
  let hash = 0;
  for (let i = 0; i < key.length; i++) {
    hash = ((hash << 5) - hash + key.charCodeAt(i)) | 0;
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

const STATUS_LABELS: Record<AlertStatus, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  resolved: "Resolved",
  false_positive: "False positive",
};

function AlertsTab({ projectId, onUpdate }: { projectId: string; onUpdate: (counts: AlertCounts) => void }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [filter, setFilter] = useState<AlertStatus | "all">("all");

  useEffect(() => {
    api.getAlerts(projectId).then(({ alerts }) => setAlerts(alerts));
  }, [projectId]);

  async function changeStatus(alertId: string, status: AlertStatus) {
    const { alert } = await api.updateAlertStatus(projectId, alertId, status);
    setAlerts((prev) => prev?.map((a) => (a.id === alert.id ? alert : a)) ?? null);
    const detail = await api.getProject(projectId);
    onUpdate(detail.alertCounts);
  }

  const filtered = alerts?.filter((a) => filter === "all" || a.status === filter);

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 style={{ margin: 0 }}>Alerts</h2>
        <select className="filter-select" value={filter} onChange={(e) => setFilter(e.target.value as AlertStatus | "all")}>
          <option value="all">All</option>
          <option value="new">New</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
        </select>
      </div>
      {alerts === null && <p className="muted">Loading…</p>}
      {filtered?.length === 0 && <p className="muted">No alerts{filter !== "all" ? ` with status "${filter}"` : ""} — good sign.</p>}
      {filtered?.map((a) => (
        <div key={a.id} className={`finding finding-${a.severity === "critical" ? "critical" : a.severity}`}>
          <div className="finding-top">
            <span className="finding-title">{a.rule}</span>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span className={`status-pill status-${a.status}`}>{STATUS_LABELS[a.status]}</span>
              <span className="finding-cat">{new Date(a.occurredAt).toLocaleString()}</span>
            </div>
          </div>
          <p className="finding-detail">{a.message}</p>
          {a.status !== "resolved" && a.status !== "false_positive" && (
            <div className="alert-actions">
              {a.status === "new" && (
                <button className="small secondary" onClick={() => changeStatus(a.id, "acknowledged")}>
                  Acknowledge
                </button>
              )}
              <button className="small secondary" onClick={() => changeStatus(a.id, "resolved")}>
                Resolve
              </button>
              <button className="small secondary" onClick={() => changeStatus(a.id, "false_positive")}>
                False positive
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function HistoryTab({ projectId }: { projectId: string }) {
  const [scans, setScans] = useState<StoredScan[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [comparing, setComparing] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  async function handleExport(scanId: string) {
    setExportError(null);
    try {
      await api.downloadScanReport(projectId, scanId);
    } catch (err) {
      setExportError(err instanceof ApiError ? err.message : "Export failed");
    }
  }

  useEffect(() => {
    api.getScans(projectId).then(({ scans }) => setScans(scans));
  }, [projectId]);

  async function compare() {
    if (!scans || scans.length < 2) return;
    setComparing(true);
    try {
      const result = await api.compareScans(projectId);
      setComparison(result);
    } catch {
      setComparison(null);
    } finally {
      setComparing(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2 style={{ margin: 0 }}>Scan history</h2>
        {scans && scans.length >= 2 && (
          <button className="small secondary" onClick={compare} disabled={comparing}>
            {comparing ? "Comparing…" : "Compare latest"}
          </button>
        )}
      </div>

      {comparison && (
        <div style={{ margin: "16px 0", padding: 12, borderRadius: 6, background: "var(--surface-alt, #f5f5f5)" }}>
          <strong>Comparison:</strong>{" "}
          <span className={comparison.scoreDelta > 0 ? "score-up" : comparison.scoreDelta < 0 ? "score-down" : ""}>
            {comparison.scoreDelta > 0 ? "+" : ""}{comparison.scoreDelta} points
          </span>
          <div style={{ display: "flex", gap: 16, marginTop: 8 }}>
            <span className="count-clear">{comparison.fixed} fixed</span>
            <span className="count-critical">{comparison.new} new</span>
            <span className="muted">{comparison.remaining} unchanged</span>
          </div>
          {comparison.fixedFindings.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <strong>Fixed:</strong>
              {comparison.fixedFindings.map((f, i) => (
                <div key={i} className="muted">- {f.title}</div>
              ))}
            </div>
          )}
          {comparison.newFindings.length > 0 && (
            <div style={{ marginTop: 8 }}>
              <strong>New issues:</strong>
              {comparison.newFindings.map((f, i) => (
                <div key={i} className="muted">- {f.title} ({f.severity})</div>
              ))}
            </div>
          )}
        </div>
      )}

      {exportError && <div className="error-banner">{exportError}</div>}
      {scans === null && <p className="muted">Loading…</p>}
      {scans?.length === 0 && <p className="muted">No scans yet.</p>}
      {scans?.map((s, i) => {
        const prev = scans[i + 1];
        const diff = prev ? s.score - prev.score : null;
        return (
          <div key={s.id}>
            <div
              className="project-row"
              style={{ cursor: "pointer" }}
              onClick={() => setExpanded(expanded === s.id ? null : s.id)}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span>{new Date(s.scannedAt).toLocaleDateString()}</span>
                <span className="score-num" style={{ fontSize: 20 }}>{s.score}</span>
                {diff !== null && diff !== 0 && (
                  <span className={diff > 0 ? "score-up" : "score-down"}>
                    {diff > 0 ? "+" : ""}{diff}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                <span className="muted">
                  {s.criticalCount} critical · {s.cautionCount} caution
                </span>
                <button
                  className="small secondary"
                  onClick={(e) => { e.stopPropagation(); handleExport(s.id); }}
                >
                  Export
                </button>
              </div>
            </div>
            {expanded === s.id && <ReportView report={s.report} />}
          </div>
        );
      })}
    </div>
  );
}

function ProjectSettingsTab({
  project,
  onUpdated,
  onDeleted,
}: {
  project: Project;
  onUpdated: (p: Project) => void;
  onDeleted: () => void;
}) {
  const [name, setName] = useState(project.name);
  const [url, setUrl] = useState(project.url ?? "");
  const [repoUrl, setRepoUrl] = useState(project.repoUrl ?? "");
  const [repoBranch, setRepoBranch] = useState(project.repoBranch ?? "");
  const [desc, setDesc] = useState(project.description ?? "");
  const [env, setEnv] = useState(project.environment ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setSaving(true);
    try {
      const updated = await api.updateProject(project.id, {
        name: name || undefined,
        url: url || undefined,
        repoUrl: repoUrl || undefined,
        repoBranch: repoBranch || undefined,
        description: desc || undefined,
        environment: env || undefined,
      });
      onUpdated(updated);
      setSuccess(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  async function handleRotateKey() {
    if (!confirm("Rotate the API key? The old key will stop working immediately.")) return;
    try {
      const updated = await api.rotateApiKey(project.id);
      onUpdated(updated);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to rotate key");
    }
  }

  async function handleArchive() {
    try {
      if (project.archivedAt) {
        const restored = await api.restoreProject(project.id);
        onUpdated(restored);
      } else {
        const archived = await api.archiveProject(project.id);
        onUpdated(archived);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Operation failed");
    }
  }

  async function handleDelete() {
    if (!confirm("Delete this project? This will remove all scans, alerts, and finding data permanently.")) return;
    try {
      await api.deleteProject(project.id);
      onDeleted();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to delete project");
    }
  }

  return (
    <>
      <div className="card">
        <h2>Project details</h2>
        {error && <div className="error-banner">{error}</div>}
        {success && <div className="success-banner">Saved</div>}
        <form onSubmit={handleSave}>
          <div className="field">
            <label htmlFor="pname">Name</label>
            <input id="pname" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="purl">URL</label>
            <input id="purl" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://myapp.com" />
          </div>
          <div className="field">
            <label htmlFor="prepourl">Repository URL</label>
            <input
              id="prepourl"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
            />
          </div>
          <div className="field">
            <label htmlFor="prepobranch">Default branch</label>
            <input id="prepobranch" value={repoBranch} onChange={(e) => setRepoBranch(e.target.value)} placeholder="main" />
          </div>
          <div className="field">
            <label htmlFor="pdesc">Description</label>
            <input id="pdesc" value={desc} onChange={(e) => setDesc(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="penv">Environment</label>
            <select id="penv" value={env} onChange={(e) => setEnv(e.target.value)}>
              <option value="">Select…</option>
              <option value="development">Development</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </div>
          <button type="submit" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
        </form>
      </div>

      <div className="card">
        <h2>API key</h2>
        <div className="code-snippet" style={{ marginBottom: 12 }}>{project.apiKey}</div>
        <button className="secondary" onClick={handleRotateKey}>Rotate key</button>
      </div>

      <div className="card">
        <h2>Danger zone</h2>
        <div className="settings-row">
          <div>
            <strong>{project.archivedAt ? "Restore project" : "Archive project"}</strong>
            <p className="muted" style={{ margin: "4px 0 0" }}>
              {project.archivedAt
                ? "Restore this project to active status."
                : "Hide from your dashboard. Scans and data are preserved."}
            </p>
          </div>
          <button className="secondary" onClick={handleArchive}>
            {project.archivedAt ? "Restore" : "Archive"}
          </button>
        </div>
        <div className="settings-row" style={{ marginTop: 12 }}>
          <div>
            <strong>Delete project</strong>
            <p className="muted" style={{ margin: "4px 0 0" }}>Permanently removes this project and all associated data.</p>
          </div>
          <button className="destructive" onClick={handleDelete}>Delete project</button>
        </div>
      </div>
    </>
  );
}
