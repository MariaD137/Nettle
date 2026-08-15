import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError, type Alert, type AlertCounts, type AlertStatus, type BadgeState, type Project, type ScanReport, type StoredScan } from "../api";
import BadgePill from "../components/BadgePill";

type Tab = "overview" | "scan" | "alerts" | "history" | "billing";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("overview");
  const [project, setProject] = useState<Project | null>(null);
  const [badge, setBadge] = useState<BadgeState | null>(null);
  const [alertCounts, setAlertCounts] = useState<AlertCounts | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.getProject(id)
      .then((data) => {
        setProject(data.project);
        setBadge(data.badge);
        setAlertCounts(data.alertCounts);
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : "Couldn't load project"));
  }, [id]);

  if (!id) return null;
  if (error) return <div className="shell error-banner">{error}</div>;
  if (!project || !badge) return <div className="shell muted">Loading…</div>;

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand">
          nettle
        </Link>
        <BadgePill state={badge} />
      </div>

      <h1>{project.name}</h1>
      <p className="muted">Created {new Date(project.createdAt).toLocaleDateString()}</p>

      <div className="tabs">
        {(["overview", "scan", "alerts", "history", "billing"] as const).map((t) => (
          <button key={t} className={`tab ${tab === t ? "active" : ""}`} onClick={() => setTab(t)} type="button">
            {t[0].toUpperCase() + t.slice(1)}
            {t === "alerts" && alertCounts && alertCounts.new > 0 && (
              <span className="tab-badge">{alertCounts.new}</span>
            )}
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab project={project} />}
      {tab === "scan" && <ScanTab project={project} onScanned={(b) => setBadge(b)} />}
      {tab === "alerts" && <AlertsTab projectId={project.id} onUpdate={(c) => setAlertCounts(c)} />}
      {tab === "history" && <HistoryTab projectId={project.id} />}
      {tab === "billing" && <BillingTab />}
    </div>
  );
}

function OverviewTab({ project }: { project: Project }) {
  const badgeUrl = api.badgeSvgUrl(project.id);
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
    </>
  );
}

function ScanTab({ project, onScanned }: { project: Project; onScanned: (badge: BadgeState) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleScan() {
    if (!file) return;
    setError(null);
    setScanning(true);
    try {
      const report = await api.scanCodebase(file, project.apiKey);
      setReport(report);
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
      <p className="muted">Upload a .zip of your codebase.</p>
      {error && <div className="error-banner">{error}</div>}
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        <button onClick={handleScan} disabled={!file || scanning}>
          {scanning ? "Scanning…" : "Scan"}
        </button>
      </div>

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

function FindingGroup({ title, findings }: { title: string; findings: ScanReport["findings"] }) {
  return (
    <>
      <h2 style={{ marginTop: 20 }}>{title}</h2>
      {findings.map((f, i) => (
        <FindingRow key={i} finding={f} />
      ))}
    </>
  );
}

function FindingRow({ finding }: { finding: ScanReport["findings"][number] }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className={`finding finding-${finding.severity}`} onClick={() => setExpanded(!expanded)} style={{ cursor: "pointer" }}>
      <div className="finding-top">
        <span className="finding-title">{finding.title}</span>
        <span className="finding-cat">{finding.category}</span>
      </div>
      <p className="finding-detail">{finding.detail}</p>
      {finding.file && <p className="finding-file">{finding.file}</p>}
      {expanded && finding.remediation && (
        <div className="remediation">
          <strong>How to fix:</strong> {finding.remediation}
        </div>
      )}
    </div>
  );
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
  useEffect(() => {
    api.getScans(projectId).then(({ scans }) => setScans(scans));
  }, [projectId]);

  return (
    <div className="card">
      <h2>Scan history</h2>
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
              <span className="muted">
                {s.criticalCount} critical · {s.cautionCount} caution
              </span>
            </div>
            {expanded === s.id && <ReportView report={s.report} />}
          </div>
        );
      })}
    </div>
  );
}

function BillingTab() {
  const [loading, setLoading] = useState<"tier1" | "tier2" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function upgrade(plan: "tier1" | "tier2") {
    setError(null);
    setLoading(plan);
    try {
      const { url } = await api.createCheckoutSession(plan);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Billing isn't available right now");
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="card">
      <h2>Plans</h2>
      {error && <div className="error-banner">{error}</div>}
      <div style={{ display: "flex", gap: 16 }}>
        <div className="card" style={{ flex: 1, marginBottom: 0 }}>
          <h2>Launch Readiness</h2>
          <p className="muted">Scan your codebase for security, legal, and compliance gaps before you ship.</p>
          <button onClick={() => upgrade("tier1")} disabled={loading !== null}>
            {loading === "tier1" ? "Redirecting…" : "Upgrade"}
          </button>
        </div>
        <div className="card" style={{ flex: 1, marginBottom: 0 }}>
          <h2>Ongoing Protection</h2>
          <p className="muted">Continuous monitoring for hacking attempts after you launch.</p>
          <button onClick={() => upgrade("tier2")} disabled={loading !== null}>
            {loading === "tier2" ? "Redirecting…" : "Upgrade"}
          </button>
        </div>
      </div>
    </div>
  );
}
