import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError, type Alert, type BadgeState, type Project, type ScanReport, type StoredScan } from "../api";
import BadgePill from "../components/BadgePill";

type Tab = "overview" | "scan" | "alerts" | "history" | "billing";

export default function ProjectPage() {
  const { id } = useParams<{ id: string }>();
  const [tab, setTab] = useState<Tab>("overview");
  const [project, setProject] = useState<Project | null>(null);
  const [badge, setBadge] = useState<BadgeState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([api.listProjects(), api.getBadge(id)])
      .then(([{ projects }, badge]) => {
        setProject(projects.find((p) => p.id === id) ?? null);
        setBadge(badge);
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
          </button>
        ))}
      </div>

      {tab === "overview" && <OverviewTab project={project} />}
      {tab === "scan" && <ScanTab project={project} onScanned={(b) => setBadge(b)} />}
      {tab === "alerts" && <AlertsTab projectId={project.id} />}
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

function ReportView({ report }: { report: ScanReport }) {
  const critical = report.findings.filter((f) => f.severity === "critical");
  const caution = report.findings.filter((f) => f.severity === "caution");
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 16 }}>
        <span className="score-num">{report.score}</span>
        <span className="muted">/ 100</span>
        <span className="muted">
          {report.summary.critical} critical · {report.summary.caution} caution · {report.summary.clear} clear
        </span>
      </div>
      {critical.length > 0 && (
        <>
          <h2>Critical</h2>
          {critical.map((f, i) => (
            <FindingRow key={i} finding={f} />
          ))}
        </>
      )}
      {caution.length > 0 && (
        <>
          <h2>Caution</h2>
          {caution.map((f, i) => (
            <FindingRow key={i} finding={f} />
          ))}
        </>
      )}
    </div>
  );
}

function FindingRow({ finding }: { finding: ScanReport["findings"][number] }) {
  return (
    <div className="finding">
      <div className="finding-top">
        <span className="finding-title">{finding.title}</span>
        <span className="finding-cat">{finding.category}</span>
      </div>
      <p className="finding-detail">{finding.detail}</p>
      {finding.file && <p className="finding-detail">{finding.file}</p>}
    </div>
  );
}

function AlertsTab({ projectId }: { projectId: string }) {
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  useEffect(() => {
    api.getAlerts(projectId).then(({ alerts }) => setAlerts(alerts));
  }, [projectId]);

  return (
    <div className="card">
      <h2>Alerts</h2>
      {alerts === null && <p className="muted">Loading…</p>}
      {alerts?.length === 0 && <p className="muted">No alerts yet — good sign.</p>}
      {alerts?.map((a) => (
        <div key={a.id} className="finding">
          <div className="finding-top">
            <span className="finding-title">{a.rule}</span>
            <span className="finding-cat">{new Date(a.occurredAt).toLocaleString()}</span>
          </div>
          <p className="finding-detail">{a.message}</p>
        </div>
      ))}
    </div>
  );
}

function HistoryTab({ projectId }: { projectId: string }) {
  const [scans, setScans] = useState<StoredScan[] | null>(null);
  useEffect(() => {
    api.getScans(projectId).then(({ scans }) => setScans(scans));
  }, [projectId]);

  return (
    <div className="card">
      <h2>Scan history</h2>
      {scans === null && <p className="muted">Loading…</p>}
      {scans?.length === 0 && <p className="muted">No scans yet.</p>}
      {scans?.map((s) => (
        <div key={s.id} className="project-row" style={{ cursor: "default" }}>
          <span>{new Date(s.scannedAt).toLocaleString()}</span>
          <span className="muted">
            {s.score}/100 · {s.criticalCount} critical · {s.cautionCount} caution
          </span>
        </div>
      ))}
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
