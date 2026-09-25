import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  api, ApiError,
  type Alert, type AlertCounts, type AlertStatus, type BadgeState,
  type CheckResult, type ComparisonFinding, type DiffStatus, type Finding, type FindingStatus, type Project, type ReleaseImpact, type ScanComparison,
  type ScanReport, type ScanQueuedResponse, type StoredFindingStatus, type StoredScan,
} from "../api";
import BadgePill from "../components/BadgePill";
import NettleLogo from "../components/NettleLogo";
import { AppBar, BottomNav, Icons, type TabItem } from "../components/MobileChrome";
import { useIsMobile } from "../useIsMobile";
import { useAuth } from "../AuthContext";
import { canRunScan, canUseFixCenter, isProtect } from "../subscription";

type Tab = "overview" | "scan" | "fixcenter" | "findings" | "alerts" | "history" | "settings";

const TAB_LABELS: Record<Tab, string> = {
  overview: "Overview",
  scan: "Scan",
  fixcenter: "Fix Center",
  findings: "Findings",
  alerts: "Alerts",
  history: "History",
  settings: "Settings",
};

/** Open (FAIL) checks from the latest scan — what the Fix Center's badge counts. */
function fixCount(latestScan: StoredScan | null): number {
  return latestScan?.report.checkResults?.filter((r) => r.status === "FAIL").length ?? 0;
}

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

  const tabs: Tab[] = ["overview", "scan", "fixcenter", "findings", "alerts", "history", "settings"];

  const content = (
    <>
      {tab === "overview" && <OverviewTab project={project} latestScan={latestScan} />}
      {tab === "scan" && <ScanTab project={project} onScanned={(b) => { setBadge(b); refresh(); }} />}
      {tab === "fixcenter" && <FixCenterTab latestScan={latestScan} projectId={project.id} onRescan={() => setTab("scan")} />}
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
      { key: "fixcenter", label: "Fix Center", icon: Icons.fixcenter, badge: fixCount(latestScan) },
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
        <BadgePill state={badge} />
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
            {TAB_LABELS[t]}
            {t === "alerts" && alertCounts && alertCounts.new > 0 && (
              <span className="tab-badge">{alertCounts.new}</span>
            )}
            {t === "fixcenter" && fixCount(latestScan) > 0 && (
              <span className="tab-badge">{fixCount(latestScan)}</span>
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
        <p className="muted">
          Drop this into your own Express app to start reporting live traffic — substitute your real API key,
          available from the Settings tab (Nettle only ever shows the full key once, right after it's created or
          rotated — it isn't displayed anywhere after that):
        </p>
        <div className="code-snippet">
          {`import { nettleMonitor } from "./nettleMonitor";\napp.use(nettleMonitor({ apiKey: "<YOUR_API_KEY>" }));`}
        </div>
      </div>

      {latestScan && (latestScan.status === "CREATED" || latestScan.status === "SCANNING") && (
        <div className="card">
          <h2>Latest scan</h2>
          <p className="muted">Scan in progress — this project's most recent scan hasn't finished yet. Check back shortly.</p>
        </div>
      )}

      {latestScan && latestScan.status === "FAILED" && (
        <div className="card">
          <h2>Latest scan</h2>
          <p className="error-banner">
            The most recent scan failed to complete ({new Date(latestScan.scannedAt).toLocaleString()}).
            {latestScan.report.error ? ` ${latestScan.report.error}` : ""} Try running it again from the Scan tab.
          </p>
        </div>
      )}

      {latestScan && latestScan.status !== "CREATED" && latestScan.status !== "SCANNING" && latestScan.status !== "FAILED" && (
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

/**
 * Project-tied scans run async now (backend/src/scanner/scanQueue.ts) — the
 * POST just returns a scanId + CREATED status, so the client polls the
 * scan list until it leaves CREATED/SCANNING. 2s between polls, up to 7
 * minutes: the isolated Fargate path itself budgets up to 5 minutes per
 * scan (SCAN_ISOLATED_TIMEOUT_MS in isolatedExecution.ts's taskTimeoutMs())
 * — on top of that, scans for one account are processed one at a time
 * (scanQueue.ts), so this scan may also sit behind another already running.
 * 7 minutes covers the full task budget plus queueing/launch overhead with
 * room to spare; it must stay comfortably above 5 minutes or a scan the
 * backend would have finished gets reported to the customer as failed.
 */
async function pollScan(projectId: string, scanId: string): Promise<StoredScan> {
  const maxAttempts = 210;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const { scans } = await api.getScans(projectId);
    const found = scans.find((s) => s.id === scanId);
    if (found && found.status !== "CREATED" && found.status !== "SCANNING") return found;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error("The scan is taking longer than expected. Check the History tab shortly.");
}

function ScanTab({ project, onScanned }: { project: Project; onScanned: (badge: BadgeState) => void }) {
  const { user } = useAuth();
  const [method, setMethod] = useState<ScanMethod>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanStage, setScanStage] = useState<"idle" | "submitting" | "queued">("idle");
  const [error, setError] = useState<string | null>(null);

  if (!canRunScan(user)) {
    return (
      <div className="card">
        <h2>Launch readiness scan</h2>
        <p className="muted">
          Real scans require an active BUILD or PROTECT subscription. FREE accounts can{" "}
          <Link to="/explore">explore Nettle's control library and sample findings</Link>, but a scan of your own
          project needs an upgrade. <Link to="/subscribe">See plans</Link>.
        </p>
      </div>
    );
  }

  async function handleScan() {
    setError(null);
    setScanning(true);
    setScanStage("submitting");
    try {
      let result: ScanReport | ScanQueuedResponse;
      if (method === "repo") {
        if (!repoUrl) { setError("Enter a repository URL"); setScanning(false); setScanStage("idle"); return; }
        result = await api.scanRepo(repoUrl, { branch: branch || undefined, projectId: project.id });
      } else {
        if (!file) { setError("Select a file"); setScanning(false); setScanStage("idle"); return; }
        result = await api.scanCodebase(file, { projectId: project.id });
      }

      if ("scanId" in result) {
        // The queued path (always taken here — this tab always sends
        // project.id, so the request is always project-tied). Poll until
        // the worker has actually persisted a real result; a FAILED scan
        // surfaces as an error, never as a fabricated report.
        setScanStage("queued");
        const finished = await pollScan(project.id, result.scanId);
        if (finished.status === "FAILED") {
          setError("The scan failed to complete. Check the History tab for details, or try again.");
        } else {
          setReport(finished.report);
        }
      } else {
        // Fallback for the (here, unreachable in practice) synchronous
        // response shape a project-less request would get.
        setReport(result);
      }
      onScanned(await api.getBadge(project.id));
    } catch (err) {
      // Not just ApiError: pollScan's own timeout throws a plain Error with
      // a real, actionable message (e.g. "still running, check History") —
      // collapsing that into a generic "Scan failed" would misreport a scan
      // that's merely still in progress as a hard failure.
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
      setScanStage("idle");
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
      {scanStage === "queued" && (
        <p className="muted">Scan queued and running — this page will update automatically once it finishes.</p>
      )}

      {method === "upload" && (
        <div>
          <p className="muted">Upload a .zip of your codebase.</p>
          <div className="scan-upload-row">
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <button onClick={handleScan} disabled={!file || scanning}>
              {scanStage === "submitting" ? "Submitting…" : scanStage === "queued" ? "Scanning…" : "Scan"}
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
            {scanStage === "submitting" ? "Cloning…" : scanStage === "queued" ? "Scanning…" : "Scan repository"}
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
  if (report.status === "FAILED") {
    return (
      <div>
        <p className="error-banner">
          {report.error ? report.error : "This scan failed to complete, and no error detail was recorded."}
        </p>
      </div>
    );
  }

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

// --- Fix Center ---------------------------------------------------------
//
// Built on checkResults, not the legacy findings[] array: checkResults is
// where a hydrated recommendation (quickFix/developerFix/architectureFix/
// verification/references) lives, for whichever checks the backend has
// migrated onto its control library. A FAIL with a controlKey but no
// recommendation is a check that hasn't been migrated yet — shown plainly
// with its remediation string (or a human-review note if it has neither),
// never hidden or faked.

const RELEASE_IMPACT_LABELS: Record<ReleaseImpact, string> = {
  BLOCK_RELEASE: "Block release",
  REVIEW_BEFORE_RELEASE: "Review before release",
  FIX_RECOMMENDED: "Fix recommended",
  IMPROVEMENT: "Improvement",
  INFORMATIONAL: "Informational",
};

const SEVERITY_GROUPS: { key: string; title: string }[] = [
  { key: "critical", title: "Critical" },
  { key: "high", title: "High" },
  { key: "medium", title: "Medium" },
  { key: "low", title: "Low" },
];

const DIFF_LABELS: Record<DiffStatus, string> = {
  FIXED: "Fixed",
  STILL_OPEN: "Still open",
  NEW: "New",
  REGRESSED: "Regressed",
  CHANGED: "Changed",
  NOT_VERIFIED: "Not verified",
};

function DiffPill({ status }: { status: DiffStatus }) {
  return <span className={`diff-pill diff-${status.toLowerCase().replace(/_/g, "")}`}>{DIFF_LABELS[status]}</span>;
}

function FixCenterTab({ latestScan, projectId, onRescan }: { latestScan: StoredScan | null; projectId: string; onRescan: () => void }) {
  // Best-effort: lets each currently-open finding be badged New/Regressed/
  // Changed relative to the previous scan, and surfaces a "recently verified
  // fixed" section — but the Fix Center is fully usable without it (a first
  // scan, or a comparison the account isn't entitled to, just means no badges).
  const [comparison, setComparison] = useState<ScanComparison | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.getScans(projectId)
      .then(({ scans }) => {
        if (cancelled || scans.length < 2) return;
        return api.compareScans(projectId).then((c) => { if (!cancelled) setComparison(c); });
      })
      .catch(() => { /* no comparison available — Fix Center still works without it */ });
    return () => { cancelled = true; };
  }, [projectId, latestScan?.id]);

  const { user } = useAuth();

  if (latestScan && (latestScan.status === "CREATED" || latestScan.status === "SCANNING")) {
    return (
      <div className="card">
        <h2>Fix Center</h2>
        <p className="muted">The latest scan is still running — its findings will appear here once it completes.</p>
      </div>
    );
  }

  if (latestScan && latestScan.status === "FAILED") {
    return (
      <div className="card">
        <h2>Fix Center</h2>
        <p className="error-banner">The latest scan failed to complete, so there's nothing to show yet. Try scanning again.</p>
      </div>
    );
  }

  if (!latestScan) {
    return (
      <div className="card">
        <h2>Fix Center</h2>
        {canUseFixCenter(user) ? (
          <p className="muted">Run a scan to see prioritized, actionable recommendations here.</p>
        ) : (
          <p className="muted">
            The Fix Center shows full findings with file-level evidence and remediation once a real scan has run.
            Upgrade to BUILD or PROTECT to scan this project, or{" "}
            <Link to="/explore">see a sample Fix Center report</Link> first. <Link to="/subscribe">See plans</Link>.
          </p>
        )}
      </div>
    );
  }

  const results = latestScan.report.checkResults ?? [];
  const fails = results.filter((r) => r.status === "FAIL");
  const notVerified = results.filter((r) => r.status === "NOT_VERIFIED");

  const diffByCheckId = new Map<string, DiffStatus>();
  if (comparison) {
    for (const item of [...comparison.new, ...comparison.regressed, ...comparison.changed]) {
      if (item.current) diffByCheckId.set(item.current.checkId, item.status);
    }
  }

  const groups = SEVERITY_GROUPS.map((g) => ({
    ...g,
    items: fails.filter((f) => (f.severity ?? "info") === g.key),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
        <h2 style={{ margin: 0 }}>Fix Center</h2>
        <button className="small secondary" onClick={onRescan}>Rescan</button>
      </div>
      <p className="muted" style={{ marginBottom: 16 }}>
        {fails.length === 0
          ? "No open issues from the latest scan — nice work."
          : `${fails.length} issue${fails.length === 1 ? "" : "s"} to fix, prioritized by severity.`}
      </p>

      {groups.map((g) => (
        <div key={g.key}>
          <h2 style={{ marginTop: 20 }}>{g.title} ({g.items.length})</h2>
          {g.items.map((item) => (
            <FixItem key={item.checkId} item={item} diffStatus={diffByCheckId.get(item.checkId)} />
          ))}
        </div>
      ))}

      {notVerified.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h2>What Nettle couldn't verify ({notVerified.length})</h2>
          <p className="muted">
            Not a pass — Nettle didn't have enough evidence in this scan to determine these one way or the other.
          </p>
          {notVerified.map((r) => (
            <div key={r.checkId} className="finding finding-info">
              <div className="finding-top">
                <span className="finding-title">{r.title}</span>
                <span className="finding-cat">{r.category}</span>
              </div>
              {r.detail && <p className="finding-detail">{r.detail}</p>}
              {r.file && <p className="finding-file">{r.file}{r.line ? `:${r.line}` : ""}</p>}
            </div>
          ))}
        </div>
      )}

      {comparison && comparison.fixed.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h2>Recently verified fixed ({comparison.fixed.length})</h2>
          <p className="muted">
            Nettle rescanned and confirmed these findings from the previous scan are no longer detected — the
            recommendation that was used to fix each one is kept below for reference.
          </p>
          {comparison.fixed.map((item) => (
            <FixItem key={item.fingerprint} item={item.finding} diffStatus="FIXED" />
          ))}
        </div>
      )}
    </div>
  );
}

function FixItem({ item, diffStatus }: { item: CheckResult; diffStatus?: DiffStatus }) {
  const [expanded, setExpanded] = useState(false);
  const rec = item.recommendation;

  return (
    <div className={`finding finding-${item.severity ?? "info"}`} style={{ cursor: "pointer" }} onClick={() => setExpanded(!expanded)}>
      <div className="finding-top">
        <span className="finding-title">{item.title}</span>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          {diffStatus && <DiffPill status={diffStatus} />}
          {item.releaseImpact && (
            <span className={`impact-pill impact-${item.releaseImpact.toLowerCase().replace(/_/g, "-")}`}>
              {RELEASE_IMPACT_LABELS[item.releaseImpact]}
            </span>
          )}
          <span className="finding-cat">{item.category}</span>
        </div>
      </div>
      {item.detail && <p className="finding-detail">{item.detail}</p>}
      {item.file && <p className="finding-file">{item.file}{item.line ? `:${item.line}` : ""}</p>}

      {expanded && (
        <div className="fix-detail" onClick={(e) => e.stopPropagation()}>
          {rec ? (
            <>
              <FixSection label="Why it matters" text={rec.whyItMatters} />
              <FixSection label="Quick fix" text={rec.quickFix} />
              <FixSection label="Developer fix" text={rec.developerFix} />
              {rec.architectureFix && <FixSection label="Architecture fix" text={rec.architectureFix} />}
              {rec.longTermHardening && <FixSection label="Long-term hardening" text={rec.longTermHardening} />}
              <FixSection label="Verification" text={rec.verificationMethod} />
              {rec.recommendationConfidence === "LOW" && (
                <p className="muted" style={{ marginTop: 8 }}>
                  Nettle couldn't determine this project's exact framework, so the fix above is general guidance —
                  a more specific fix likely exists for your stack once it's detected.
                </p>
              )}
              {rec.recommendationConfidence === "HIGH" && rec.multipleValidSolutions && (
                <p className="muted" style={{ marginTop: 8 }}>
                  There are multiple valid implementations — Nettle recommends the option above based on the
                  detected {rec.technologyMatched} stack.
                </p>
              )}
              {rec.references.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <strong style={{ fontSize: 12.5 }}>References</strong>
                  <ul className="fix-refs">
                    {rec.references.map((ref, i) => <li key={i}>{ref}</li>)}
                  </ul>
                </div>
              )}
            </>
          ) : item.remediation ? (
            <div className="remediation"><strong>How to fix:</strong> {item.remediation}</div>
          ) : (
            <p className="muted">
              Nettle hasn't published detailed remediation guidance for this check yet — human/developer review recommended.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function FixSection({ label, text }: { label: string; text: string }) {
  return (
    <div className="fix-section">
      <strong>{label}:</strong> <span>{text}</span>
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
  const { user } = useAuth();
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [filter, setFilter] = useState<AlertStatus | "all">("all");
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    api.getAlerts(projectId)
      .then(({ alerts }) => setAlerts(alerts))
      .catch((err) => setLoadError(err instanceof ApiError ? err.message : "Couldn't load alerts"));
  }, [projectId]);

  if (!isProtect(user)) {
    return (
      <div className="card">
        <h2>Alerts</h2>
        <p className="muted">
          Live risk alerts from continuous monitoring are a PROTECT feature. Upgrade to PROTECT to see real-time
          alerts here. <Link to="/subscribe">See plans</Link>.
        </p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="card">
        <h2>Alerts</h2>
        <p className="error-banner">{loadError}</p>
      </div>
    );
  }

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

/**
 * One finding's row inside a comparison bucket. REGRESSED gets its own
 * explanatory callout — a returning finding is one of Nettle's core
 * continuous-value signals, not just another list item — and CHANGED/
 * NOT_VERIFIED show the engine's stated reason rather than a bare label.
 */
function ComparisonFindingRow({ item }: { item: ComparisonFinding }) {
  return (
    <div style={{ padding: "8px 0", borderBottom: "1px solid var(--line)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: 13 }}>{item.finding.title}</span>
        <DiffPill status={item.status} />
      </div>
      {item.finding.file && (
        <p className="muted" style={{ fontSize: 12, margin: "2px 0 0" }}>
          {item.finding.file}{item.finding.line ? `:${item.finding.line}` : ""}
        </p>
      )}
      {item.status === "REGRESSED" && (
        <div className="regression-callout">
          <strong>Regression detected.</strong> This finding was verified fixed in an earlier scan and has returned.
          {item.finding.recommendation && <> {item.finding.recommendation.quickFix}</>}
        </div>
      )}
      {(item.status === "CHANGED" || item.status === "NOT_VERIFIED") && item.reason && (
        <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>{item.reason}</p>
      )}
      {item.status === "FIXED" && item.finding.recommendation && (
        <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>
          Verified fixed — no longer detected as of the current scan.
        </p>
      )}
    </div>
  );
}

const COMPARISON_SECTIONS: { key: keyof Pick<ScanComparison, "regressed" | "new" | "changed" | "stillOpen" | "fixed" | "notVerified">; title: string }[] = [
  { key: "regressed", title: "Regressed" },
  { key: "new", title: "New" },
  { key: "changed", title: "Changed" },
  { key: "stillOpen", title: "Still open" },
  { key: "fixed", title: "Fixed" },
  { key: "notVerified", title: "Not verified" },
];

function ComparisonPanel({ comparison }: { comparison: ScanComparison }) {
  return (
    <div className="comparison-panel">
      <strong>Comparison:</strong>{" "}
      {new Date(comparison.baselineScannedAt).toLocaleDateString()} → {new Date(comparison.currentScannedAt).toLocaleDateString()}{" "}
      <span className={comparison.scoreDelta > 0 ? "score-up" : comparison.scoreDelta < 0 ? "score-down" : "muted"}>
        {comparison.scoreDelta > 0 ? "+" : ""}{comparison.scoreDelta} points
      </span>
      <p className="muted" style={{ margin: "4px 0 0", fontSize: 12 }}>
        A higher score doesn't by itself prove a fix — the findings below are the authoritative record.
      </p>

      <div className="comparison-summary">
        <span className="count-clear">{comparison.summary.fixed} fixed</span>
        <span className="count-critical">{comparison.summary.new} new</span>
        <span className="count-critical">{comparison.summary.regressed} regressed</span>
        <span className="count-medium">{comparison.summary.changed} changed</span>
        <span className="muted">{comparison.summary.stillOpen} still open</span>
        <span className="muted">{comparison.summary.notVerified} not verified</span>
      </div>

      {comparison.versionNote && <div className="version-note">{comparison.versionNote}</div>}

      {COMPARISON_SECTIONS.map(({ key, title }) => {
        const items = comparison[key] as ComparisonFinding[];
        if (items.length === 0) return null;
        return (
          <div key={key} className="comparison-section">
            <h3>{title} ({items.length})</h3>
            {items.map((item) => <ComparisonFindingRow key={item.fingerprint} item={item} />)}
          </div>
        );
      })}
    </div>
  );
}

function HistoryTab({ projectId }: { projectId: string }) {
  const [scans, setScans] = useState<StoredScan[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [comparing, setComparing] = useState(false);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [baselineId, setBaselineId] = useState<string | null>(null);
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
    setComparisonError(null);
    try {
      // Baseline defaults (from left unset) to the previous scan, matching
      // the backend's own default — picking "Use as baseline" below compares
      // against a specific earlier scan instead.
      const result = await api.compareScans(projectId, baselineId ?? undefined);
      setComparison(result);
    } catch (err) {
      setComparison(null);
      setComparisonError(err instanceof ApiError ? err.message : "Comparison failed");
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
            {comparing ? "Comparing…" : "Compare with latest"}
          </button>
        )}
      </div>
      {scans && scans.length >= 2 && (
        <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
          {baselineId
            ? `Baseline set to ${new Date(scans.find((s) => s.id === baselineId)?.scannedAt ?? "").toLocaleDateString()}. Pick "Use as baseline" on another scan to change it.`
            : 'Compares against the scan immediately before the latest by default — pick "Use as baseline" on any scan below to compare against a specific one, e.g. to verify a fix that took several rescans.'}
        </p>
      )}

      {comparisonError && <div className="error-banner">{comparisonError}</div>}
      {comparison && <ComparisonPanel comparison={comparison} />}

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
                {s.status === "CREATED" || s.status === "SCANNING" ? (
                  <span className="muted">Running…</span>
                ) : s.status === "FAILED" ? (
                  <span className="finding-critical" style={{ padding: "2px 8px", borderRadius: 4 }}>Failed</span>
                ) : (
                  <span className="score-num" style={{ fontSize: 20 }}>{s.score}</span>
                )}
                {diff !== null && diff !== 0 && (
                  <span className={diff > 0 ? "score-up" : "score-down"}>
                    {diff > 0 ? "+" : ""}{diff}
                  </span>
                )}
                {baselineId === s.id && <span className="baseline-marker">Baseline</span>}
              </div>
              <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                {(s.status === "CREATED" || s.status === "SCANNING" || s.status === "FAILED") ? null : (
                  <span className="muted">
                    {s.criticalCount} critical · {s.cautionCount} caution
                  </span>
                )}
                {scans.length >= 2 && (
                  <button
                    className="small secondary"
                    onClick={(e) => { e.stopPropagation(); setBaselineId(s.id); }}
                  >
                    Use as baseline
                  </button>
                )}
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
  const [desc, setDesc] = useState(project.description ?? "");
  const [env, setEnv] = useState(project.environment ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  // POST /rotate-key is the only route (besides creation) that returns the
  // real key — every other read returns it masked. Shown here once so the
  // user doesn't have to guess where to find it after rotating.
  const [rotatedKey, setRotatedKey] = useState<string | null>(null);
  const [keyCopied, setKeyCopied] = useState(false);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setSaving(true);
    try {
      const updated = await api.updateProject(project.id, {
        name: name || undefined,
        url: url || undefined,
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
      setKeyCopied(false);
      setRotatedKey(updated.apiKey);
      onUpdated(updated);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to rotate key");
    }
  }

  async function copyRotatedKey() {
    if (!rotatedKey) return;
    try {
      await navigator.clipboard.writeText(rotatedKey);
      setKeyCopied(true);
    } catch {
      // Clipboard access can be denied — the key is still selectable text below.
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
        <p className="muted" style={{ marginBottom: 12 }}>
          For your security, Nettle doesn't display your API key. If you don't have it saved, rotate it below to get
          a new one — you'll see the full value once, right after rotating.
        </p>
        <button className="secondary" onClick={handleRotateKey}>Rotate key</button>
        {rotatedKey && (
          <div style={{ marginTop: 12 }}>
            <p className="muted">
              New key — copy it now. For your security, Nettle won't show the full key again after you leave this page.
            </p>
            <div className="code-snippet" style={{ marginBottom: 8 }}>{rotatedKey}</div>
            <button type="button" onClick={copyRotatedKey}>{keyCopied ? "Copied!" : "Copy key"}</button>
          </div>
        )}
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
