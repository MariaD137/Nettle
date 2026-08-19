import { useEffect, useState } from "react";
import { api, ApiError, type Project, type ScanReport } from "../api";
import { useAuth } from "../AuthContext";
import NettleLogo from "../components/NettleLogo";
import ScanProgress from "../components/ScanProgress";
import { useScanJob } from "../useScanJob";
import { scoreLabel, scoreBand } from "../scoreLabel";

type Step = "welcome" | "intro" | "project" | "scan" | "score";
const STEPS: Step[] = ["welcome", "intro", "project", "scan", "score"];
const STEP_LABELS: Record<Step, string> = {
  welcome: "Welcome",
  intro: "How it works",
  project: "First project",
  scan: "First scan",
  score: "Your score",
};

const SESSION_KEY = "nettle_onboarding_progress";
const REPORT_KEY = "nettle_onboarding_report";

interface SavedProgress {
  userId: string;
  step: Step;
  project: Project | null;
}

// Scoped to the signed-in user id so a shared/reused tab (logout, then a
// different account logs in) never resumes with someone else's in-progress
// project or step.
function loadProgress(userId: string): SavedProgress | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SavedProgress;
    return parsed.userId === userId ? parsed : null;
  } catch {
    return null;
  }
}

function saveProgress(userId: string, step: Step, project: Project | null) {
  try {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ userId, step, project }));
  } catch {
    // Best-effort — losing resumability on a refresh is a minor inconvenience,
    // not a reason to break the flow.
  }
}

function clearProgress() {
  try {
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(REPORT_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * First-run flow shown once per account, right after a paid subscription
 * unlocks the dashboard: welcome -> product intro -> create the first
 * project -> run the first scan -> see the first score. Progress is
 * resumed from sessionStorage if the tab is refreshed mid-flow, and the
 * whole thing can be skipped at any point — completion is what unlocks the
 * real dashboard (via the same `onboardingCompletedAt` stamp either way),
 * not finishing every step.
 */
export default function OnboardingPage() {
  const { user, refreshUser } = useAuth();
  const userId = user?.id ?? "";
  const saved = loadProgress(userId);
  const [step, setStep] = useState<Step>(saved?.step ?? "welcome");
  const [project, setProject] = useState<Project | null>(saved?.project ?? null);
  const [finishing, setFinishing] = useState(false);

  useEffect(() => {
    if (userId) saveProgress(userId, step, project);
  }, [userId, step, project]);

  async function finish() {
    setFinishing(true);
    try {
      await api.completeOnboarding();
    } catch {
      // Even if the stamp fails to save, don't trap the user on the wizard —
      // they'll just see it again next visit, which is the safe failure mode.
    } finally {
      clearProgress();
      refreshUser();
    }
  }

  const currentIndex = STEPS.indexOf(step);

  return (
    <div className="onboarding-shell">
      <div className="onboarding-steps" aria-label="Onboarding progress">
        {STEPS.map((s, i) => (
          <div key={s} className="onboarding-step" title={STEP_LABELS[s]}>
            <span
              className={`step-dot ${i === currentIndex ? "active" : ""} ${i < currentIndex ? "done" : ""}`}
            />
          </div>
        ))}
        {step !== "score" && (
          <button type="button" className="link-btn onboarding-skip" onClick={finish} disabled={finishing}>
            Skip setup
          </button>
        )}
      </div>

      {step === "welcome" && <WelcomeStep onNext={() => setStep("intro")} />}
      {step === "intro" && <IntroStep onNext={() => setStep("project")} />}
      {step === "project" && (
        <ProjectStep
          onCreated={(p) => {
            setProject(p);
            setStep("scan");
          }}
        />
      )}
      {step === "scan" && project && (
        <ScanStep
          project={project}
          onScanned={(report) => {
            try {
              sessionStorage.setItem(REPORT_KEY, JSON.stringify(report));
            } catch {
              /* ignore — the score step falls back to a generic message */
            }
            setStep("score");
          }}
          onSkip={finish}
        />
      )}
      {step === "score" && <ScoreStep onFinish={finish} finishing={finishing} />}
    </div>
  );
}

function WelcomeStep({ onNext }: { onNext: () => void }) {
  return (
    <div className="onboarding-panel onboarding-center">
      <NettleLogo size={80} />
      <h1 className="auth-wordmark">Welcome to nettle</h1>
      <p className="muted onboarding-lede">
        Let's get your first project scanned and your first security score on the board —
        it takes about two minutes.
      </p>
      <button type="button" onClick={onNext}>
        Get started
      </button>
    </div>
  );
}

const FEATURES: { title: string; detail: string }[] = [
  { title: "Scan any way you ship", detail: "Upload a .zip, point at a public repo, or (soon) scan a live URL." },
  { title: "Findings you can act on", detail: "Every issue comes with the file, the line, and how to fix it — not just a score." },
  { title: "Keep watching after launch", detail: "Continuous monitoring flags suspicious traffic once you're live." },
  { title: "Prove it", detail: "An embeddable trust badge reflects your real, current score." },
];

function IntroStep({ onNext }: { onNext: () => void }) {
  return (
    <div className="onboarding-panel">
      <h2>What nettle does</h2>
      <div className="intro-features">
        {FEATURES.map((f) => (
          <div key={f.title} className="intro-feature">
            <strong>{f.title}</strong>
            <p className="muted">{f.detail}</p>
          </div>
        ))}
      </div>
      <button type="button" onClick={onNext}>
        Continue
      </button>
    </div>
  );
}

function ProjectStep({ onCreated }: { onCreated: (project: Project) => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setCreating(true);
    try {
      const project = await api.createProject(name, { url: url || undefined });
      onCreated(project);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't create the project");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="onboarding-panel">
      <h2>Create your first project</h2>
      <p className="muted">A project groups a codebase's scans, findings, and alerts together.</p>
      {error && <div className="error-banner">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="ob-name">Project name</label>
          <input
            id="ob-name"
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My App"
          />
        </div>
        <div className="field">
          <label htmlFor="ob-url">URL (optional)</label>
          <input id="ob-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://myapp.com" />
        </div>
        <button type="submit" disabled={creating || !name}>
          {creating ? "Creating…" : "Create project"}
        </button>
      </form>
    </div>
  );
}

type ScanMethod = "upload" | "repo";

function ScanStep({
  project,
  onScanned,
  onSkip,
}: {
  project: Project;
  onScanned: (report: ScanReport) => void;
  onSkip: () => void;
}) {
  const [method, setMethod] = useState<ScanMethod>("upload");
  const [file, setFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState("");
  const { job, scanning, error: jobError, startUpload, startRepo, cancel } = useScanJob();
  const [formError, setFormError] = useState<string | null>(null);
  const error = formError || jobError;

  async function handleScan() {
    setFormError(null);
    const report =
      method === "repo" ? await startRepo(repoUrl, { apiKey: project.apiKey }) : await startUpload(file as File, project.apiKey);
    if (report) onScanned(report);
  }

  return (
    <div className="onboarding-panel">
      <h2>Run your first scan</h2>
      <p className="muted">
        Scan <strong>{project.name}</strong> now to see real findings and your first security score.
      </p>

      <div className="scan-method-tabs">
        <button type="button" className={`scan-method-tab ${method === "upload" ? "active" : ""}`} onClick={() => setMethod("upload")}>
          Upload zip
        </button>
        <button type="button" className={`scan-method-tab ${method === "repo" ? "active" : ""}`} onClick={() => setMethod("repo")}>
          Scan repo
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {method === "upload" ? (
        <div>
          <div className="scan-upload-row">
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} disabled={scanning} />
            <button onClick={handleScan} disabled={!file || scanning}>
              {scanning ? "Scanning…" : "Scan"}
            </button>
            {scanning && (
              <button type="button" className="secondary" onClick={cancel}>
                Cancel
              </button>
            )}
          </div>
          {scanning && <ScanProgress job={job} />}
        </div>
      ) : (
        <div>
          <div className="field">
            <label htmlFor="ob-repo">Repository URL</label>
            <input
              id="ob-repo"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/owner/repo"
            />
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <button onClick={handleScan} disabled={!repoUrl || scanning}>
              {scanning ? "Cloning & scanning…" : "Scan repository"}
            </button>
            {scanning && (
              <button type="button" className="secondary" onClick={cancel}>
                Cancel
              </button>
            )}
          </div>
          {scanning && <ScanProgress job={job} />}
        </div>
      )}

      <button
        type="button"
        className="link-btn"
        style={{ marginTop: 14 }}
        onClick={() => {
          if (scanning) cancel();
          onSkip();
        }}
      >
        I'll scan later — take me to the dashboard
      </button>
    </div>
  );
}

function ScoreStep({ onFinish, finishing }: { onFinish: () => void; finishing: boolean }) {
  const [report, setReport] = useState<ScanReport | null>(null);

  useEffect(() => {
    const raw = sessionStorage.getItem(REPORT_KEY);
    if (raw) {
      try {
        setReport(JSON.parse(raw) as ScanReport);
      } catch {
        setReport(null);
      }
    }
  }, []);

  return (
    <div className="onboarding-panel onboarding-center">
      <h2>Your first security score</h2>
      {report ? (
        <>
          <div className="report-header" style={{ justifyContent: "center" }}>
            <div className="score-block">
              <span className="score-num">{report.score}</span>
              <span className="muted">/ 100</span>
            </div>
            <span className={`score-label score-${scoreBand(report.score)}`}>
              {scoreLabel(report.score)}
            </span>
          </div>
          <div className="score-counts" style={{ justifyContent: "center" }}>
            <span className="count-critical">{report.summary.critical} critical</span>
            <span className="count-high">{report.summary.high} high</span>
            <span className="count-medium">{report.summary.medium} medium</span>
            <span className="count-low">{report.summary.low} low</span>
            <span className="count-clear">{report.summary.clear} clear</span>
          </div>
          <p className="muted onboarding-lede">
            That's your baseline. Every finding comes with exactly what to fix — head to the dashboard to dig in.
          </p>
        </>
      ) : (
        <p className="muted onboarding-lede">You're all set — head to the dashboard whenever you're ready.</p>
      )}
      <button type="button" onClick={onFinish} disabled={finishing}>
        {finishing ? "Finishing…" : "Go to dashboard"}
      </button>
    </div>
  );
}
