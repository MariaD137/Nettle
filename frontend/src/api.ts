const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

/**
 * Every call site below still writes a literal "/api/..." path — this
 * rewrites it to the versioned "/api/v1/..." surface at the one place
 * requests actually go out, so none of them needed touching individually.
 * The backend keeps serving the unversioned path unchanged indefinitely
 * (see backend's middleware/apiVersion.ts), so this is a one-way upgrade,
 * not something either side depends on for correctness.
 *
 * Deliberately NOT applied to badgeSvgUrl below: a badge URL gets pasted
 * into a customer's own README as a long-lived embed, and must never
 * change once published.
 */
function apiPath(path: string): string {
  return path.startsWith("/api/") ? `/api/v1/${path.slice("/api/".length)}` : path;
}

export interface User {
  id: string;
  email: string;
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  createdAt: string;
}

export interface Project {
  id: string;
  userId: string;
  name: string;
  apiKey: string;
  url: string | null;
  description: string | null;
  environment: string | null;
  archivedAt: string | null;
  createdAt: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  file: string | null;
  line: number | null;
  remediation: string | null;
}

export interface ScanAccess {
  tier: "preview" | "full";
  fullReport: boolean;
  totalFindings: number;
  visibleFindings: number;
  lockedFindings: number;
  message: string | null;
}

export type CheckStatus = "PASS" | "FAIL" | "NOT_VERIFIED";

export type ReleaseImpact = "BLOCK_RELEASE" | "REVIEW_BEFORE_RELEASE" | "FIX_RECOMMENDED" | "IMPROVEMENT" | "INFORMATIONAL";

export type RecommendationConfidence = "HIGH" | "MEDIUM" | "LOW";

export interface Recommendation {
  whyItMatters: string;
  recommendedSolution: string;
  quickFix: string;
  developerFix: string;
  architectureFix: string | null;
  longTermHardening: string | null;
  verificationMethod: string;
  references: string[];
  technologyMatched: string;
  multipleValidSolutions: boolean;
  recommendationConfidence: RecommendationConfidence;
}

/**
 * The unified, three-state check result the control library produces.
 * `recommendation`/`releaseImpact` are only present on a FAIL whose
 * controlKey matches a control the backend has migrated onto the control
 * library — see scanner/controls/ on the backend. A FAIL with a controlKey
 * but recommendation: null is a check that hasn't been migrated yet, not a
 * missing feature to hide: the Fix Center shows it plainly rather than
 * pretending every finding has full guidance.
 */
export interface CheckResult {
  checkId: string;
  status: CheckStatus;
  category: string;
  title: string;
  detail?: string;
  severity?: Severity;
  file?: string | null;
  line?: number | null;
  remediation?: string | null;
  confidence?: number;
  controlKey?: string;
  recommendation?: Recommendation | null;
  releaseImpact?: ReleaseImpact | null;
  humanReviewRequired?: boolean;
}

export interface ScanReport {
  scannedAt: string;
  target: string;
  score: number;
  scoreConfidence?: number;
  scannerVersion: string;
  detectedTechnology?: string | null;
  access?: ScanAccess;
  findings: Finding[];
  passed: { category: string; title: string }[];
  checkResults?: CheckResult[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; clear: number };
}

export interface StoredScan {
  id: string;
  projectId: string;
  scannedAt: string;
  score: number;
  criticalCount: number;
  cautionCount: number;
  clearCount: number;
  report: ScanReport;
}

export type AlertStatus = "new" | "acknowledged" | "resolved" | "false_positive";

export interface Alert {
  id: string;
  projectId: string;
  occurredAt: string;
  severity: "critical" | "high" | "medium" | "low";
  rule: string;
  message: string;
  status: AlertStatus;
}

export interface BadgeState {
  status: "protected" | "caution" | "critical" | "unknown";
  label: string;
  lastScannedAt: string | null;
  score: number | null;
}

export interface AlertCounts {
  new: number;
  acknowledged: number;
  resolved: number;
  false_positive: number;
}

export interface ProjectDetail {
  project: Project;
  badge: BadgeState;
  latestScan: StoredScan | null;
  alertCounts: AlertCounts;
}

export interface QuotaState {
  /** null = unlimited/fair-use (PROTECT). 0 = no scan access at all (FREE), not "a quota of zero to exhaust". */
  limit: number | null;
  used: number;
  /** null when limit is unlimited — there is no "remaining count" to show. */
  remaining: number | null;
  periodStart: string;
  periodEnd: string;
  exhausted: boolean;
}

export interface OverviewData {
  quota: QuotaState | null;
  totalProjects: number;
  totalCriticalFindings: number;
  totalHighFindings: number;
  totalNewAlerts: number;
  latestScore: number | null;
  latestScanAt: string | null;
  projects: {
    id: string;
    name: string;
    badge: BadgeState;
    latestScore: number | null;
    lastScannedAt: string | null;
    newAlerts: number;
  }[];
}

export type FindingStatus = "open" | "in_progress" | "resolved" | "false_positive" | "accepted_risk";

export interface StoredFindingStatus {
  id: string;
  projectId: string;
  findingHash: string;
  status: FindingStatus;
  notes: string | null;
  updatedAt: string;
}

export interface SessionInfo {
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export type DiffStatus = "FIXED" | "STILL_OPEN" | "NEW" | "REGRESSED" | "CHANGED" | "NOT_VERIFIED";

/**
 * One finding's classification between two scans. `finding` is whichever of
 * baseline/current is most relevant to show (current when present, else
 * baseline) and is hydrated the same way a live Fix Center item is — a
 * FIXED or REGRESSED entry keeps its original recommendation, not just
 * currently-failing ones (see backend routes/projects.routes.ts).
 */
export interface ComparisonFinding {
  fingerprint: string;
  status: DiffStatus;
  finding: CheckResult;
  baseline?: CheckResult;
  current?: CheckResult;
  /** Populated for NOT_VERIFIED (why comparison was unsafe) and CHANGED (what changed). */
  reason?: string;
}

export interface ScanComparison {
  baselineScanId: string;
  currentScanId: string;
  baselineScannedAt: string;
  currentScannedAt: string;
  baselineScore: number;
  currentScore: number;
  scoreDelta: number;
  versionNote: string | null;
  summary: {
    fixed: number;
    stillOpen: number;
    new: number;
    regressed: number;
    changed: number;
    notVerified: number;
  };
  fixed: ComparisonFinding[];
  stillOpen: ComparisonFinding[];
  new: ComparisonFinding[];
  regressed: ComparisonFinding[];
  changed: ComparisonFinding[];
  notVerified: ComparisonFinding[];
}

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
  }
}

function getToken(): string | null {
  return localStorage.getItem("nettle_token");
}

export function setToken(token: string | null) {
  if (token) localStorage.setItem("nettle_token", token);
  else localStorage.removeItem("nettle_token");
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = { ...(options.headers as Record<string, string>) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API_BASE}${apiPath(path)}`, { ...options, headers });
  if (res.status === 204) return undefined as T;
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;

  if (!res.ok) {
    // The API is the real paywall; this keeps a client that's holding stale
    // user data (subscription cancelled in another tab, webhook landed after
    // load) from sitting on a dashboard it can no longer fetch.
    if (res.status === 402 && body?.subscriptionRequired && window.location.pathname !== "/subscribe") {
      window.location.assign("/subscribe");
    }
    throw new ApiError(res.status, body?.error ?? `Request failed with status ${res.status}`);
  }
  return body as T;
}

export const api = {
  // Auth
  signup: (email: string, password: string) =>
    request<{ token: string; user: User }>("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  login: (email: string, password: string) =>
    request<{ token: string; user: User }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  logout: () => request<void>("/api/auth/logout", { method: "POST" }),

  me: () => request<{ user: User }>("/api/auth/me"),

  forgotPassword: (email: string) =>
    request<{ message: string }>("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  resetPassword: (token: string, password: string) =>
    request<{ message: string }>("/api/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    }),

  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ message: string }>("/api/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    }),

  changeEmail: (email: string, password: string) =>
    request<{ user: User }>("/api/auth/email", {
      method: "PATCH",
      body: JSON.stringify({ email, password }),
    }),

  listSessions: () =>
    request<{ sessions: SessionInfo[] }>("/api/auth/sessions"),

  revokeSession: (tokenPrefix: string) =>
    request<void>(`/api/auth/sessions/${tokenPrefix}`, { method: "DELETE" }),

  revokeAllSessions: () =>
    request<{ token: string; message: string }>("/api/auth/sessions/revoke-all", { method: "POST" }),

  deleteAccount: (password: string) =>
    request<void>("/api/auth/account", {
      method: "DELETE",
      body: JSON.stringify({ password }),
    }),

  // Dashboard
  overview: () => request<OverviewData>("/api/overview"),

  // Projects
  listProjects: (includeArchived = false) =>
    request<{ projects: Project[] }>(`/api/projects${includeArchived ? "?includeArchived=true" : ""}`),

  createProject: (name: string, opts?: { url?: string; description?: string; environment?: string }) =>
    request<Project>("/api/projects", { method: "POST", body: JSON.stringify({ name, ...opts }) }),

  getProject: (id: string) => request<ProjectDetail>(`/api/projects/${id}`),

  updateProject: (id: string, updates: { name?: string; url?: string; description?: string; environment?: string }) =>
    request<Project>(`/api/projects/${id}`, { method: "PATCH", body: JSON.stringify(updates) }),

  deleteProject: (id: string) =>
    request<void>(`/api/projects/${id}`, { method: "DELETE" }),

  archiveProject: (id: string) =>
    request<Project>(`/api/projects/${id}/archive`, { method: "POST" }),

  restoreProject: (id: string) =>
    request<Project>(`/api/projects/${id}/restore`, { method: "POST" }),

  rotateApiKey: (id: string) =>
    request<Project>(`/api/projects/${id}/rotate-key`, { method: "POST" }),

  // Alerts
  getAlerts: (projectId: string) =>
    request<{ project: { id: string; name: string }; alerts: Alert[] }>(`/api/projects/${projectId}/alerts`),

  updateAlertStatus: (projectId: string, alertId: string, status: AlertStatus) =>
    request<{ alert: Alert }>(`/api/projects/${projectId}/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  // Scans
  getScans: (projectId: string) =>
    request<{ project: { id: string; name: string }; scans: StoredScan[] }>(`/api/projects/${projectId}/scans`),

  compareScans: (projectId: string, from?: string, to?: string) => {
    const params = new URLSearchParams();
    if (from) params.set("from", from);
    if (to) params.set("to", to);
    const qs = params.toString();
    return request<ScanComparison>(`/api/projects/${projectId}/scans/compare${qs ? `?${qs}` : ""}`);
  },

  // Fetched rather than linked: the export route is bearer-authenticated, and
  // a plain <a href> can't carry the Authorization header. Downloading through
  // fetch also lets a 402 surface as a real upgrade prompt instead of dumping
  // a JSON error into a new tab.
  downloadScanReport: async (projectId: string, scanId: string): Promise<void> => {
    const token = getToken();
    const res = await fetch(`${API_BASE}${apiPath(`/api/projects/${projectId}/scans/${scanId}/export`)}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new ApiError(res.status, body?.error ?? `Export failed with status ${res.status}`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nettle-report-${scanId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  // Findings
  listFindingStatuses: (projectId: string) =>
    request<{ findingStatuses: StoredFindingStatus[] }>(`/api/projects/${projectId}/findings`),

  updateFindingStatus: (projectId: string, findingHash: string, status: FindingStatus, notes?: string) =>
    request<{ findingStatus: StoredFindingStatus }>(`/api/projects/${projectId}/findings/${findingHash}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes }),
    }),

  // Badge
  getBadge: (projectId: string) => request<BadgeState>(`/api/projects/${projectId}/badge.json`),

  badgeSvgUrl: (projectId: string) => `${API_BASE}/api/projects/${projectId}/badge.svg`,

  // Scan upload
  scanCodebase: async (file: File, apiKey?: string): Promise<ScanReport> => {
    const form = new FormData();
    form.append("codebase", file);
    const headers: Record<string, string> = {};
    if (apiKey) headers["X-Nettle-Api-Key"] = apiKey;
    return request<ScanReport>("/api/scans", { method: "POST", body: form, headers });
  },

  scanRepo: (repoUrl: string, opts?: { branch?: string; apiKey?: string }) =>
    request<ScanReport>("/api/scans/repo", {
      method: "POST",
      body: JSON.stringify({ repoUrl, branch: opts?.branch, apiKey: opts?.apiKey }),
    }),

  // Billing
  createCheckoutSession: (plan: "build" | "protect") =>
    request<{ url: string }>("/api/billing/checkout-session", {
      method: "POST",
      body: JSON.stringify({ plan }),
    }),
};

export { ApiError };
