const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

export interface User {
  id: string;
  email: string;
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  onboardingCompletedAt?: string | null;
  emailVerifiedAt?: string | null;
  createdAt: string;
}

export interface Project {
  id: string;
  userId: string;
  name: string;
  apiKey: string;
  url: string | null;
  repoUrl: string | null;
  repoBranch: string | null;
  // Never the token itself — see backend/src/security/tokenEncryption.ts.
  hasRepoAccessToken: boolean;
  description: string | null;
  environment: string | null;
  archivedAt: string | null;
  createdAt: string;
}

export type ApiKeyScope = "scan" | "events";

export interface StoredApiKey {
  id: string;
  projectId: string;
  name: string;
  // The full secret only on the response from createApiKey/rotateApiKeyById
  // — every other read (listApiKeys) returns this masked, e.g. "nettle_a1b2…c3d4".
  key: string;
  scopes: ApiKeyScope[];
  isDefault: boolean;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface DetectionSettings {
  projectId: string;
  bruteForceThreshold: number;
  highRequestRateThreshold: number;
  credentialStuffingMinIps: number;
  updatedAt: string | null;
}

export interface AlertTimelineBucket {
  hour: string;
  count: number;
  bySeverity: Record<"critical" | "high" | "medium" | "low", number>;
}

export interface RankedCount {
  label: string;
  count: number;
}

export interface AlertAnalytics {
  timeline: AlertTimelineBucket[];
  topAttackTypes: RankedCount[];
  topEndpoints: RankedCount[];
  topCountries: RankedCount[];
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
  // How a vulnerable dependency was actually pulled in, root to leaf.
  // Only ever set on dependency findings when a lockfile was present.
  dependencyPaths?: string[][];
  // A stable reference to the detection rule that produced this finding —
  // the real Semgrep check_id for Semgrep-sourced findings, a generated
  // (but still stable) ID for everything else.
  ruleId?: string | null;
  // A short, redacted snippet of the actual source line that triggered
  // this finding, when available.
  codeContext?: string | null;
}

export interface ScanAccess {
  tier: "preview" | "full";
  fullReport: boolean;
  totalFindings: number;
  visibleFindings: number;
  lockedFindings: number;
  message: string | null;
}

export interface ScanReport {
  scannedAt: string;
  target: string;
  score: number;
  scannerVersion: string;
  access?: ScanAccess;
  findings: Finding[];
  passed: { category: string; title: string }[];
  summary: { critical: number; high: number; medium: number; low: number; info: number; clear: number };
  // The project's environment at the moment this scan was recorded — a
  // permanent snapshot, not a live lookup of the project's current setting.
  environment?: string | null;
}

export type ScanJobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ScanJobStepStatus = "pending" | "running" | "done";

export interface ScanJobStep {
  id: string;
  label: string;
  status: ScanJobStepStatus;
}

export interface ScanJob {
  id: string;
  status: ScanJobStatus;
  source: "upload" | "repo" | "url";
  steps: ScanJobStep[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  report: ScanReport | null;
  error: string | null;
  friendlyError?: string;
  queuePosition: number | null;
}

export interface StoredScan {
  id: string;
  projectId: string;
  scannedAt: string;
  score: number;
  criticalCount: number;
  cautionCount: number;
  clearCount: number;
  // Null for scans recorded before scanner-version tracking existed.
  scannerVersion?: string | null;
  semgrepVersion?: string | null;
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
  limit: number;
  used: number;
  remaining: number;
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
    environment: string | null;
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

// When a given finding (by its stable hash) was first and most recently
// observed across a project's scan history.
export interface FindingHistoryEntry {
  findingHash: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface SessionInfo {
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export interface PaymentFailure {
  id: string;
  userId: string;
  stripeInvoiceId: string;
  amountDue: number | null;
  currency: string | null;
  failureReason: string | null;
  occurredAt: string;
  resolvedAt: string | null;
}

export interface CustomRule {
  id: string;
  project_id: string;
  name: string;
  description?: string;
  pattern_type: "exact" | "regex" | "threshold" | "combination";
  pattern_value: string;
  weight: number;
  severity: "critical" | "high" | "medium" | "low";
  enabled: boolean;
  version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface CustomRuleInput {
  name: string;
  description?: string;
  pattern_type: CustomRule["pattern_type"];
  pattern_value: string;
  weight: number;
  severity: CustomRule["severity"];
  enabled: boolean;
}

export type WebhookService = "slack" | "pagerduty" | "splunk" | "datadog" | "generic";

// Every string a caller may currently subscribe a webhook to. "scan.completed"
// fires from recordScan (backend/src/patrol/scans.ts); the rest fire from
// alert creation (backend/src/patrol/alerts.ts#notifyAlertWebhooks).
export const WEBHOOK_EVENT_TYPES = ["scan.completed", "incident_alert", "anomaly_alert"] as const;
export type WebhookEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

export interface Webhook {
  id: string;
  project_id: string;
  service: WebhookService;
  webhook_url: string;
  is_active: boolean;
  event_types: string[];
  created_at: string;
  updated_at: string;
}

export type NotificationChannelType = "email" | "sms";

export const NOTIFICATION_EVENT_TYPES = ["scan.completed", "incident_alert", "digest.daily", "digest.weekly"] as const;
export type NotificationEventType = (typeof NOTIFICATION_EVENT_TYPES)[number];

export interface NotificationChannel {
  id: string;
  project_id: string;
  channel: NotificationChannelType;
  destination: string;
  is_active: boolean;
  event_types: string[];
  created_at: string;
  updated_at: string;
}

export interface WebhookEvent {
  id: string;
  webhook_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  status: "pending" | "sent" | "failed" | "retrying";
  attempt_count: number;
  last_error?: string;
  created_at: string;
  sent_at?: string;
}

export interface ScanComparison {
  from: { id: string; score: number; scannedAt: string };
  to: { id: string; score: number; scannedAt: string };
  scoreDelta: number;
  fixed: number;
  new: number;
  remaining: number;
  fixedFindings: Finding[];
  newFindings: Finding[];
  remainingFindings: Finding[];
  fullReport: boolean;
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

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
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

  completeOnboarding: () =>
    request<{ user: User }>("/api/auth/onboarding/complete", { method: "POST" }),

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

  verifyEmail: (token: string) =>
    request<{ message: string; user: User }>("/api/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),

  resendVerification: () =>
    request<{ message: string }>("/api/auth/resend-verification", { method: "POST" }),

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

  createProject: (
    name: string,
    opts?: { url?: string; repoUrl?: string; repoBranch?: string; description?: string; environment?: string }
  ) => request<Project>("/api/projects", { method: "POST", body: JSON.stringify({ name, ...opts }) }),

  getProject: (id: string) => request<ProjectDetail>(`/api/projects/${id}`),

  updateProject: (
    id: string,
    updates: {
      name?: string;
      url?: string;
      repoUrl?: string;
      repoBranch?: string;
      // Empty string clears a previously-stored token; omit the field
      // entirely to leave whatever's already stored untouched.
      repoAccessToken?: string;
      description?: string;
      environment?: string;
    }
  ) => request<Project>(`/api/projects/${id}`, { method: "PATCH", body: JSON.stringify(updates) }),

  deleteProject: (id: string) =>
    request<void>(`/api/projects/${id}`, { method: "DELETE" }),

  archiveProject: (id: string) =>
    request<Project>(`/api/projects/${id}/archive`, { method: "POST" }),

  restoreProject: (id: string) =>
    request<Project>(`/api/projects/${id}/restore`, { method: "POST" }),

  rotateApiKey: (id: string) =>
    request<Project>(`/api/projects/${id}/rotate-key`, { method: "POST" }),

  // Multi-key API key management (additive to the single legacy key
  // above — see backend/src/patrol/apiKeys.ts).
  listApiKeys: (projectId: string) =>
    request<{ apiKeys: StoredApiKey[] }>(`/api/projects/${projectId}/api-keys`),

  createApiKey: (projectId: string, name: string, scopes: ApiKeyScope[]) =>
    request<{ apiKey: StoredApiKey }>(`/api/projects/${projectId}/api-keys`, {
      method: "POST",
      body: JSON.stringify({ name, scopes }),
    }),

  updateApiKey: (projectId: string, keyId: string, updates: { name?: string; scopes?: ApiKeyScope[] }) =>
    request<{ apiKey: StoredApiKey }>(`/api/projects/${projectId}/api-keys/${keyId}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  rotateApiKeyById: (projectId: string, keyId: string) =>
    request<{ apiKey: StoredApiKey }>(`/api/projects/${projectId}/api-keys/${keyId}/rotate`, { method: "POST" }),

  revokeApiKey: (projectId: string, keyId: string) =>
    request<{ apiKey: StoredApiKey }>(`/api/projects/${projectId}/api-keys/${keyId}/revoke`, { method: "POST" }),

  // Detection thresholds
  getDetectionSettings: (projectId: string) =>
    request<{ settings: DetectionSettings }>(`/api/projects/${projectId}/detection-settings`),

  updateDetectionSettings: (
    projectId: string,
    updates: { bruteForceThreshold?: number; highRequestRateThreshold?: number; credentialStuffingMinIps?: number }
  ) =>
    request<{ settings: DetectionSettings }>(`/api/projects/${projectId}/detection-settings`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  resetDetectionSettings: (projectId: string) =>
    request<{ settings: DetectionSettings }>(`/api/projects/${projectId}/detection-settings/reset`, { method: "POST" }),

  // Alerts
  getAlerts: (projectId: string) =>
    request<{ project: { id: string; name: string }; alerts: Alert[] }>(`/api/projects/${projectId}/alerts`),

  updateAlertStatus: (projectId: string, alertId: string, status: AlertStatus) =>
    request<{ alert: Alert }>(`/api/projects/${projectId}/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  getAlertAnalytics: (projectId: string, hours = 24) =>
    request<{ analytics: AlertAnalytics }>(`/api/projects/${projectId}/alerts/analytics?hours=${hours}`),

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
    const res = await fetch(`${API_BASE}/api/projects/${projectId}/scans/${scanId}/export`, {
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
    request<{ findingStatuses: StoredFindingStatus[]; findingHistory: FindingHistoryEntry[] }>(`/api/projects/${projectId}/findings`),

  updateFindingStatus: (projectId: string, findingHash: string, status: FindingStatus, notes?: string) =>
    request<{ findingStatus: StoredFindingStatus }>(`/api/projects/${projectId}/findings/${findingHash}`, {
      method: "PATCH",
      body: JSON.stringify({ status, notes }),
    }),

  // Custom rules
  listCustomRules: (projectId: string) =>
    request<{ rules: CustomRule[] }>(`/api/custom-rules/${projectId}`),

  createCustomRule: (projectId: string, input: CustomRuleInput) =>
    request<CustomRule>(`/api/custom-rules/${projectId}`, {
      method: "POST",
      body: JSON.stringify(input),
    }),

  updateCustomRule: (projectId: string, ruleId: string, input: Partial<CustomRuleInput>) =>
    request<CustomRule>(`/api/custom-rules/${projectId}/${ruleId}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),

  deleteCustomRule: (projectId: string, ruleId: string) =>
    request<void>(`/api/custom-rules/${projectId}/${ruleId}`, { method: "DELETE" }),

  // Integrations / webhooks
  listWebhooks: (projectId: string) =>
    request<Webhook[]>(`/api/projects/${projectId}/webhooks`),

  createWebhook: (projectId: string, service: WebhookService, webhookUrl: string, eventTypes: string[]) =>
    request<Webhook>(`/api/projects/${projectId}/webhooks`, {
      method: "POST",
      body: JSON.stringify({ service, webhook_url: webhookUrl, event_types: eventTypes }),
    }),

  updateWebhook: (
    projectId: string,
    webhookId: string,
    updates: { webhook_url?: string; event_types?: string[]; is_active?: boolean }
  ) =>
    request<Webhook>(`/api/projects/${projectId}/webhooks/${webhookId}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  deleteWebhook: (projectId: string, webhookId: string) =>
    request<void>(`/api/projects/${projectId}/webhooks/${webhookId}`, { method: "DELETE" }),

  testWebhook: (projectId: string, webhookId: string) =>
    request<{ message: string }>(`/api/projects/${projectId}/webhooks/${webhookId}/test`, { method: "POST" }),

  getWebhookEvents: (projectId: string, webhookId: string, limit = 50) =>
    request<WebhookEvent[]>(`/api/projects/${projectId}/webhooks/${webhookId}/events?limit=${limit}`),

  listNotificationChannels: (projectId: string) =>
    request<NotificationChannel[]>(`/api/projects/${projectId}/notification-channels`),

  createNotificationChannel: (projectId: string, channel: NotificationChannelType, destination: string, eventTypes: string[]) =>
    request<NotificationChannel>(`/api/projects/${projectId}/notification-channels`, {
      method: "POST",
      body: JSON.stringify({ channel, destination, event_types: eventTypes }),
    }),

  updateNotificationChannel: (
    projectId: string,
    channelId: string,
    updates: { destination?: string; event_types?: string[]; is_active?: boolean }
  ) =>
    request<NotificationChannel>(`/api/projects/${projectId}/notification-channels/${channelId}`, {
      method: "PATCH",
      body: JSON.stringify(updates),
    }),

  deleteNotificationChannel: (projectId: string, channelId: string) =>
    request<void>(`/api/projects/${projectId}/notification-channels/${channelId}`, { method: "DELETE" }),

  // Badge
  getBadge: (projectId: string) => request<BadgeState>(`/api/projects/${projectId}/badge.json`),

  badgeSvgUrl: (projectId: string) => `${API_BASE}/api/projects/${projectId}/badge.svg`,

  // Scan upload
  scanCodebase: async (file: File, apiKey?: string, signal?: AbortSignal): Promise<ScanReport> => {
    const form = new FormData();
    form.append("codebase", file);
    const headers: Record<string, string> = {};
    if (apiKey) headers["X-Nettle-Api-Key"] = apiKey;
    return request<ScanReport>("/api/scans", { method: "POST", body: form, headers, signal });
  },

  scanRepo: (repoUrl: string, opts?: { branch?: string; apiKey?: string; signal?: AbortSignal }) =>
    request<ScanReport>("/api/scans/repo", {
      method: "POST",
      signal: opts?.signal,
      body: JSON.stringify({ repoUrl, branch: opts?.branch, apiKey: opts?.apiKey }),
    }),

  // Scan jobs — the async, real-progress counterpart to scanCodebase/scanRepo
  // above (which stay as they are for anyone relying on the immediate-report
  // response). A scan submitted this way runs in a background worker on the
  // server, so the request returns a job id right away instead of blocking
  // until the whole scan finishes.
  startUploadScanJob: async (file: File, apiKey?: string): Promise<{ jobId: string }> => {
    const form = new FormData();
    form.append("codebase", file);
    const headers: Record<string, string> = {};
    if (apiKey) headers["X-Nettle-Api-Key"] = apiKey;
    return request<{ jobId: string }>("/api/scans/jobs/upload", { method: "POST", body: form, headers });
  },

  startRepoScanJob: (repoUrl: string, opts?: { branch?: string; apiKey?: string }) =>
    request<{ jobId: string }>("/api/scans/jobs/repo", {
      method: "POST",
      body: JSON.stringify({ repoUrl, branch: opts?.branch, apiKey: opts?.apiKey }),
    }),

  getScanJob: (jobId: string) => request<ScanJob>(`/api/scans/jobs/${jobId}`),

  cancelScanJob: (jobId: string) => request<void>(`/api/scans/jobs/${jobId}/cancel`, { method: "POST" }),

  // Analytics
  getAnalyticsDashboard: (projectId: string, timeframe: string = "24h") =>
    request<any>(`/api/analytics/${projectId}/dashboard?timeframe=${timeframe}`),

  getAnalyticsBaselines: (projectId: string, metric: string = "request_rate", period: string = "hourly", hour?: number) => {
    let query = `metric=${metric}&period=${period}`;
    if (hour !== undefined) query += `&hour=${hour}`;
    return request<any>(`/api/analytics/${projectId}/baselines?${query}`);
  },

  getAnomalies: (projectId: string, limit: number = 50, scoreMin: number = 0.7) =>
    request<any>(`/api/analytics/${projectId}/anomalies?limit=${limit}&score_min=${scoreMin}`),

  getModelStatus: (projectId: string) =>
    request<any>(`/api/analytics/${projectId}/model-status`),

  calculateBaselines: (projectId: string, hoursBack: number = 24) =>
    request<any>(`/api/analytics/${projectId}/calculate-baselines`, {
      method: "POST",
      body: JSON.stringify({ hoursBack }),
    }),

  // Billing
  createCheckoutSession: (plan: "tier1" | "tier2") =>
    request<{ url: string }>("/api/billing/checkout-session", {
      method: "POST",
      body: JSON.stringify({ plan }),
    }),

  createPortalSession: () =>
    request<{ url: string }>("/api/billing/portal-session", { method: "POST" }),

  getPaymentFailures: () =>
    request<{ failures: PaymentFailure[] }>("/api/billing/payment-failures"),
};

export { ApiError };
