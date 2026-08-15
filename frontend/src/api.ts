const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

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
  createdAt: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  category: string;
  title: string;
  detail: string;
  file: string | null;
  remediation: string | null;
}

export interface ScanReport {
  scannedAt: string;
  target: string;
  score: number;
  findings: Finding[];
  passed: { category: string; title: string }[];
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

export interface OverviewData {
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
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const body = isJson ? await res.json() : null;

  if (!res.ok) {
    throw new ApiError(res.status, body?.error ?? `Request failed with status ${res.status}`);
  }
  return body as T;
}

export const api = {
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

  overview: () => request<OverviewData>("/api/overview"),

  listProjects: () => request<{ projects: Project[] }>("/api/projects"),

  createProject: (name: string) =>
    request<Project>("/api/projects", { method: "POST", body: JSON.stringify({ name }) }),

  getProject: (id: string) => request<ProjectDetail>(`/api/projects/${id}`),

  getAlerts: (projectId: string) =>
    request<{ project: { id: string; name: string }; alerts: Alert[] }>(`/api/projects/${projectId}/alerts`),

  updateAlertStatus: (projectId: string, alertId: string, status: AlertStatus) =>
    request<{ alert: Alert }>(`/api/projects/${projectId}/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),

  getScans: (projectId: string) =>
    request<{ project: { id: string; name: string }; scans: StoredScan[] }>(`/api/projects/${projectId}/scans`),

  getBadge: (projectId: string) => request<BadgeState>(`/api/projects/${projectId}/badge.json`),

  badgeSvgUrl: (projectId: string) => `${API_BASE}/api/projects/${projectId}/badge.svg`,

  scanCodebase: async (file: File, apiKey?: string): Promise<ScanReport> => {
    const form = new FormData();
    form.append("codebase", file);
    const headers: Record<string, string> = {};
    if (apiKey) headers["X-Nettle-Api-Key"] = apiKey;
    return request<ScanReport>("/api/scans", { method: "POST", body: form, headers });
  },

  createCheckoutSession: (plan: "tier1" | "tier2") =>
    request<{ url: string }>("/api/billing/checkout-session", {
      method: "POST",
      body: JSON.stringify({ plan }),
    }),
};

export { ApiError };
