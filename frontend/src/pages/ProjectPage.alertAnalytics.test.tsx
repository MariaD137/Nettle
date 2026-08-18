import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProjectPage from "./ProjectPage";
import type { Alert, AlertAnalytics } from "../api";

window.matchMedia =
  window.matchMedia ||
  ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as any;

const mockProject = {
  id: "proj-1",
  userId: "user-1",
  name: "My App",
  apiKey: "nettle_default_key_value",
  url: null,
  repoUrl: null,
  repoBranch: null,
  hasRepoAccessToken: false,
  description: null,
  environment: "production",
  archivedAt: null,
  createdAt: "2026-01-01T00:00:00.000Z",
};

const brutForceAlert: Alert = {
  id: "alert-1",
  projectId: "proj-1",
  occurredAt: "2026-02-01T10:00:00.000Z",
  severity: "critical",
  rule: "suspicious-path-8.8.8.8",
  message: 'Request to "/wp-admin" from 8.8.8.8 matches a common attack-probe pattern.',
  status: "new",
};

const analytics: AlertAnalytics = {
  timeline: [
    { hour: "2026-02-01T09:00:00Z", count: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } },
    { hour: "2026-02-01T10:00:00Z", count: 1, bySeverity: { critical: 1, high: 0, medium: 0, low: 0 } },
  ],
  topAttackTypes: [{ label: "suspicious-path", count: 1 }],
  topEndpoints: [{ label: "/wp-admin", count: 1 }],
  topCountries: [{ label: "US", count: 1 }],
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getProject: vi.fn(),
      getAlerts: vi.fn(),
      updateAlertStatus: vi.fn(),
      getAlertAnalytics: vi.fn(),
      getBadge: vi.fn(),
      badgeSvgUrl: (id: string) => `http://example.com/badge/${id}.svg`,
    },
  };
});

import { api } from "../api";

function renderProjectPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/proj-1"]}>
      <Routes>
        <Route path="/projects/:id" element={<ProjectPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ProjectPage Alerts tab attack analytics", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      project: mockProject,
      badge: { status: "caution", label: "Caution", lastScannedAt: null, score: null },
      latestScan: null,
      alertCounts: { new: 1, acknowledged: 0, resolved: 0, false_positive: 0 },
    } as any);
    vi.mocked(api.getAlerts).mockReset().mockResolvedValue({
      project: { id: "proj-1", name: "My App" },
      alerts: [brutForceAlert],
    });
    vi.mocked(api.getAlertAnalytics).mockReset().mockResolvedValue({ analytics });
  });

  async function openAlertsTab() {
    renderProjectPage();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /alerts/i }));
    await waitFor(() => expect(screen.getByText("Attack activity (last 24h)")).toBeInTheDocument());
  }

  it("shows the attack timeline and rankings once alerts have loaded", async () => {
    await openAlertsTab();

    expect(api.getAlertAnalytics).toHaveBeenCalledWith("proj-1", 24);
    expect(screen.getByText("Top attack types")).toBeInTheDocument();
    expect(screen.getByText("suspicious-path")).toBeInTheDocument();
    expect(screen.getByText("Top targeted endpoints")).toBeInTheDocument();
    expect(screen.getByText("/wp-admin")).toBeInTheDocument();
    expect(screen.getByText("Top source countries")).toBeInTheDocument();
    expect(screen.getByText("United States")).toBeInTheDocument();
  });

  it("does not render the analytics panel when there are no alerts at all", async () => {
    vi.mocked(api.getAlerts).mockResolvedValue({ project: { id: "proj-1", name: "My App" }, alerts: [] });
    renderProjectPage();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /alerts/i }));
    await waitFor(() => expect(screen.getByText(/good sign/i)).toBeInTheDocument());

    expect(screen.queryByText("Attack activity (last 24h)")).not.toBeInTheDocument();
    expect(api.getAlertAnalytics).not.toHaveBeenCalled();
  });
});
