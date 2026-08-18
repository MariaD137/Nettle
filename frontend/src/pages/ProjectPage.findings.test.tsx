import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProjectPage, { hashFinding } from "./ProjectPage";

// jsdom doesn't implement matchMedia — ProjectPage's useIsMobile() needs it
// to decide between the mobile/desktop layouts (this suite exercises the
// desktop one, hence "matches: false").
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
  apiKey: "nettle_test_key",
  url: null,
  repoUrl: null,
  repoBranch: null,
  hasRepoAccessToken: false,
  description: null,
  environment: "production",
  archivedAt: null,
  createdAt: "2026-01-01T00:00:00.000Z",
};

const findings = [
  {
    severity: "critical", category: "Security", title: "Hardcoded API key", detail: "Found a hardcoded key in source.",
    file: "src/config.js", line: 12, remediation: null,
    ruleId: "abc123def456", codeContext: "const API_KEY = '[REDACTED]';",
  },
  { severity: "high", category: "Dependencies", title: "Vulnerable dependency: lodash", detail: "Known prototype pollution issue.", file: "package.json", line: null, remediation: null },
  { severity: "medium", category: "Security", title: "Missing CSP header", detail: "No Content-Security-Policy header set.", file: null, line: null, remediation: null },
  { severity: "low", category: "Legal & Policy", title: "No cookie policy found", detail: "Consider adding one.", file: null, line: null, remediation: null },
];

const HARDCODED_API_KEY_HASH = hashFinding("Security", "Hardcoded API key", "src/config.js");

const mockScan = {
  id: "scan-1",
  projectId: "proj-1",
  scannedAt: "2026-01-02T00:00:00.000Z",
  score: 62,
  criticalCount: 2,
  cautionCount: 2,
  clearCount: 5,
  report: {
    scannedAt: "2026-01-02T00:00:00.000Z",
    target: "My App",
    score: 62,
    scannerVersion: "1.4.0",
    findings,
    passed: [],
    summary: { critical: 1, high: 1, medium: 1, low: 1, info: 0, clear: 5 },
  },
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getProject: vi.fn(),
      listFindingStatuses: vi.fn(),
      updateFindingStatus: vi.fn(),
      getBadge: vi.fn(),
      badgeSvgUrl: (id: string) => `http://example.com/badge/${id}.svg`,
    },
  };
});

import { api } from "../api";

function renderFindingsTab() {
  return render(
    <MemoryRouter initialEntries={["/projects/proj-1"]}>
      <Routes>
        <Route path="/projects/:id" element={<ProjectPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("ProjectPage Findings tab", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      project: mockProject,
      badge: { status: "caution", label: "Caution", lastScannedAt: mockScan.scannedAt, score: 62 },
      latestScan: mockScan,
      alertCounts: { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
    } as any);
    vi.mocked(api.listFindingStatuses).mockReset().mockResolvedValue({
      findingStatuses: [
        {
          id: "fs-1",
          projectId: "proj-1",
          findingHash: "existing-hash",
          status: "open",
          notes: null,
          updatedAt: "2026-01-01T00:00:00.000Z",
        },
      ],
      findingHistory: [
        { findingHash: HARDCODED_API_KEY_HASH, firstSeenAt: "2026-01-01T00:00:00.000Z", lastSeenAt: "2026-01-02T00:00:00.000Z" },
      ],
    });
    vi.mocked(api.updateFindingStatus).mockReset();
  });

  async function openFindingsTab() {
    renderFindingsTab();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /findings/i }));
    await waitFor(() => expect(screen.getByRole("heading", { name: /^Findings/ })).toBeInTheDocument());
  }

  it("lists every finding from the latest scan by default", async () => {
    await openFindingsTab();
    expect(screen.getByText("Hardcoded API key")).toBeInTheDocument();
    expect(screen.getByText("Vulnerable dependency: lodash")).toBeInTheDocument();
    expect(screen.getByText("Missing CSP header")).toBeInTheDocument();
    expect(screen.getByText("No cookie policy found")).toBeInTheDocument();
    expect(screen.getByText("Findings (4)")).toBeInTheDocument();
  });

  it("shows line number, code context, rule reference, and first/last-detected dates when available", async () => {
    await openFindingsTab();

    expect(screen.getByText("src/config.js:12")).toBeInTheDocument();
    expect(screen.getByText("const API_KEY = '[REDACTED]';")).toBeInTheDocument();
    expect(screen.getByText("abc123def456")).toBeInTheDocument();
    expect(screen.getByText(/First detected/)).toBeInTheDocument();
    expect(screen.getByText(/last seen/)).toBeInTheDocument();
  });

  it("search filters findings by title text", async () => {
    await openFindingsTab();
    fireEvent.change(screen.getByLabelText(/search findings/i), { target: { value: "lodash" } });

    expect(screen.getByText("Vulnerable dependency: lodash")).toBeInTheDocument();
    expect(screen.queryByText("Hardcoded API key")).not.toBeInTheDocument();
    expect(screen.getByText("Findings (1 of 4)")).toBeInTheDocument();
  });

  it("filters by severity", async () => {
    await openFindingsTab();
    fireEvent.change(screen.getByLabelText(/filter by severity/i), { target: { value: "critical" } });

    expect(screen.getByText("Hardcoded API key")).toBeInTheDocument();
    expect(screen.queryByText("Missing CSP header")).not.toBeInTheDocument();
  });

  it("filters by category", async () => {
    await openFindingsTab();
    fireEvent.change(screen.getByLabelText(/filter by category/i), { target: { value: "Legal & Policy" } });

    expect(screen.getByText("No cookie policy found")).toBeInTheDocument();
    expect(screen.queryByText("Hardcoded API key")).not.toBeInTheDocument();
  });

  it("sorting by title A-Z reorders the list", async () => {
    await openFindingsTab();
    fireEvent.change(screen.getByLabelText(/sort findings/i), { target: { value: "title-asc" } });

    const titles = screen.getAllByText(/Hardcoded API key|Vulnerable dependency: lodash|Missing CSP header|No cookie policy found/);
    const order = titles.map((el) => el.textContent);
    const sorted = [...order].sort((a, b) => (a ?? "").localeCompare(b ?? ""));
    expect(order).toEqual(sorted);
  });

  it("shows an empty state when filters match nothing", async () => {
    await openFindingsTab();
    fireEvent.change(screen.getByLabelText(/search findings/i), { target: { value: "nothing matches this" } });
    expect(screen.getByText(/no findings match your filters/i)).toBeInTheDocument();
  });

  it("saving a note calls updateFindingStatus with the current status and note text, and the Save button disappears once saved", async () => {
    vi.mocked(api.updateFindingStatus).mockImplementation((projectId, findingHash, status, notes) =>
      Promise.resolve({
        findingStatus: {
          id: "fs-2",
          projectId,
          findingHash,
          status,
          notes: notes ?? null,
          updatedAt: "2026-01-02T00:00:00.000Z",
        },
      })
    );
    await openFindingsTab();

    const textareas = screen.getAllByPlaceholderText(/add a note/i);
    fireEvent.change(textareas[0], { target: { value: "Tracked in JIRA-123" } });

    const saveButton = await screen.findByRole("button", { name: /save note/i });
    fireEvent.click(saveButton);

    await waitFor(() => expect(api.updateFindingStatus).toHaveBeenCalledWith("proj-1", expect.any(String), "open", "Tracked in JIRA-123"));
    await waitFor(() => expect(screen.queryByRole("button", { name: /save note/i })).not.toBeInTheDocument());
  });

  it("changing a finding's status calls updateFindingStatus with the new status", async () => {
    vi.mocked(api.updateFindingStatus).mockResolvedValue({
      findingStatus: {
        id: "fs-3",
        projectId: "proj-1",
        findingHash: "whatever",
        status: "resolved",
        notes: null,
        updatedAt: "2026-01-02T00:00:00.000Z",
      },
    });
    await openFindingsTab();

    const statusSelects = screen.getAllByDisplayValue("Open");
    fireEvent.change(statusSelects[0], { target: { value: "resolved" } });

    await waitFor(() => expect(api.updateFindingStatus).toHaveBeenCalledWith("proj-1", expect.any(String), "resolved"));
  });
});
