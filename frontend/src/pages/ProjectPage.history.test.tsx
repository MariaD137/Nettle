import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProjectPage from "./ProjectPage";

// jsdom doesn't implement matchMedia — ProjectPage's useIsMobile() needs it.
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

function makeScan(id: string, scannedAt: string, score: number): any {
  return {
    id,
    projectId: "proj-1",
    scannedAt,
    score,
    criticalCount: 1,
    cautionCount: 1,
    clearCount: 5,
    scannerVersion: "1.4.0",
    report: {
      scannedAt,
      target: "My App",
      score,
      scannerVersion: "1.4.0",
      findings: [],
      passed: [],
      summary: { critical: 1, high: 0, medium: 1, low: 0, info: 0, clear: 5 },
    },
  };
}

const scans = [
  makeScan("scan-3", "2026-03-01T00:00:00.000Z", 78),
  makeScan("scan-2", "2026-02-01T00:00:00.000Z", 62),
  makeScan("scan-1", "2026-01-01T00:00:00.000Z", 45),
];

const comparisonResult = {
  from: { id: "scan-1", score: 45, scannedAt: "2026-01-01T00:00:00.000Z" },
  to: { id: "scan-2", score: 62, scannedAt: "2026-02-01T00:00:00.000Z" },
  scoreDelta: 17,
  fixed: 1,
  new: 1,
  remaining: 1,
  fixedFindings: [{ severity: "high", category: "Security", title: "Old vulnerable dependency", detail: "", file: null, line: null, remediation: null }],
  newFindings: [{ severity: "critical", category: "Security", title: "Fresh SQL injection", detail: "", file: null, line: null, remediation: null }],
  remainingFindings: [{ severity: "low", category: "Legal & Policy", title: "No cookie policy found", detail: "", file: null, line: null, remediation: null }],
  fullReport: true,
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getProject: vi.fn(),
      getScans: vi.fn(),
      compareScans: vi.fn(),
      downloadScanReport: vi.fn(),
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

describe("ProjectPage History tab", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      project: mockProject,
      badge: { status: "caution", label: "Caution", lastScannedAt: scans[0].scannedAt, score: 78 },
      latestScan: scans[0],
      alertCounts: { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
    } as any);
    vi.mocked(api.getScans).mockReset().mockResolvedValue({
      project: { id: "proj-1", name: "My App" },
      scans,
    } as any);
    vi.mocked(api.compareScans).mockReset().mockResolvedValue(comparisonResult as any);
    vi.mocked(api.downloadScanReport).mockReset();
  });

  async function openHistoryTab() {
    renderProjectPage();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /history/i }));
    await waitFor(() => expect(screen.getByRole("heading", { name: /scan history/i })).toBeInTheDocument());
  }

  it("renders a score chart summarizing the trend across all scans", async () => {
    await openHistoryTab();
    await waitFor(() => expect(screen.getByRole("img", { name: /score trend/i })).toBeInTheDocument());
    const chart = screen.getByRole("img", { name: /score trend/i });
    expect(chart.getAttribute("aria-label")).toMatch(/45.*78|78.*45/s);
  });

  it("defaults the compare picker to the previous vs. latest scan", async () => {
    await openHistoryTab();
    const fromSelect = screen.getByLabelText("Compare") as HTMLSelectElement;
    const toSelect = screen.getByLabelText("with") as HTMLSelectElement;
    expect(fromSelect.value).toBe("scan-2");
    expect(toSelect.value).toBe("scan-3");
  });

  it("lets the user pick two specific scans and compares them side by side", async () => {
    await openHistoryTab();

    fireEvent.change(screen.getByLabelText("Compare"), { target: { value: "scan-1" } });
    fireEvent.change(screen.getByLabelText("with"), { target: { value: "scan-2" } });
    fireEvent.click(screen.getByRole("button", { name: /^compare$/i }));

    await waitFor(() => expect(api.compareScans).toHaveBeenCalledWith("proj-1", "scan-1", "scan-2"));

    // Side-by-side: both scan scores are shown together with the delta between them.
    const compareCard = await screen.findByTestId("scan-compare");
    expect(within(compareCard).getByText("45")).toBeInTheDocument();
    expect(within(compareCard).getByText("62")).toBeInTheDocument();
    expect(within(compareCard).getByText("+17")).toBeInTheDocument();
  });

  it("shows fixed, new, and unchanged findings as three distinct sections", async () => {
    await openHistoryTab();
    fireEvent.click(screen.getByRole("button", { name: /^compare$/i }));

    const fixedSection = await screen.findByText(/Fixed \(1\)/);
    expect(within(fixedSection.closest("details")!).getByText(/Old vulnerable dependency/)).toBeInTheDocument();

    const newSection = screen.getByText(/New issues \(1\)/);
    expect(within(newSection.closest("details")!).getByText(/Fresh SQL injection/)).toBeInTheDocument();

    // Unchanged findings are now actually listed (not just counted).
    const unchangedSection = screen.getByText(/Unchanged \(1\)/);
    expect(within(unchangedSection.closest("details")!).getByText(/No cookie policy found/)).toBeInTheDocument();
  });

  it("the unchanged section is collapsed by default; fixed/new are expanded", async () => {
    await openHistoryTab();
    fireEvent.click(screen.getByRole("button", { name: /^compare$/i }));
    await screen.findByText(/Fixed \(1\)/);

    const unchangedDetails = screen.getByText(/Unchanged \(1\)/).closest("details") as HTMLDetailsElement;
    const fixedDetails = screen.getByText(/Fixed \(1\)/).closest("details") as HTMLDetailsElement;
    expect(unchangedDetails.open).toBe(false);
    expect(fixedDetails.open).toBe(true);
  });
});
