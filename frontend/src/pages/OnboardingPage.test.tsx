import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import OnboardingPage from "./OnboardingPage";

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
  environment: null,
  archivedAt: null,
  createdAt: "2026-01-01T00:00:00.000Z",
};

const mockReport = {
  scannedAt: "2026-01-01T00:00:00.000Z",
  target: "My App",
  scannerVersion: "1.4.0",
  score: 82,
  findings: [],
  passed: [],
  summary: { critical: 0, high: 1, medium: 2, low: 0, info: 0, clear: 9 },
};

const mockCompletedJob = {
  id: "job-1",
  status: "completed" as const,
  source: "repo" as const,
  steps: [{ id: "secrets", label: "Scanning for hardcoded secrets", status: "done" as const }],
  createdAt: "2026-01-01T00:00:00.000Z",
  startedAt: "2026-01-01T00:00:00.000Z",
  finishedAt: "2026-01-01T00:00:01.000Z",
  report: mockReport,
  error: null,
  queuePosition: null,
};

const refreshUser = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ user: { id: "user-1", email: "a@b.com" }, refreshUser }),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      createProject: vi.fn(),
      startUploadScanJob: vi.fn(),
      startRepoScanJob: vi.fn(),
      getScanJob: vi.fn(),
      cancelScanJob: vi.fn(),
      completeOnboarding: vi.fn(),
    },
  };
});

import { api } from "../api";

describe("OnboardingPage", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.mocked(api.createProject).mockReset();
    vi.mocked(api.startUploadScanJob).mockReset();
    vi.mocked(api.startRepoScanJob).mockReset();
    vi.mocked(api.getScanJob).mockReset();
    vi.mocked(api.cancelScanJob).mockReset().mockResolvedValue(undefined);
    vi.mocked(api.completeOnboarding).mockReset().mockResolvedValue({ user: {} as any });
    refreshUser.mockReset();
  });

  it("walks welcome -> intro -> project -> scan -> score", async () => {
    vi.mocked(api.createProject).mockResolvedValue(mockProject);
    vi.mocked(api.startRepoScanJob).mockResolvedValue({ jobId: "job-1" });
    vi.mocked(api.getScanJob).mockResolvedValue(mockCompletedJob);

    render(<OnboardingPage />);

    // Welcome
    expect(screen.getByText(/welcome to nettle/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /get started/i }));

    // Intro
    expect(screen.getByText(/what nettle does/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));

    // Project creation
    expect(screen.getByText(/create your first project/i)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: "My App" } });
    fireEvent.click(screen.getByRole("button", { name: /create project/i }));

    await waitFor(() => expect(api.createProject).toHaveBeenCalledWith("My App", { url: undefined }));

    // Scan step
    await waitFor(() => expect(screen.getByText(/run your first scan/i)).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /scan repo/i }));
    fireEvent.change(screen.getByLabelText(/repository url/i), { target: { value: "https://github.com/o/r" } });
    fireEvent.click(screen.getByRole("button", { name: /scan repository/i }));

    await waitFor(() =>
      expect(api.startRepoScanJob).toHaveBeenCalledWith(
        "https://github.com/o/r",
        expect.objectContaining({ apiKey: "nettle_test_key" })
      )
    );
    await waitFor(() => expect(api.getScanJob).toHaveBeenCalledWith("job-1"), { timeout: 3000 });

    // Score step
    await waitFor(() => expect(screen.getByText(/your first security score/i)).toBeInTheDocument(), { timeout: 3000 });
    expect(screen.getByText("82")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /go to dashboard/i }));
    await waitFor(() => expect(api.completeOnboarding).toHaveBeenCalled());
    expect(refreshUser).toHaveBeenCalled();
  });

  it("shows real-time step progress while a scan job is still running", async () => {
    vi.mocked(api.createProject).mockResolvedValue(mockProject);
    vi.mocked(api.startUploadScanJob).mockResolvedValue({ jobId: "job-2" });
    vi.mocked(api.getScanJob).mockResolvedValue({
      ...mockCompletedJob,
      id: "job-2",
      source: "upload",
      status: "running",
      report: null,
      steps: [
        { id: "secrets", label: "Scanning for hardcoded secrets", status: "done" },
        { id: "dependencies", label: "Checking dependency lockfile", status: "running" },
        { id: "semgrep", label: "Running static analysis (Semgrep)", status: "pending" },
      ],
    });

    render(<OnboardingPage />);
    fireEvent.click(screen.getByRole("button", { name: /get started/i }));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: "My App" } });
    fireEvent.click(screen.getByRole("button", { name: /create project/i }));

    await waitFor(() => expect(screen.getByText(/run your first scan/i)).toBeInTheDocument());
    const file = new File(["console.log(1)"], "app.zip", { type: "application/zip" });
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: /^scan$/i }));

    await waitFor(() => expect(screen.getByText("Checking dependency lockfile")).toBeInTheDocument(), { timeout: 3000 });
    // A step already marked "done" by the server should render as such.
    expect(screen.getByText("Scanning for hardcoded secrets").closest("li")?.className).toContain("done");
  });

  it("cancel calls the job-cancel endpoint and stops waiting", async () => {
    vi.mocked(api.createProject).mockResolvedValue(mockProject);
    vi.mocked(api.startUploadScanJob).mockResolvedValue({ jobId: "job-3" });
    // Never resolves to "completed" — simulates a long-running scan the
    // user cancels before it finishes.
    vi.mocked(api.getScanJob).mockResolvedValue({
      ...mockCompletedJob,
      id: "job-3",
      status: "running",
      report: null,
    });

    render(<OnboardingPage />);
    fireEvent.click(screen.getByRole("button", { name: /get started/i }));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: "My App" } });
    fireEvent.click(screen.getByRole("button", { name: /create project/i }));

    await waitFor(() => expect(screen.getByText(/run your first scan/i)).toBeInTheDocument());
    const file = new File(["console.log(1)"], "app.zip", { type: "application/zip" });
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    fireEvent.change(fileInput, { target: { files: [file] } });
    fireEvent.click(screen.getByRole("button", { name: /^scan$/i }));

    await waitFor(() => expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /cancel/i }));

    expect(api.cancelScanJob).toHaveBeenCalledWith("job-3");
  });

  it("skipping from the scan step still completes onboarding", async () => {
    vi.mocked(api.createProject).mockResolvedValue(mockProject);

    render(<OnboardingPage />);
    fireEvent.click(screen.getByRole("button", { name: /get started/i }));
    fireEvent.click(screen.getByRole("button", { name: /continue/i }));
    fireEvent.change(screen.getByLabelText(/project name/i), { target: { value: "My App" } });
    fireEvent.click(screen.getByRole("button", { name: /create project/i }));

    await waitFor(() => expect(screen.getByText(/run your first scan/i)).toBeInTheDocument());
    fireEvent.click(screen.getByText(/i'll scan later/i));

    await waitFor(() => expect(api.completeOnboarding).toHaveBeenCalled());
    expect(refreshUser).toHaveBeenCalled();
  });

  it("the top-level Skip setup control completes onboarding from any step", async () => {
    render(<OnboardingPage />);
    fireEvent.click(screen.getByRole("button", { name: /skip setup/i }));
    await waitFor(() => expect(api.completeOnboarding).toHaveBeenCalled());
  });
});
