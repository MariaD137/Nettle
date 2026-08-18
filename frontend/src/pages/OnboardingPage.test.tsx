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
      scanCodebase: vi.fn(),
      scanRepo: vi.fn(),
      completeOnboarding: vi.fn(),
    },
  };
});

import { api } from "../api";

describe("OnboardingPage", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.mocked(api.createProject).mockReset();
    vi.mocked(api.scanRepo).mockReset();
    vi.mocked(api.completeOnboarding).mockReset().mockResolvedValue({ user: {} as any });
    refreshUser.mockReset();
  });

  it("walks welcome -> intro -> project -> scan -> score", async () => {
    vi.mocked(api.createProject).mockResolvedValue(mockProject);
    vi.mocked(api.scanRepo).mockResolvedValue(mockReport as any);

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
      expect(api.scanRepo).toHaveBeenCalledWith("https://github.com/o/r", { apiKey: "nettle_test_key" })
    );

    // Score step
    await waitFor(() => expect(screen.getByText(/your first security score/i)).toBeInTheDocument());
    expect(screen.getByText("82")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /go to dashboard/i }));
    await waitFor(() => expect(api.completeOnboarding).toHaveBeenCalled());
    expect(refreshUser).toHaveBeenCalled();
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
