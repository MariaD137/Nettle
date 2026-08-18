import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProjectPage from "./ProjectPage";

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

window.confirm = vi.fn(() => true);

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

const defaultSettings = {
  projectId: "proj-1",
  bruteForceThreshold: 5,
  highRequestRateThreshold: 50,
  credentialStuffingMinIps: 5,
  updatedAt: null,
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getProject: vi.fn(),
      listApiKeys: vi.fn(),
      getDetectionSettings: vi.fn(),
      updateDetectionSettings: vi.fn(),
      resetDetectionSettings: vi.fn(),
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

describe("ProjectPage Detection thresholds (Settings tab)", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      project: mockProject,
      badge: { status: "caution", label: "Caution", lastScannedAt: null, score: null },
      latestScan: null,
      alertCounts: { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
    } as any);
    vi.mocked(api.listApiKeys).mockReset().mockResolvedValue({ apiKeys: [] });
    vi.mocked(api.getDetectionSettings).mockReset().mockResolvedValue({ settings: defaultSettings });
    vi.mocked(api.updateDetectionSettings).mockReset();
    vi.mocked(api.resetDetectionSettings).mockReset();
  });

  async function openSettingsTab() {
    renderProjectPage();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
    await waitFor(() => expect(screen.getByText("Detection thresholds")).toBeInTheDocument());
  }

  it("loads and displays the current thresholds", async () => {
    await openSettingsTab();
    expect(screen.getByLabelText(/brute-force/i)).toHaveValue(5);
    expect(screen.getByLabelText(/high request rate/i)).toHaveValue(50);
    expect(screen.getByLabelText(/credential stuffing/i)).toHaveValue(5);
  });

  it("saving sends only real numeric values and reflects the response", async () => {
    vi.mocked(api.updateDetectionSettings).mockResolvedValue({
      settings: { ...defaultSettings, bruteForceThreshold: 3, updatedAt: "2026-02-01T00:00:00.000Z" },
    });
    await openSettingsTab();

    fireEvent.change(screen.getByLabelText(/brute-force/i), { target: { value: "3" } });
    const saveButtons = screen.getAllByRole("button", { name: /^save$/i });
    fireEvent.click(saveButtons[saveButtons.length - 1]);

    await waitFor(() =>
      expect(api.updateDetectionSettings).toHaveBeenCalledWith("proj-1", {
        bruteForceThreshold: 3,
        highRequestRateThreshold: 50,
        credentialStuffingMinIps: 5,
      })
    );
    await waitFor(() => expect(screen.getByLabelText(/brute-force/i)).toHaveValue(3));
  });

  it("reset restores the defaults after confirmation", async () => {
    vi.mocked(api.getDetectionSettings).mockResolvedValue({
      settings: { ...defaultSettings, bruteForceThreshold: 2 },
    });
    vi.mocked(api.resetDetectionSettings).mockResolvedValue({ settings: defaultSettings });
    await openSettingsTab();

    await waitFor(() => expect(screen.getByLabelText(/brute-force/i)).toHaveValue(2));
    fireEvent.click(screen.getByRole("button", { name: /reset to defaults/i }));

    expect(window.confirm).toHaveBeenCalled();
    await waitFor(() => expect(api.resetDetectionSettings).toHaveBeenCalledWith("proj-1"));
    await waitFor(() => expect(screen.getByLabelText(/brute-force/i)).toHaveValue(5));
  });
});
