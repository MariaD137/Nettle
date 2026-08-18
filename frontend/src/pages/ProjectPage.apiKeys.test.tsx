import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import ProjectPage from "./ProjectPage";
import type { StoredApiKey } from "../api";

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

const defaultKey: StoredApiKey = {
  id: "key-default",
  projectId: "proj-1",
  name: "Default key",
  key: "nettle_defa…lue1",
  scopes: ["scan", "events"],
  isDefault: true,
  lastUsedAt: null,
  revokedAt: null,
  createdAt: "2026-01-01T00:00:00.000Z",
};

const ciKey: StoredApiKey = {
  id: "key-ci",
  projectId: "proj-1",
  name: "CI pipeline",
  key: "nettle_ci12…3456",
  scopes: ["scan"],
  isDefault: false,
  lastUsedAt: "2026-01-05T00:00:00.000Z",
  revokedAt: null,
  createdAt: "2026-01-02T00:00:00.000Z",
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getProject: vi.fn(),
      listApiKeys: vi.fn(),
      createApiKey: vi.fn(),
      rotateApiKeyById: vi.fn(),
      revokeApiKey: vi.fn(),
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

describe("ProjectPage API keys (Settings tab)", () => {
  beforeEach(() => {
    vi.mocked(api.getProject).mockReset().mockResolvedValue({
      project: mockProject,
      badge: { status: "caution", label: "Caution", lastScannedAt: null, score: null },
      latestScan: null,
      alertCounts: { new: 0, acknowledged: 0, resolved: 0, false_positive: 0 },
    } as any);
    vi.mocked(api.listApiKeys).mockReset().mockResolvedValue({ apiKeys: [defaultKey, ciKey] });
    vi.mocked(api.createApiKey).mockReset();
    vi.mocked(api.rotateApiKeyById).mockReset();
    vi.mocked(api.revokeApiKey).mockReset();
  });

  async function openSettingsTab() {
    renderProjectPage();
    await waitFor(() => expect(screen.getByText("My App")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
    await waitFor(() => expect(screen.getByText("API keys")).toBeInTheDocument());
  }

  it("lists every key, masked, with scopes and last-used", async () => {
    await openSettingsTab();

    expect(screen.getByText("Default key")).toBeInTheDocument();
    expect(screen.getByText("nettle_defa…lue1")).toBeInTheDocument();
    expect(screen.getByText("CI pipeline")).toBeInTheDocument();
    expect(screen.getByText("nettle_ci12…3456")).toBeInTheDocument();
    expect(screen.getByText(/Scan, Events/)).toBeInTheDocument();
    expect(screen.getByText(/Last used never/)).toBeInTheDocument();
  });

  it("creating a key reveals the full value once and never again after dismissing it", async () => {
    vi.mocked(api.createApiKey).mockResolvedValue({
      apiKey: { ...ciKey, id: "key-new", name: "New key", key: "nettle_full_secret_value_shown_once" },
    });
    await openSettingsTab();

    fireEvent.click(screen.getByRole("button", { name: /new key/i }));
    fireEvent.change(screen.getByPlaceholderText(/e.g. CI pipeline/i), { target: { value: "New key" } });
    fireEvent.click(screen.getByRole("button", { name: /create key/i }));

    await waitFor(() => expect(screen.getByText("nettle_full_secret_value_shown_once")).toBeInTheDocument());
    expect(api.createApiKey).toHaveBeenCalledWith("proj-1", "New key", ["scan", "events"]);

    fireEvent.click(screen.getByRole("button", { name: /hide it/i }));
    await waitFor(() => expect(screen.queryByText("nettle_full_secret_value_shown_once")).not.toBeInTheDocument());
  });

  it("unchecking a scope before creating only requests the remaining scope(s)", async () => {
    vi.mocked(api.createApiKey).mockResolvedValue({ apiKey: { ...ciKey, id: "key-new" } });
    await openSettingsTab();

    fireEvent.click(screen.getByRole("button", { name: /new key/i }));
    fireEvent.change(screen.getByPlaceholderText(/e.g. CI pipeline/i), { target: { value: "Events only" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /scan/i }));
    fireEvent.click(screen.getByRole("button", { name: /create key/i }));

    await waitFor(() => expect(api.createApiKey).toHaveBeenCalledWith("proj-1", "Events only", ["events"]));
  });

  it("rotating a key confirms, reveals the new value, and refreshes the list", async () => {
    vi.mocked(api.rotateApiKeyById).mockResolvedValue({
      apiKey: { ...ciKey, key: "nettle_freshly_rotated_secret" },
    });
    await openSettingsTab();

    const rotateButtons = screen.getAllByRole("button", { name: /^rotate$/i });
    fireEvent.click(rotateButtons[0]);

    expect(window.confirm).toHaveBeenCalled();
    await waitFor(() => expect(screen.getByText("nettle_freshly_rotated_secret")).toBeInTheDocument());
    expect(api.listApiKeys).toHaveBeenCalledTimes(2); // initial load + refresh after rotate
  });

  it("revoking a key shows it as revoked and hides its rotate/revoke actions", async () => {
    vi.mocked(api.revokeApiKey).mockResolvedValue({
      apiKey: { ...ciKey, revokedAt: "2026-02-01T00:00:00.000Z" },
    });
    vi.mocked(api.listApiKeys)
      .mockResolvedValueOnce({ apiKeys: [defaultKey, ciKey] })
      .mockResolvedValueOnce({ apiKeys: [defaultKey, { ...ciKey, revokedAt: "2026-02-01T00:00:00.000Z" }] });
    await openSettingsTab();

    const revokeButtons = screen.getAllByRole("button", { name: /^revoke$/i });
    fireEvent.click(revokeButtons[revokeButtons.length - 1]);

    await waitFor(() => expect(screen.getByText("Revoked")).toBeInTheDocument());
    expect(screen.getAllByRole("button", { name: /^revoke$/i }).length).toBe(1); // only the still-active default key
  });
});
