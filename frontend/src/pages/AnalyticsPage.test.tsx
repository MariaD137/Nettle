import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { AnalyticsPage } from "./AnalyticsPage";

// Regression coverage for a real crash: the backend used to send
// model_status: null for any project with no trained ML model — the
// default state for every project, since nothing trains one automatically.
// ModelStatus read status.is_active with no null guard and no error
// boundary above it, so the whole Analytics page rendered blank white.
// The backend now always sends a real fallback object, but this suite
// covers the frontend staying resilient even if that ever regresses.

const baseDashboard = {
  metrics: { request_count: 120, error_rate: 2.5, request_baseline: 100, error_baseline: 2 },
  anomalies: [],
  model_status: { model_type: null, is_active: false, trained_at: null, training_samples: 0, accuracy: null },
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      getAnalyticsDashboard: vi.fn(),
      getAnalyticsBaselines: vi.fn(),
      calculateBaselines: vi.fn(),
    },
  };
});

import { api } from "../api";

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/proj-1/analytics"]}>
      <Routes>
        <Route path="/projects/:projectId/analytics" element={<AnalyticsPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("AnalyticsPage", () => {
  beforeEach(() => {
    vi.mocked(api.getAnalyticsDashboard).mockReset().mockResolvedValue(baseDashboard as any);
    vi.mocked(api.getAnalyticsBaselines).mockReset().mockResolvedValue({ baselines: [] } as any);
    vi.mocked(api.calculateBaselines).mockReset();
  });

  it("renders a real 'not trained' status instead of crashing when the model has never been trained", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("ML Model Status")).toBeInTheDocument());
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument(); // training samples
  });

  it("does not crash and renders nothing extra when model_status itself is missing from the response", async () => {
    vi.mocked(api.getAnalyticsDashboard).mockResolvedValue({ ...baseDashboard, model_status: null } as any);
    renderPage();
    await waitFor(() => expect(screen.getByText("Request Rate")).toBeInTheDocument());
    expect(screen.queryByText("ML Model Status")).not.toBeInTheDocument();
  });

  it("renders real trained-model data when a model is active", async () => {
    vi.mocked(api.getAnalyticsDashboard).mockResolvedValue({
      ...baseDashboard,
      model_status: { model_type: "isolation_forest", is_active: true, trained_at: "2026-02-01T00:00:00.000Z", training_samples: 500, accuracy: 0.87 },
    } as any);
    renderPage();
    await waitFor(() => expect(screen.getByText("Active")).toBeInTheDocument());
    expect(screen.getByText("500")).toBeInTheDocument();
    expect(screen.getByText("87.0%")).toBeInTheDocument();
  });
});
