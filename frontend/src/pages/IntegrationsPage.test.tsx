import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { IntegrationsPage } from "./IntegrationsPage";
import type { Webhook } from "../api";

window.confirm = vi.fn(() => true);

const slackWebhook: Webhook = {
  id: "wh-slack",
  project_id: "proj-1",
  service: "slack",
  webhook_url: "https://hooks.slack.com/services/abc",
  is_active: true,
  event_types: ["scan.completed", "incident_alert"],
  created_at: "2026-01-01T00:00:00.000Z",
  updated_at: "2026-01-01T00:00:00.000Z",
};

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      listWebhooks: vi.fn(),
      createWebhook: vi.fn(),
      updateWebhook: vi.fn(),
      deleteWebhook: vi.fn(),
      testWebhook: vi.fn(),
    },
  };
});

import { api } from "../api";

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/projects/proj-1/integrations"]}>
      <Routes>
        <Route path="/projects/:projectId/integrations" element={<IntegrationsPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("IntegrationsPage", () => {
  beforeEach(() => {
    vi.mocked(api.listWebhooks).mockReset().mockResolvedValue([slackWebhook]);
    vi.mocked(api.createWebhook).mockReset();
    vi.mocked(api.updateWebhook).mockReset();
    vi.mocked(api.deleteWebhook).mockReset();
    vi.mocked(api.testWebhook).mockReset();
  });

  it("lists configured webhooks with their service, url, and subscribed events", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("slack")).toBeInTheDocument());
    expect(screen.getByText("https://hooks.slack.com/services/abc")).toBeInTheDocument();
    expect(screen.getByText("scan.completed")).toBeInTheDocument();
    expect(screen.getByText("incident_alert")).toBeInTheDocument();
  });

  it("shows an empty state when no webhooks are configured", async () => {
    vi.mocked(api.listWebhooks).mockResolvedValue([]);
    renderPage();
    await waitFor(() => expect(screen.getByText(/No webhooks configured yet/i)).toBeInTheDocument());
  });

  it("creating a webhook sends the selected service, url, and event types", async () => {
    vi.mocked(api.listWebhooks).mockResolvedValueOnce([]).mockResolvedValueOnce([slackWebhook]);
    vi.mocked(api.createWebhook).mockResolvedValue(slackWebhook);
    renderPage();
    await waitFor(() => expect(screen.getByText(/No webhooks configured yet/i)).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    fireEvent.change(screen.getByLabelText(/webhook url/i), {
      target: { value: "https://hooks.slack.com/services/abc" },
    });
    fireEvent.click(screen.getByRole("button", { name: /^save webhook$/i }));

    await waitFor(() =>
      expect(api.createWebhook).toHaveBeenCalledWith(
        "proj-1",
        "slack",
        "https://hooks.slack.com/services/abc",
        ["scan.completed"]
      )
    );
  });

  it("unchecking the only event type blocks submission with a validation error", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText("slack")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /add webhook/i }));
    fireEvent.change(screen.getByLabelText(/webhook url/i), { target: { value: "https://example.com/hook" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /scan\.completed/i }));
    fireEvent.click(screen.getByRole("button", { name: /^save webhook$/i }));

    await waitFor(() => expect(screen.getByText(/select at least one event type/i)).toBeInTheDocument());
    expect(api.createWebhook).not.toHaveBeenCalled();
  });

  it("toggling active calls updateWebhook with the flipped state", async () => {
    vi.mocked(api.updateWebhook).mockResolvedValue({ ...slackWebhook, is_active: false });
    renderPage();
    await waitFor(() => expect(screen.getByText("slack")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("checkbox", { name: /active/i }));

    await waitFor(() => expect(api.updateWebhook).toHaveBeenCalledWith("proj-1", "wh-slack", { is_active: false }));
  });

  it("removing a webhook confirms, then deletes it and drops it from the list", async () => {
    vi.mocked(api.deleteWebhook).mockResolvedValue(undefined);
    renderPage();
    await waitFor(() => expect(screen.getByText("slack")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /remove/i }));

    expect(window.confirm).toHaveBeenCalled();
    await waitFor(() => expect(api.deleteWebhook).toHaveBeenCalledWith("proj-1", "wh-slack"));
    await waitFor(() => expect(screen.queryByText("slack")).not.toBeInTheDocument());
  });

  it("sending a test delivery shows the resulting status message", async () => {
    vi.mocked(api.testWebhook).mockResolvedValue({ message: "Test webhook sent successfully" });
    renderPage();
    await waitFor(() => expect(screen.getByText("slack")).toBeInTheDocument());

    fireEvent.click(screen.getByRole("button", { name: /send test/i }));

    await waitFor(() => expect(screen.getByText("Test webhook sent successfully")).toBeInTheDocument());
    expect(api.testWebhook).toHaveBeenCalledWith("proj-1", "wh-slack");
  });
});
