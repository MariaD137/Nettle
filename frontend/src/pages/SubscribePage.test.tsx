import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SubscribePage from "./SubscribePage";
import { api, ApiError } from "../api";
import type { User } from "../api";

const baseUser: User = {
  id: "user-1",
  email: "a@b.com",
  plan: "free",
  stripeCustomerId: null,
  subscriptionStatus: "none",
  emailVerifiedAt: "2026-01-01T00:00:00.000Z",
  createdAt: "2026-01-01T00:00:00.000Z",
};

let mockUser: User | null = baseUser;
const logout = vi.fn();
const refreshUser = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ user: mockUser, logout, refreshUser }),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: { createCheckoutSession: vi.fn() },
  };
});

function renderPage() {
  return render(
    <MemoryRouter>
      <SubscribePage />
    </MemoryRouter>
  );
}

describe("SubscribePage", () => {
  beforeEach(() => {
    mockUser = baseUser;
    logout.mockReset();
    refreshUser.mockReset();
    vi.mocked(api.createCheckoutSession).mockReset();
    delete (window as any).location;
    (window as any).location = { href: "" };
  });

  it("renders the plan choices without crashing even before the user has loaded", () => {
    mockUser = null;
    renderPage();
    expect(screen.getByRole("button", { name: "Choose Tier 1" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Choose Tier 2" })).toBeInTheDocument();
  });

  it("choosing a plan sends only the plan id to the server — there is no client field for price or amount", async () => {
    vi.mocked(api.createCheckoutSession).mockResolvedValue({ url: "https://checkout.stripe.com/session/test" });
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Choose Tier 1" }));

    await waitFor(() => expect(api.createCheckoutSession).toHaveBeenCalledWith("tier1"));
  });

  it("shows a loading state on the clicked button and disables both while checkout is starting", async () => {
    let resolveCheckout!: (v: { url: string }) => void;
    vi.mocked(api.createCheckoutSession).mockReturnValue(new Promise((resolve) => { resolveCheckout = resolve; }));
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Choose Tier 1" }));

    expect(await screen.findByRole("button", { name: "Opening checkout…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Choose Tier 2" })).toBeDisabled();

    resolveCheckout({ url: "https://checkout.stripe.com/session/test" });
    await waitFor(() => expect(window.location.href).toBe("https://checkout.stripe.com/session/test"));
  });

  it("redirects the browser to the real Stripe checkout URL on success", async () => {
    vi.mocked(api.createCheckoutSession).mockResolvedValue({ url: "https://checkout.stripe.com/session/abc123" });
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Choose Tier 2" }));

    await waitFor(() => expect(window.location.href).toBe("https://checkout.stripe.com/session/abc123"));
  });

  it("shows the real server error when checkout fails to start", async () => {
    vi.mocked(api.createCheckoutSession).mockRejectedValue(new ApiError(503, "Billing is not available"));
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Choose Tier 1" }));

    await waitFor(() => expect(screen.getByText("Billing is not available")).toBeInTheDocument());
    // The button re-enables so the user can retry rather than being stuck.
    expect(screen.getByRole("button", { name: "Choose Tier 1" })).not.toBeDisabled();
  });

  it("shows a generic fallback for a non-API failure", async () => {
    vi.mocked(api.createCheckoutSession).mockRejectedValue(new Error("network exploded"));
    renderPage();

    fireEvent.click(screen.getByRole("button", { name: "Choose Tier 1" }));

    await waitFor(() => expect(screen.getByText("Couldn't start checkout. Please try again.")).toBeInTheDocument());
  });

  it("shows lapsed-subscription copy for a past_due or canceled account", () => {
    mockUser = { ...baseUser, plan: "tier1", subscriptionStatus: "past_due" };
    renderPage();
    expect(screen.getByText("Your subscription has lapsed")).toBeInTheDocument();
  });

  it("the 'Refresh your plan' link re-checks the current user rather than reloading the page", () => {
    renderPage();
    fireEvent.click(screen.getByRole("button", { name: "Refresh your plan" }));
    expect(refreshUser).toHaveBeenCalled();
  });
});
