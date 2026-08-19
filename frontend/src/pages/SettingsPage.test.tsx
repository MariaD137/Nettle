import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SettingsPage from "./SettingsPage";
import type { User } from "../api";

// jsdom doesn't implement matchMedia — SettingsPage's useIsMobile() needs it.
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

const baseUser: User = {
  id: "user-1",
  email: "a@b.com",
  plan: "tier1",
  stripeCustomerId: "cus_1",
  subscriptionStatus: "active",
  emailVerifiedAt: "2026-01-01T00:00:00.000Z",
  createdAt: "2026-01-01T00:00:00.000Z",
};

let mockUser: User = baseUser;
const logout = vi.fn();
const refreshUser = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ user: mockUser, logout, refreshUser }),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: {
      createPortalSession: vi.fn(),
      listSessions: vi.fn(),
      resendVerification: vi.fn(),
    },
  };
});

import { api, ApiError } from "../api";

function renderPage() {
  return render(
    <MemoryRouter>
      <SettingsPage />
    </MemoryRouter>
  );
}

describe("SettingsPage billing card", () => {
  beforeEach(() => {
    mockUser = baseUser;
    vi.mocked(api.createPortalSession).mockReset();
    vi.mocked(api.listSessions).mockReset().mockResolvedValue({ sessions: [] });
    vi.mocked(api.resendVerification).mockReset();
    // jsdom throws on unimplemented navigation; the button under test sets
    // this directly rather than calling a router API, so this just needs
    // to not blow up when the assignment happens.
    delete (window as any).location;
    (window as any).location = { href: "" };
  });

  it("shows a Manage billing button for a paid user and redirects to the real portal URL", async () => {
    vi.mocked(api.createPortalSession).mockResolvedValue({ url: "https://billing.stripe.com/session/test" });
    renderPage();

    const button = await screen.findByRole("button", { name: "Manage billing" });
    fireEvent.click(button);

    await waitFor(() => expect(window.location.href).toBe("https://billing.stripe.com/session/test"));
  });

  it("shows a past-due warning when the subscription is past_due", async () => {
    mockUser = { ...baseUser, subscriptionStatus: "past_due" };
    renderPage();

    await waitFor(() =>
      expect(screen.getByText(/last payment didn't go through/i)).toBeInTheDocument()
    );
  });

  it("shows an error instead of crashing when opening the portal fails", async () => {
    vi.mocked(api.createPortalSession).mockRejectedValue(new ApiError(400, "No billing account yet — subscribe first"));
    renderPage();

    const button = await screen.findByRole("button", { name: "Manage billing" });
    fireEvent.click(button);

    await waitFor(() => expect(screen.getByText("No billing account yet — subscribe first")).toBeInTheDocument());
  });

  it("does not show the billing card for a free-plan user", async () => {
    mockUser = { ...baseUser, plan: "free", stripeCustomerId: null, subscriptionStatus: "none" };
    renderPage();

    await waitFor(() => expect(screen.getByText("Account")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Manage billing" })).not.toBeInTheDocument();
  });
});

describe("SettingsPage email verification notice", () => {
  beforeEach(() => {
    vi.mocked(api.listSessions).mockReset().mockResolvedValue({ sessions: [] });
    vi.mocked(api.resendVerification).mockReset();
  });

  it("shows nothing for an already-verified account", async () => {
    mockUser = baseUser;
    renderPage();

    await waitFor(() => expect(screen.getByText("Account")).toBeInTheDocument());
    expect(screen.queryByText(/isn't verified yet/)).not.toBeInTheDocument();
  });

  it("shows a resend prompt for an unverified account and confirms after a real send", async () => {
    mockUser = { ...baseUser, emailVerifiedAt: null };
    vi.mocked(api.resendVerification).mockResolvedValue({ message: "Verification email sent" });
    renderPage();

    const button = await screen.findByRole("button", { name: "Resend verification email" });
    fireEvent.click(button);

    await waitFor(() => expect(screen.getByText(/verification email sent/i)).toBeInTheDocument());
    expect(api.resendVerification).toHaveBeenCalled();
  });

  it("shows the real error instead of crashing when resend is rate-limited", async () => {
    mockUser = { ...baseUser, emailVerifiedAt: null };
    vi.mocked(api.resendVerification).mockRejectedValue(
      new ApiError(429, "Too many verification emails requested — try again in an hour")
    );
    renderPage();

    const button = await screen.findByRole("button", { name: "Resend verification email" });
    fireEvent.click(button);

    await waitFor(() =>
      expect(screen.getByText("Too many verification emails requested — try again in an hour")).toBeInTheDocument()
    );
  });
});

describe("SettingsPage desktop topbar", () => {
  beforeEach(() => {
    mockUser = baseUser;
    logout.mockReset();
    vi.mocked(api.listSessions).mockReset().mockResolvedValue({ sessions: [] });
  });

  it("has a working Log out button, matching Dashboard's desktop topbar", async () => {
    renderPage();

    const button = await screen.findByRole("button", { name: "Log out" });
    fireEvent.click(button);

    expect(logout).toHaveBeenCalled();
  });
});
