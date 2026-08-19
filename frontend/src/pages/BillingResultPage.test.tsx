import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import BillingResultPage from "./BillingResultPage";
import type { User } from "../api";

const activeUser: User = {
  id: "user-1",
  email: "a@b.com",
  plan: "tier1",
  stripeCustomerId: "cus_1",
  subscriptionStatus: "active",
  emailVerifiedAt: "2026-01-01T00:00:00.000Z",
  createdAt: "2026-01-01T00:00:00.000Z",
};

const unpaidUser: User = { ...activeUser, plan: "free", subscriptionStatus: "none" };

let mockUser: User | null = null;
const refreshUser = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ user: mockUser, refreshUser }),
}));

function renderAt(outcome: "success" | "cancelled") {
  return render(
    <MemoryRouter initialEntries={[`/billing/${outcome}`]}>
      <Routes>
        <Route path={`/billing/${outcome}`} element={<BillingResultPage outcome={outcome} />} />
        <Route path="/" element={<div>Home page marker</div>} />
        <Route path="/subscribe" element={<div>Subscribe page marker</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe("BillingResultPage", () => {
  beforeEach(() => {
    mockUser = null;
    refreshUser.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("outcome=success with an already-active subscription navigates straight to /", () => {
    mockUser = activeUser;
    renderAt("success");
    expect(screen.getByText("Home page marker")).toBeInTheDocument();
  });

  it("outcome=cancelled shows the cancellation message and a way back to plans, without polling", () => {
    mockUser = unpaidUser;
    renderAt("cancelled");
    expect(screen.getByText("Checkout cancelled")).toBeInTheDocument();
    expect(screen.getByText(/have not been charged/i)).toBeInTheDocument();
    expect(refreshUser).not.toHaveBeenCalled();
  });

  it("outcome=success while not yet active shows the confirming state", () => {
    mockUser = unpaidUser;
    renderAt("success");
    expect(screen.getByText("Confirming your payment…")).toBeInTheDocument();
  });

  it("polls refreshUser on an interval, and stops after MAX_POLLS with a 'payment received' fallback", async () => {
    vi.useFakeTimers();
    mockUser = unpaidUser;
    renderAt("success");

    for (let i = 0; i < 8; i++) {
      await vi.advanceTimersByTimeAsync(1500);
    }

    expect(refreshUser).toHaveBeenCalledTimes(8);
    expect(screen.getByText("Payment received")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Check again" })).toBeInTheDocument();
  });

  it("navigates to / the moment a poll observes the subscription has become active (beats a slow webhook)", async () => {
    vi.useFakeTimers();
    mockUser = unpaidUser;
    refreshUser.mockImplementation(() => {
      mockUser = activeUser;
    });
    renderAt("success");

    expect(screen.getByText("Confirming your payment…")).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(1500);

    expect(screen.getByText("Home page marker")).toBeInTheDocument();
    expect(refreshUser).toHaveBeenCalledTimes(1);
  });

  it("'Check again' resets and restarts polling instead of leaving the page stuck", async () => {
    vi.useFakeTimers();
    mockUser = unpaidUser;
    renderAt("success");

    for (let i = 0; i < 8; i++) {
      await vi.advanceTimersByTimeAsync(1500);
    }
    expect(screen.getByText("Payment received")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Check again" }));
    expect(screen.getByText("Confirming your payment…")).toBeInTheDocument();
  });
});
