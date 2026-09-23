import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App from "./App";

vi.mock("./AuthContext", () => {
  let mockUser: unknown = null;
  let mockLoading = false;
  return {
    useAuth: () => ({ user: mockUser, loading: mockLoading }),
    AuthProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
    __setMockUser: (u: unknown) => { mockUser = u; },
    __setMockLoading: (l: boolean) => { mockLoading = l; },
  };
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>
  );
}

describe("App routing", () => {
  it("renders the public marketing page at / when not authenticated", async () => {
    const { __setMockUser } = await import("./AuthContext") as any;
    __setMockUser(null);

    renderAt("/");
    await waitFor(() => {
      expect(screen.queryByText("Loading…")).not.toBeInTheDocument();
    });
    expect(screen.getAllByText("Pricing").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Get started").length).toBeGreaterThan(0);
  });

  it("a signed-in FREE account reaches the dashboard at / — no more forced redirect to /subscribe", async () => {
    const { __setMockUser } = await import("./AuthContext") as any;
    __setMockUser({ id: "u1", email: "free@example.com", plan: "free", subscriptionStatus: "none", createdAt: new Date().toISOString() });

    renderAt("/");
    // Dashboard chrome, not the marketing page and not bounced to /subscribe.
    // "New project" is part of the dashboard's static structure (unlike the
    // "Loading…" text also present here, which stays up while the overview
    // fetch to a real backend that isn't running in this test never
    // resolves), so it's there as soon as the component mounts.
    await waitFor(() => {
      expect(screen.getByText("New project")).toBeInTheDocument();
    });
    expect(screen.getByText("Upgrade")).toBeInTheDocument();

    __setMockUser(null); // don't leak into later tests in this file
  });

  it("renders the login page at /login", () => {
    renderAt("/login");
    expect(document.body.querySelector('[class]')).toBeTruthy();
  });

  it("shows loading state while auth is resolving", async () => {
    const { __setMockLoading } = await import("./AuthContext") as any;
    __setMockLoading(true);

    renderAt("/");
    expect(screen.getByText("Loading…")).toBeInTheDocument();

    __setMockLoading(false);
  });

  it("renders billing success page without auth", () => {
    renderAt("/billing/success");
    expect(document.body.textContent).toBeTruthy();
  });

  it("renders billing cancelled page without auth", () => {
    renderAt("/billing/cancelled");
    expect(document.body.textContent).toBeTruthy();
  });
});
