import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act } from "@testing-library/react";
import { AuthProvider, useAuth } from "./AuthContext";
import { api, setToken } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: {
      me: vi.fn(),
      login: vi.fn(),
      signup: vi.fn(),
      logout: vi.fn(),
    },
  };
});

function TestConsumer() {
  const { user, loading } = useAuth();
  if (loading) return <div>loading</div>;
  return <div>{user ? user.email : "logged-out"}</div>;
}

describe("AuthProvider", () => {
  beforeEach(() => {
    vi.mocked(api.me).mockReset();
    vi.mocked(api.login).mockReset();
    vi.mocked(api.logout).mockReset();
    localStorage.clear();
  });

  it("shows loading then the user email when me() succeeds", async () => {
    vi.mocked(api.me).mockResolvedValue({
      user: { id: "1", email: "a@b.com", plan: "free", stripeCustomerId: null, subscriptionStatus: "none", createdAt: "" },
    });

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );

    expect(screen.getByText("loading")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("a@b.com")).toBeInTheDocument());
  });

  it("shows logged-out when me() fails", async () => {
    vi.mocked(api.me).mockRejectedValue(new Error("401"));

    render(
      <AuthProvider>
        <TestConsumer />
      </AuthProvider>
    );

    await waitFor(() => expect(screen.getByText("logged-out")).toBeInTheDocument());
  });
});

describe("useAuth outside provider", () => {
  it("throws when used without AuthProvider", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => render(<TestConsumer />)).toThrow("useAuth must be used within AuthProvider");
    spy.mockRestore();
  });
});
