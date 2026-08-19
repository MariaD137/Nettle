import { describe, it, expect, vi, beforeEach } from "vitest";
import { StrictMode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import VerifyEmailPage from "./VerifyEmailPage";

const refreshUser = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ refreshUser }),
}));

vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return {
    ...actual,
    api: { verifyEmail: vi.fn(), me: vi.fn() },
  };
});

import { api, ApiError } from "../api";

function renderAt(path: string, { strict = false } = {}) {
  const tree = (
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/verify-email" element={<VerifyEmailPage />} />
      </Routes>
    </MemoryRouter>
  );
  return render(strict ? <StrictMode>{tree}</StrictMode> : tree);
}

describe("VerifyEmailPage", () => {
  beforeEach(() => {
    vi.mocked(api.verifyEmail).mockReset();
    vi.mocked(api.me).mockReset();
    refreshUser.mockReset();
  });

  it("verifies a real token and refreshes the current user", async () => {
    vi.mocked(api.verifyEmail).mockResolvedValue({ message: "Email verified", user: {} as any });
    renderAt("/verify-email?token=realtoken123");

    await waitFor(() => expect(screen.getByText("Email verified")).toBeInTheDocument());
    expect(api.verifyEmail).toHaveBeenCalledWith("realtoken123");
    expect(refreshUser).toHaveBeenCalled();
  });

  it("shows the real server error for a token that's genuinely invalid (not signed in to fall back on)", async () => {
    vi.mocked(api.verifyEmail).mockRejectedValue(new ApiError(400, "Invalid or expired verification link"));
    vi.mocked(api.me).mockRejectedValue(new ApiError(401, "Invalid session"));
    renderAt("/verify-email?token=badtoken");

    await waitFor(() => expect(screen.getByText("Invalid or expired verification link")).toBeInTheDocument());
  });

  it("shows an error immediately when there's no token in the URL, without calling the API", () => {
    renderAt("/verify-email");

    expect(screen.getByText("Couldn't verify your email")).toBeInTheDocument();
    expect(api.verifyEmail).not.toHaveBeenCalled();
  });

  // Regression test for a real bug found by actually driving the app in a
  // browser (not caught by any prior unit test): React StrictMode's
  // deliberate dev-mode double-invoke of effects sent two verify-email
  // requests for one real click. The token is correctly single-use
  // server-side, so the second request was rejected — and the page showed
  // "Couldn't verify your email" even though the first request had just
  // genuinely succeeded.
  it("under StrictMode's double effect invocation, calls verifyEmail only once", async () => {
    vi.mocked(api.verifyEmail).mockResolvedValue({ message: "Email verified", user: {} as any });
    renderAt("/verify-email?token=realtoken123", { strict: true });

    await waitFor(() => expect(screen.getByText("Email verified")).toBeInTheDocument());
    expect(api.verifyEmail).toHaveBeenCalledTimes(1);
  });

  // Covers the production-realistic version of the same failure mode that
  // a ref guard alone can't fix: the same link opened in two tabs, or
  // clicked twice — two independent page loads, each sending its own
  // request. One succeeds, the other gets "already used." The second
  // load's failure handler checks the real current account state before
  // showing an error, and shows success instead once it sees the email
  // actually is verified.
  it("when verification fails but the account is already verified (e.g. the link was opened twice), shows success instead of a false error", async () => {
    vi.mocked(api.verifyEmail).mockRejectedValue(new ApiError(400, "Invalid or expired verification link"));
    vi.mocked(api.me).mockResolvedValue({
      user: { emailVerifiedAt: "2026-01-01T00:00:00.000Z" } as any,
    });
    renderAt("/verify-email?token=alreadyused");

    await waitFor(() => expect(screen.getByText("Email verified")).toBeInTheDocument());
    expect(screen.queryByText("Couldn't verify your email")).not.toBeInTheDocument();
  });
});
