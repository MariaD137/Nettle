import { describe, it, expect, vi, beforeEach } from "vitest";
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
    api: { verifyEmail: vi.fn() },
  };
});

import { api, ApiError } from "../api";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/verify-email" element={<VerifyEmailPage />} />
      </Routes>
    </MemoryRouter>
  );
}

describe("VerifyEmailPage", () => {
  beforeEach(() => {
    vi.mocked(api.verifyEmail).mockReset();
    refreshUser.mockReset();
  });

  it("verifies a real token and refreshes the current user", async () => {
    vi.mocked(api.verifyEmail).mockResolvedValue({ message: "Email verified", user: {} as any });
    renderAt("/verify-email?token=realtoken123");

    await waitFor(() => expect(screen.getByText("Email verified")).toBeInTheDocument());
    expect(api.verifyEmail).toHaveBeenCalledWith("realtoken123");
    expect(refreshUser).toHaveBeenCalled();
  });

  it("shows the real server error for an invalid or expired token", async () => {
    vi.mocked(api.verifyEmail).mockRejectedValue(new ApiError(400, "Invalid or expired verification link"));
    renderAt("/verify-email?token=badtoken");

    await waitFor(() => expect(screen.getByText("Invalid or expired verification link")).toBeInTheDocument());
  });

  it("shows an error immediately when there's no token in the URL, without calling the API", () => {
    renderAt("/verify-email");

    expect(screen.getByText("Couldn't verify your email")).toBeInTheDocument();
    expect(api.verifyEmail).not.toHaveBeenCalled();
  });
});
