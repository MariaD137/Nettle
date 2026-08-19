import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import LoginPage from "./LoginPage";
import { ApiError } from "../api";
import type { User } from "../api";

const baseUser: User = {
  id: "user-1",
  email: "a@b.com",
  plan: "tier1",
  stripeCustomerId: "cus_1",
  subscriptionStatus: "active",
  emailVerifiedAt: "2026-01-01T00:00:00.000Z",
  createdAt: "2026-01-01T00:00:00.000Z",
};

let mockUser: User | null = null;
const login = vi.fn();
const signup = vi.fn();

vi.mock("../AuthContext", () => ({
  useAuth: () => ({ user: mockUser, login, signup }),
}));

function renderAt(path = "/login") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div>Home page marker</div>} />
      </Routes>
    </MemoryRouter>
  );
}

// The submit button's own text changes with mode ("Create account" /
// "Log in") and, once in login mode, is identical to the "Log in" tab
// label — getByRole('button', {name: 'Log in'}) would then match both and
// throw. The tab buttons are explicitly type="button"; the real submit is
// the form's own type="submit" element, so target that directly rather
// than by accessible name.
function submitButton(container: HTMLElement): HTMLButtonElement {
  const button = container.querySelector('form button[type="submit"]');
  if (!button) throw new Error("submit button not found");
  return button as HTMLButtonElement;
}

function fillAndSubmit(container: HTMLElement, email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: password } });
  fireEvent.click(submitButton(container));
}

describe("LoginPage", () => {
  beforeEach(() => {
    mockUser = null;
    login.mockReset();
    signup.mockReset();
  });

  it("redirects to / when already authenticated (protected-route behavior)", () => {
    mockUser = baseUser;
    renderAt();
    expect(screen.getByText("Home page marker")).toBeInTheDocument();
    expect(login).not.toHaveBeenCalled();
    expect(signup).not.toHaveBeenCalled();
  });

  it("defaults to signup mode and calls signup on submit", async () => {
    signup.mockResolvedValue(undefined);
    const { container } = renderAt();

    fillAndSubmit(container, "new@example.com", "correct horse battery staple");

    await waitFor(() => expect(signup).toHaveBeenCalledWith("new@example.com", "correct horse battery staple"));
    expect(login).not.toHaveBeenCalled();
  });

  it("switching to the Log in tab calls login, not signup, on submit", async () => {
    login.mockResolvedValue(undefined);
    const { container } = renderAt();

    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    fillAndSubmit(container, "existing@example.com", "correct horse battery staple");

    await waitFor(() => expect(login).toHaveBeenCalledWith("existing@example.com", "correct horse battery staple"));
    expect(signup).not.toHaveBeenCalled();
  });

  it("shows a loading state while the request is in flight, and disables the submit button", async () => {
    let resolveLogin!: () => void;
    login.mockReturnValue(new Promise<void>((resolve) => { resolveLogin = resolve; }));
    const { container } = renderAt();

    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    fillAndSubmit(container, "slow@example.com", "correct horse battery staple");

    const button = await screen.findByRole("button", { name: /please wait/i });
    expect(button).toBeDisabled();

    resolveLogin();
    await waitFor(() => expect(screen.getByText("Home page marker")).toBeInTheDocument());
  });

  it("navigates to / after a successful login", async () => {
    login.mockResolvedValue(undefined);
    const { container } = renderAt();

    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    fillAndSubmit(container, "worked@example.com", "correct horse battery staple");

    await waitFor(() => expect(screen.getByText("Home page marker")).toBeInTheDocument());
  });

  it("shows the real server error for a failed login instead of a generic message", async () => {
    login.mockRejectedValue(new ApiError(401, "Invalid email or password"));
    const { container } = renderAt();

    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    fillAndSubmit(container, "wrong@example.com", "wrongpassword");

    await waitFor(() => expect(screen.getByText("Invalid email or password")).toBeInTheDocument());
    expect(screen.queryByText("Home page marker")).not.toBeInTheDocument();
  });

  it("shows a generic fallback for a non-API error (e.g. a network failure)", async () => {
    login.mockRejectedValue(new Error("network exploded"));
    const { container } = renderAt();

    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    fillAndSubmit(container, "offline@example.com", "correct horse battery staple");

    await waitFor(() => expect(screen.getByText("Something went wrong. Try again.")).toBeInTheDocument());
  });
});
