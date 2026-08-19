import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../AuthContext";

export default function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const { refreshUser } = useAuth();
  const [status, setStatus] = useState<"verifying" | "done" | "error">(token ? "verifying" : "error");
  const [error, setError] = useState<string | null>(token ? null : "No verification token was provided.");
  // Guards against React StrictMode's deliberate dev-mode double-invoke of
  // effects (mount -> unmount -> mount) — without this, a single real
  // click sends two verify calls; the token is correctly single-use
  // server-side, so the second one gets rejected and a real, successful
  // verification showed the user a false "invalid or expired" error.
  // Found by actually driving the app, not by the unit tests.
  const attempted = useRef(false);

  useEffect(() => {
    if (!token || attempted.current) return;
    attempted.current = true;
    api
      .verifyEmail(token)
      .then(() => {
        setStatus("done");
        refreshUser();
      })
      .catch(async (err) => {
        // The token is single-use, so a failure here doesn't necessarily
        // mean verification never happened — the same link opened twice
        // (two tabs, a double click) legitimately produces one success
        // and one "already used" response. Check the real current state
        // before showing a scary error for what might already be a
        // completed verification.
        try {
          const { user } = await api.me();
          if (user.emailVerifiedAt) {
            setStatus("done");
            refreshUser();
            return;
          }
        } catch {
          // Not signed in on this device/browser — fall through to the
          // real error below; there's no account state to check against.
        }
        setStatus("error");
        setError(err instanceof ApiError ? err.message : "Something went wrong");
      });
    // refreshUser is intentionally omitted — it's a new function identity
    // on every AuthProvider render, and re-running this effect for that
    // reason would hit the same double-call problem the attempted ref
    // above guards against.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  if (status === "verifying") {
    return (
      <div className="shell" style={{ maxWidth: 400, textAlign: "center", paddingTop: 80 }}>
        <h1>Verifying your email…</h1>
      </div>
    );
  }

  if (status === "done") {
    return (
      <div className="shell" style={{ maxWidth: 400, textAlign: "center", paddingTop: 80 }}>
        <h1>Email verified</h1>
        <p className="muted">Your email address has been confirmed.</p>
        <Link to="/" className="button">Continue to Nettle</Link>
      </div>
    );
  }

  return (
    <div className="shell" style={{ maxWidth: 400, textAlign: "center", paddingTop: 80 }}>
      <h1>Couldn't verify your email</h1>
      <p className="muted">{error}</p>
      <Link to="/settings" className="button">Go to account settings</Link>
    </div>
  );
}
