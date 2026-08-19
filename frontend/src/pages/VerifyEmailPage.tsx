import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../api";
import { useAuth } from "../AuthContext";

export default function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const { refreshUser } = useAuth();
  const [status, setStatus] = useState<"verifying" | "done" | "error">(token ? "verifying" : "error");
  const [error, setError] = useState<string | null>(token ? null : "No verification token was provided.");

  useEffect(() => {
    if (!token) return;
    api
      .verifyEmail(token)
      .then(() => {
        setStatus("done");
        refreshUser();
      })
      .catch((err) => {
        setStatus("error");
        setError(err instanceof ApiError ? err.message : "Something went wrong");
      });
    // Runs once for the token this page loaded with — a token is single-use
    // server-side anyway, so re-running this on unrelated re-renders would
    // just surface a confusing "invalid or expired" the second time.
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
