import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api, ApiError, type Organization } from "../api";
import NettleLogo from "../components/NettleLogo";

/**
 * Reachable signed out — the invited person may not have a Nettle account
 * yet, or may not be logged in on this device. The token lives in the URL
 * (same pattern as ResetPasswordPage), so an inline login/signup form here
 * (rather than redirecting to /login and losing the query string) is what
 * keeps the token attached through auth. Once `user` is set, acceptance
 * runs automatically — the organization and role are never client-supplied,
 * both come back from the server (see backend/src/organizations/invitations.ts).
 */
export default function AcceptInvitationPage() {
  const [params] = useSearchParams();
  const token = params.get("token");
  const { user, loading, login, signup } = useAuth();
  const [result, setResult] = useState<Organization | "pending" | "done" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const attempted = useRef(false);

  useEffect(() => {
    if (!token || !user || attempted.current) return;
    attempted.current = true;
    setResult("pending");
    api
      .acceptInvitation(token)
      .then(({ organization }) => setResult(organization ?? "done"))
      .catch((err) => {
        setResult(null);
        setError(err instanceof ApiError ? err.message : "Couldn't accept invitation");
      });
  }, [token, user]);

  if (!token) {
    return (
      <div className="shell" style={{ maxWidth: 400 }}>
        <h1>Invalid invitation link</h1>
        <p className="muted">This link is missing its invitation token.</p>
        <Link to="/" className="button">Go home</Link>
      </div>
    );
  }

  if (loading) {
    return <div className="shell muted">Loading…</div>;
  }

  if (!user) {
    return <InlineAuthForm login={login} signup={signup} />;
  }

  if (error) {
    return (
      <div className="shell" style={{ maxWidth: 400 }}>
        <h1>Couldn't accept invitation</h1>
        <div className="error-banner">{error}</div>
        <Link to="/" className="button">Go to dashboard</Link>
      </div>
    );
  }

  if (result === "pending" || result === null) {
    return <div className="shell muted">Accepting invitation…</div>;
  }

  if (result === "done") {
    return (
      <div className="shell" style={{ maxWidth: 400 }}>
        <h1>Invitation accepted</h1>
        <Link to="/organizations" className="button">View organizations</Link>
      </div>
    );
  }

  return (
    <div className="shell" style={{ maxWidth: 400 }}>
      <h1>You've joined {result.name}</h1>
      <p className="muted">You now have access to this organization's shared projects.</p>
      <Link to={`/organizations/${result.id}`} className="button">View organization</Link>
    </div>
  );
}

function InlineAuthForm({
  login,
  signup,
}: {
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string) => Promise<void>;
}) {
  const [mode, setMode] = useState<"login" | "signup">("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (mode === "signup") await signup(email, password);
      else await login(email, password);
      // Acceptance runs automatically once `user` is set (see the effect above).
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong. Try again.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-landing">
      <div className="auth-header">
        <NettleLogo size={92} />
        <h1 className="auth-wordmark">nettle</h1>
        <p className="muted auth-tagline">Log in or create an account to accept this organization invitation.</p>
      </div>

      <div className="tabs">
        <button className={`tab ${mode === "signup" ? "active" : ""}`} onClick={() => setMode("signup")} type="button">
          Sign up
        </button>
        <button className={`tab ${mode === "login" ? "active" : ""}`} onClick={() => setMode("login")} type="button">
          Log in
        </button>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="ai-email">Email</label>
          <input id="ai-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="ai-password">Password</label>
          <input
            id="ai-password"
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? "Please wait…" : mode === "signup" ? "Create account" : "Log in"}
        </button>
      </form>
    </div>
  );
}
