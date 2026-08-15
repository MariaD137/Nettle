import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { ApiError } from "../api";
import NettleLogo from "../components/NettleLogo";

export default function LoginPage() {
  const { user, login, signup } = useAuth();
  const navigate = useNavigate();
  const [mode, setMode] = useState<"login" | "signup">("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (mode === "signup") await signup(email, password);
      else await login(email, password);
      navigate("/");
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
        <p className="muted auth-tagline">
          Scans AI-built apps for launch-readiness gaps, then keeps watching after they ship.
        </p>
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
          <label htmlFor="email">Email</label>
          <input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
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

      {mode === "login" && (
        <p style={{ marginTop: 16, textAlign: "center" }}>
          <Link to="/reset-password">Forgot password?</Link>
        </p>
      )}
    </div>
  );
}
