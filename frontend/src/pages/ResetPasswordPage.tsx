import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../api";

export default function ResetPasswordPage() {
  const [params] = useSearchParams();
  const token = params.get("token");

  if (token) return <ResetForm token={token} />;
  return <ForgotForm />;
}

function ForgotForm() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.forgotPassword(email);
      setSent(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  if (sent) {
    return (
      <div className="shell" style={{ maxWidth: 400 }}>
        <h1>Check your email</h1>
        <p className="muted">If that email is registered, we've sent a password reset link.</p>
        <Link to="/login" className="button">
          Back to login
        </Link>
      </div>
    );
  }

  return (
    <div className="shell" style={{ maxWidth: 400 }}>
      <h1>Reset password</h1>
      <p className="muted" style={{ marginBottom: 24 }}>
        Enter your email and we'll send a reset link.
      </p>

      {error && <div className="error-banner">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="email">Email</label>
          <input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? "Sending…" : "Send reset link"}
        </button>
      </form>

      <p style={{ marginTop: 16 }}>
        <Link to="/login">Back to login</Link>
      </p>
    </div>
  );
}

function ResetForm({ token }: { token: string }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match");
      return;
    }

    setSubmitting(true);
    try {
      await api.resetPassword(token, password);
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  if (done) {
    return (
      <div className="shell" style={{ maxWidth: 400 }}>
        <h1>Password reset</h1>
        <p className="muted">Your password has been updated. You can now log in.</p>
        <Link to="/login" className="button">
          Log in
        </Link>
      </div>
    );
  }

  return (
    <div className="shell" style={{ maxWidth: 400 }}>
      <h1>Set new password</h1>

      {error && <div className="error-banner">{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor="password">New password</label>
          <input
            id="password"
            type="password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="confirm">Confirm password</label>
          <input
            id="confirm"
            type="password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? "Resetting…" : "Reset password"}
        </button>
      </form>
    </div>
  );
}
