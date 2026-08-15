import { useState } from "react";
import { useAuth } from "../AuthContext";
import { api, ApiError } from "../api";
import { PLANS } from "../plans";

/**
 * The paywall. Every account lands here after signing up and stays here until
 * a subscription is active — there is no free tier behind it, so this page
 * has to carry the whole pitch rather than act as an upsell nudge.
 */
export default function SubscribePage() {
  const { user, logout, refreshUser } = useAuth();
  const [starting, setStarting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function choose(plan: "tier1" | "tier2") {
    setError(null);
    setStarting(plan);
    try {
      const { url } = await api.createCheckoutSession(plan);
      window.location.href = url;
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : "Couldn't start checkout. Please try again."
      );
      setStarting(null);
    }
  }

  // Covers the case where the webhook lands while the user is sitting here.
  async function recheck() {
    refreshUser();
  }

  const lapsed = user?.subscriptionStatus === "past_due" || user?.subscriptionStatus === "canceled";

  return (
    <div className="shell">
      <div className="topbar">
        <span className="brand">nettle</span>
        <div className="topbar-right">
          {user && <span>{user.email}</span>}
          <button className="link-btn" onClick={() => logout()}>Log out</button>
        </div>
      </div>

      <div className="paywall-intro">
        <h1>{lapsed ? "Your subscription has lapsed" : "Choose a plan to continue"}</h1>
        <p className="muted">
          {lapsed
            ? "Renew to get back into your dashboard. Your projects and scan history are exactly where you left them."
            : "Your account is created. Pick a plan to open your dashboard and run your first scan."}
        </p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="plan-grid">
        {PLANS.map((plan) => (
          <div key={plan.id} className={`plan-card ${plan.highlight ? "plan-card-highlight" : ""}`}>
            {plan.highlight && <span className="plan-flag">Most complete</span>}
            <h2>{plan.name}</h2>
            <p className="plan-tagline">{plan.tagline}</p>
            <div className="plan-price">
              <span className="plan-price-amount">{plan.price}</span>
              <span className="muted">{plan.cadence}</span>
            </div>
            <ul className="plan-features">
              {plan.features.map((f) => (
                <li key={f}>
                  <span className="passed-icon" aria-hidden="true">&#10003;</span>
                  <span>{f}</span>
                </li>
              ))}
            </ul>
            <button
              className={plan.highlight ? "" : "secondary"}
              onClick={() => choose(plan.id)}
              disabled={starting !== null}
              style={{ width: "100%" }}
            >
              {starting === plan.id ? "Opening checkout…" : `Choose ${plan.name.split(" — ")[0]}`}
            </button>
          </div>
        ))}
      </div>

      <p className="muted" style={{ textAlign: "center", marginTop: 20 }}>
        Already paid? <button className="link-btn" onClick={recheck}>Refresh your plan</button>
      </p>
    </div>
  );
}
