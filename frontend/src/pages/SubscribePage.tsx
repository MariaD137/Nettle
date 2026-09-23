import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { api, ApiError } from "../api";
import { PLANS } from "../plans";
import { entitledPlan } from "../subscription";
import NettleLogo from "../components/NettleLogo";

/**
 * The plan picker. No longer a forced landing page every account is stuck
 * behind until it pays (FREE is a real, usable dashboard tier now — see
 * billing/entitlements.ts) — this is a voluntary destination reached via an
 * "Upgrade" link from the dashboard, or the redirect a lapsed subscription
 * still gets pointed at from BillingResultPage/paywalled-feature prompts.
 */
export default function SubscribePage() {
  const { user, logout, refreshUser } = useAuth();
  const navigate = useNavigate();
  const [starting, setStarting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function choose(plan: "build" | "protect") {
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

  const currentPlan = entitledPlan(user);
  const lapsed = user?.subscriptionStatus === "past_due" || user?.subscriptionStatus === "canceled";

  return (
    <div className="shell paywall-shell">
      <div className="topbar">
        <span className="brand"><NettleLogo size={22} title="" />nettle</span>
        <div className="topbar-right">
          {user && <span>{user.email}</span>}
          <button className="link-btn" onClick={() => logout()}>Log out</button>
        </div>
      </div>

      <div className="paywall-intro">
        <h1>{lapsed ? "Your subscription has lapsed" : "Choose a plan"}</h1>
        <p className="muted">
          {lapsed
            ? "Renew to pick up BUILD or PROTECT features again. Your projects and scan history are exactly where you left them."
            : "BUILD and PROTECT unlock real scans, the Fix Center, and scan history. Free stays free for exploring Nettle's control library."}
        </p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="plan-grid">
        {PLANS.map((plan) => {
          const isCurrent = plan.id === currentPlan && plan.id !== "free";
          return (
            <div key={plan.id} className={`plan-card ${plan.highlight ? "plan-card-highlight" : ""}`}>
              {plan.badge && !isCurrent && <span className="plan-flag">{plan.badge}</span>}
              {isCurrent && <span className="plan-flag">Current plan</span>}
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
                {plan.excluded?.map((f) => (
                  <li key={f} className="muted">
                    <span aria-hidden="true">&#10005;</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              {plan.id === "free" ? (
                <button className="secondary" onClick={() => navigate("/")} style={{ width: "100%" }}>
                  {plan.cta}
                </button>
              ) : (
                <button
                  className={plan.highlight ? "" : "secondary"}
                  onClick={() => choose(plan.id as "build" | "protect")}
                  disabled={starting !== null || isCurrent}
                  style={{ width: "100%" }}
                >
                  {isCurrent ? "Current plan" : starting === plan.id ? "Opening checkout…" : plan.cta}
                </button>
              )}
            </div>
          );
        })}
      </div>

      <p className="muted" style={{ textAlign: "center", marginTop: 20 }}>
        Already paid? <button className="link-btn" onClick={recheck}>Refresh your plan</button>
      </p>
    </div>
  );
}
