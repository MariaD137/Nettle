import { useEffect, useState } from "react";
import { Link, Navigate } from "react-router-dom";
import { useAuth } from "../AuthContext";
import { hasActiveSubscription } from "../subscription";

// Stripe redirects here the moment checkout completes, which can beat the
// webhook that actually flips the plan. Rather than dumping the customer at a
// paywall they just paid to clear, poll /me a few times and send them onward
// as soon as the subscription shows up.
const POLL_INTERVAL_MS = 1500;
const MAX_POLLS = 8;

export default function BillingResultPage({ outcome }: { outcome: "success" | "cancelled" }) {
  const { user, refreshUser } = useAuth();
  const [polls, setPolls] = useState(0);
  const active = hasActiveSubscription(user);

  useEffect(() => {
    if (outcome !== "success" || active || polls >= MAX_POLLS) return;
    const timer = setTimeout(() => {
      refreshUser();
      setPolls((n) => n + 1);
    }, POLL_INTERVAL_MS);
    return () => clearTimeout(timer);
  }, [outcome, active, polls, refreshUser]);

  if (outcome === "success" && active) {
    return <Navigate to="/" replace />;
  }

  if (outcome === "cancelled") {
    return (
      <div className="shell" style={{ maxWidth: 420, textAlign: "center", paddingTop: 80 }}>
        <h1>Checkout cancelled</h1>
        <p className="muted">No changes were made and you have not been charged.</p>
        <Link to="/subscribe" className="button">Back to plans</Link>
      </div>
    );
  }

  const stillWaiting = polls >= MAX_POLLS;

  return (
    <div className="shell" style={{ maxWidth: 420, textAlign: "center", paddingTop: 80 }}>
      <h1>{stillWaiting ? "Payment received" : "Confirming your payment…"}</h1>
      <p className="muted">
        {stillWaiting
          ? "Your payment went through, but we haven't seen the confirmation from Stripe yet. This usually clears within a minute."
          : "One moment while we activate your plan."}
      </p>
      {stillWaiting && (
        <button onClick={() => setPolls(0)}>Check again</button>
      )}
    </div>
  );
}
