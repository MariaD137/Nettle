import { Link } from "react-router-dom";

export default function BillingResultPage({ outcome }: { outcome: "success" | "cancelled" }) {
  return (
    <div className="shell" style={{ maxWidth: 400, textAlign: "center", paddingTop: 80 }}>
      <h1>{outcome === "success" ? "You're upgraded" : "Checkout cancelled"}</h1>
      <p className="muted">
        {outcome === "success"
          ? "Your plan is now active. It may take a few seconds for the dashboard to reflect it."
          : "No changes were made to your plan."}
      </p>
      <Link to="/" className="button">
        Back to dashboard
      </Link>
    </div>
  );
}
