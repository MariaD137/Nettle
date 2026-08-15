/**
 * Plan copy for the paywall.
 *
 * PLACEHOLDER PRICING — these amounts are display-only and have not been
 * decided yet. The real charge always comes from the Stripe price IDs
 * configured on the API (STRIPE_PRICE_TIER1 / STRIPE_PRICE_TIER2); this file
 * only controls what the paywall *says*. Update both together, or customers
 * will be quoted one number and charged another.
 */
export interface PlanCopy {
  id: "tier1" | "tier2";
  name: string;
  tagline: string;
  price: string;
  cadence: string;
  features: string[];
  highlight?: boolean;
}

export const PLANS: PlanCopy[] = [
  {
    id: "tier1",
    name: "Tier 1 — Dry Dock",
    tagline: "Find what's wrong before you launch.",
    price: "$49",
    cadence: "per month",
    features: [
      "Unlimited launch-readiness scans",
      "Full findings with file, line, and how to fix",
      "Up to 10 projects",
      "Scan by zip upload or public repo URL",
      "Scan history and score tracking",
      "JSON report export",
      "Embeddable trust badge",
    ],
  },
  {
    id: "tier2",
    name: "Tier 2 — Open Water",
    tagline: "Keep watching after you ship.",
    price: "$149",
    cadence: "per month",
    highlight: true,
    features: [
      "Everything in Tier 1",
      "Up to 50 projects",
      "Continuous runtime monitoring",
      "Live alerts on suspicious traffic",
      "Scan-to-scan comparison",
      "Finding triage and ownership",
      "Priority support",
    ],
  },
];

// Human-readable plan names. The database stores "free" / "tier1" / "tier2";
// nothing customer-facing should ever show those raw values.
export const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  tier1: "Tier 1 — Dry Dock",
  tier2: "Tier 2 — Open Water",
};
