/**
 * Plan copy for the pricing page and paywall.
 *
 * PLACEHOLDER PRICING — these amounts are display-only and have not been
 * decided yet. The real charge always comes from the Stripe price IDs
 * configured on the API (STRIPE_PRICE_BUILD / STRIPE_PRICE_PROTECT); this
 * file only controls what the pricing page *says*. Update both together, or
 * customers will be quoted one number and charged another.
 *
 * FREE has no `id` usable for checkout — there is nothing to buy. See
 * SubscribePage.tsx: FREE's button just continues into the (capped)
 * dashboard rather than starting a Stripe session.
 */
export interface PlanCopy {
  id: "free" | "build" | "protect";
  name: string;
  badge?: string;
  tagline: string;
  price: string;
  cadence: string;
  features: string[];
  excluded?: string[];
  cta: string;
  highlight?: boolean;
}

export const PLANS: PlanCopy[] = [
  {
    id: "free",
    name: "Free",
    tagline: "Explore Nettle's security controls before scanning.",
    price: "$0",
    cadence: "per month",
    features: [
      "Security control library preview",
      "Sample findings & remediation",
      "Security readiness checklist",
      "1 project",
    ],
    excluded: ["No scans"],
    cta: "Explore Nettle",
  },
  {
    id: "build",
    name: "Build",
    badge: "MOST USED",
    tagline: "Scan your applications, identify security gaps, and get actionable fixes.",
    price: "$49",
    cadence: "per month",
    highlight: true,
    features: [
      "10 scans per month",
      "3 projects",
      "Full findings & severity",
      "File-level evidence",
      "Fix Center & remediation",
      "Rescan & verification",
      "CI/CD gating",
      "Scan history & trust badge",
      "3 team members",
    ],
    cta: "Start scanning",
  },
  {
    id: "protect",
    name: "Protect",
    tagline: "Continuously monitor your applications for new security risk after launch.",
    price: "$199",
    cadence: "per month",
    features: [
      "Everything in Build",
      "Unlimited projects",
      "Unlimited, fair-use scans",
      "Continuous monitoring",
      "Real-time event ingestion",
      "Live risk alerts",
      "API access",
      "10 team members",
      "Priority support",
    ],
    cta: "Start protecting",
  },
];

// Human-readable plan names. The database stores "free" / "build" /
// "protect"; nothing customer-facing should ever show those raw values.
export const PLAN_LABELS: Record<string, string> = {
  free: "Free",
  build: "Build",
  protect: "Protect",
};
