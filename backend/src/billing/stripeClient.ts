import Stripe from "stripe";

let client: Stripe | null = null;

// Lazy init, not at import time — this module gets imported even in dev/test
// environments with no Stripe keys configured at all, and importing it
// shouldn't crash the whole server on boot just because billing isn't set
// up yet.
export function getStripeClient(): Stripe {
  if (!client) {
    const key = process.env.STRIPE_SECRET_KEY;
    if (!key) {
      throw new Error("STRIPE_SECRET_KEY is not set — billing is not configured in this environment");
    }
    client = new Stripe(key);
  }
  return client;
}

export const PLAN_PRICE_ENV_VARS: Record<string, string> = {
  tier1: "STRIPE_PRICE_TIER1",
  tier2: "STRIPE_PRICE_TIER2",
};

export function priceIdForPlan(plan: string): string {
  const envVar = PLAN_PRICE_ENV_VARS[plan];
  if (!envVar) throw new Error(`Unknown plan "${plan}"`);
  const priceId = process.env[envVar];
  if (!priceId) throw new Error(`${envVar} is not set — billing is not configured for the "${plan}" plan`);
  return priceId;
}

/**
 * Reverse of priceIdForPlan — maps a Stripe price id back to the plan it
 * represents, by checking it against the same configured price env vars.
 * Used to re-derive a subscription's plan from Stripe's own state (its
 * current price) instead of trusting a previously stored plan value, which
 * would otherwise go stale the moment a customer upgrades or downgrades
 * through the Stripe Customer Portal. Returns null for a price id that
 * doesn't match any configured plan (e.g. billing not configured, or a
 * price that predates the current STRIPE_PRICE_* values) rather than
 * throwing — the caller decides what to do with "unknown."
 */
export function planForPriceId(priceId: string): string | null {
  for (const [plan, envVar] of Object.entries(PLAN_PRICE_ENV_VARS)) {
    if (process.env[envVar] === priceId) return plan;
  }
  return null;
}
