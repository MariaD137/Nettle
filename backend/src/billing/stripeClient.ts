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
 * The reverse of priceIdForPlan: given a Stripe price id, which plan does it
 * belong to. Used on customer.subscription.updated/.deleted so the plan
 * recorded is derived from what Stripe says is actually being billed, not
 * from whatever this app's own database happened to have recorded before —
 * the two can drift (a plan change made directly in the Stripe dashboard, a
 * failed webhook that never updated the DB, ...). Returns null for a price
 * id that doesn't map to a known plan rather than guessing.
 */
export function planForPriceId(priceId: string): string | null {
  for (const plan of Object.keys(PLAN_PRICE_ENV_VARS)) {
    const envVar = PLAN_PRICE_ENV_VARS[plan];
    if (process.env[envVar] === priceId) return plan;
  }
  return null;
}

/**
 * Cancels every active subscription a Stripe customer has. Used before
 * deleting an account (see auth/users.ts's deleteUser and the DELETE
 * /api/auth/account route) — the account row must never disappear while
 * Stripe keeps billing it, since nothing would be left to receive or act on
 * a future webhook for a customer id that no longer resolves to a user.
 *
 * Throws on a genuine Stripe API failure so the caller can refuse the
 * deletion rather than silently proceeding with billing left running; a
 * customer with no subscriptions at all is not an error.
 */
export async function cancelAllSubscriptions(stripeCustomerId: string): Promise<void> {
  const stripe = getStripeClient();
  const subscriptions = await stripe.subscriptions.list({ customer: stripeCustomerId, status: "active" });
  for (const subscription of subscriptions.data) {
    await stripe.subscriptions.cancel(subscription.id);
  }
  const trialing = await stripe.subscriptions.list({ customer: stripeCustomerId, status: "trialing" });
  for (const subscription of trialing.data) {
    await stripe.subscriptions.cancel(subscription.id);
  }
}
