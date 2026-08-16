import type { User } from "./api";

// Mirrors backend/src/billing/subscription.ts. Kept in sync deliberately:
// this copy decides what the user *sees*, the backend copy decides what they
// can actually reach. "past_due" is not active in either.
const PAID_PLANS = ["tier1", "tier2"];
const ACTIVE_STATUSES = ["active", "trialing"];

export function hasActiveSubscription(user: User | null): boolean {
  if (!user) return false;
  return PAID_PLANS.includes(user.plan) && ACTIVE_STATUSES.includes(user.subscriptionStatus);
}
