import type { User } from "./api";

// Mirrors backend/src/billing/subscription.ts. Kept in sync deliberately:
// this copy decides what the user *sees*, the backend copy decides what they
// can actually reach — this is UI framing only, never an access decision by
// itself (every route this gates is independently enforced server-side).
// "past_due" is not active in either.
const PAID_PLANS = ["build", "protect"];
const ACTIVE_STATUSES = ["active", "trialing"];

export function hasActiveSubscription(user: User | null): boolean {
  if (!user) return false;
  return PAID_PLANS.includes(user.plan) && ACTIVE_STATUSES.includes(user.subscriptionStatus);
}

/** Mirrors backend/src/billing/subscription.ts's entitledPlan(): the plan actually in effect right now, not just the last one purchased. */
export function entitledPlan(user: User | null): "free" | "build" | "protect" {
  if (!user) return "free";
  return hasActiveSubscription(user) ? (user.plan as "build" | "protect") : "free";
}

/** Mirrors backend/src/billing/entitlements.ts's canRunScan(): true for BUILD and PROTECT, false for FREE. */
export function canRunScan(user: User | null): boolean {
  return entitledPlan(user) !== "free";
}

/** Mirrors backend/src/billing/entitlements.ts's canUseFixCenter(): true for BUILD and PROTECT. */
export function canUseFixCenter(user: User | null): boolean {
  return entitledPlan(user) !== "free";
}

/** Mirrors backend/src/billing/entitlements.ts's canUseContinuousMonitoring()/canUseLiveAlerts(): PROTECT only. */
export function isProtect(user: User | null): boolean {
  return entitledPlan(user) === "protect";
}
