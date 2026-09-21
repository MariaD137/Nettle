import type { NextFunction, Request, Response } from "express";
import { getUserById, type User } from "../auth/users";

// The plans that buy dashboard access. A new account starts on "free", which
// is not a usable tier — it's the state between signing up and paying.
export const PAID_PLANS = ["tier1", "tier2"] as const;

// Stripe subscription states we treat as paid-up. "past_due" is deliberately
// excluded: the payment failed, and access should stop until it clears.
const ACTIVE_STATUSES = new Set(["active", "trialing"]);

export function hasActiveSubscription(user: Pick<User, "plan" | "subscriptionStatus"> | null): boolean {
  if (!user) return false;
  return (PAID_PLANS as readonly string[]).includes(user.plan) && ACTIVE_STATUSES.has(user.subscriptionStatus);
}

/**
 * The plan a caller is actually entitled to right now.
 *
 * `users.plan` records which plan was last purchased and is deliberately left
 * in place when a subscription ends, so the account can be resubscribed and
 * reconciled against Stripe. It is therefore a record of intent, not a grant:
 * on its own it says nothing about whether the account is paid up.
 *
 * Anything gating paid output must go through this, not through `user.plan`.
 * Reading the raw plan is what let a canceled or past_due account keep
 * receiving full scan reports indefinitely while the dashboard correctly
 * returned 402.
 */
export function entitledPlan(user: Pick<User, "plan" | "subscriptionStatus"> | null): string {
  return hasActiveSubscription(user) ? user!.plan : "free";
}

/**
 * Blocks every dashboard route behind an active subscription. Runs after
 * requireAuth, so an unauthenticated caller still gets a 401 rather than a
 * misleading "go pay" response.
 *
 * The 402 body carries `subscriptionRequired` so the frontend can tell a
 * paywall bounce apart from any other error and route to /subscribe.
 */
export function requireSubscription(req: Request, res: Response, next: NextFunction) {
  const user = req.userId ? getUserById(req.userId) : null;
  if (!hasActiveSubscription(user)) {
    return res.status(402).json({
      error: "An active Tier 1 or Tier 2 subscription is required",
      subscriptionRequired: true,
      plan: user?.plan ?? "free",
      subscriptionStatus: user?.subscriptionStatus ?? "none",
    });
  }
  next();
}
