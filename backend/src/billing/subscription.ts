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
