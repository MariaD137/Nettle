import type { NextFunction, Request, Response } from "express";
import { getUserById, type User } from "../auth/users";

// The plans that buy paid dashboard access (BUILD/PROTECT). FREE is a real,
// usable tier in its own right now (1 project, demo content — see
// entitlements.ts), just not a paid one: it's still the account state
// between signing up and subscribing, but it is no longer "not a usable
// tier" the way it was before FREE got real (capped) dashboard access.
export const PAID_PLANS = ["build", "protect"] as const;

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
 * Blocks a route behind an active BUILD or PROTECT subscription. Runs after
 * requireAuth, so an unauthenticated caller still gets a 401 rather than a
 * misleading "go pay" response.
 *
 * FREE is a real, usable dashboard tier now (see entitlements.ts) — this
 * middleware is no longer "the paywall in front of the whole dashboard," it
 * gates specifically the routes the pricing model marks BUILD+ (real scan
 * execution, Fix Center findings, scan history, comparisons, exports — see
 * routes/scans.routes.ts and routes/projects.routes.ts for which routes
 * still use it vs. which now only need requireAuth). PROTECT-only routes
 * (continuous monitoring, live alerts, API access) use requireProtect
 * below instead — BUILD alone doesn't satisfy this gate for those.
 *
 * The 402 body carries `subscriptionRequired` and `requiredPlan` so the
 * frontend can tell a paywall bounce apart from any other error and route
 * to /subscribe with the right upgrade framed.
 */
export async function requireSubscription(req: Request, res: Response, next: NextFunction) {
  const user = req.userId ? await getUserById(req.userId) : null;
  if (!hasActiveSubscription(user)) {
    return res.status(402).json({
      error: "This feature requires an active BUILD or PROTECT subscription",
      subscriptionRequired: true,
      requiredPlan: "build",
      plan: entitledPlan(user),
      subscriptionStatus: user?.subscriptionStatus ?? "none",
    });
  }
  next();
}

/**
 * Blocks a route behind PROTECT specifically — BUILD is not enough. For the
 * PROTECT-only surface: continuous monitoring's alert views, event
 * ingestion, live risk alerts, API access. A BUILD account (or a PROTECT
 * account that's downgraded to BUILD, whose historical alert data is
 * preserved but no longer viewable — same "don't delete, but gate access"
 * rule as Fix Center content on a lapsed BUILD/PROTECT account) gets the
 * same 402 shape as requireSubscription, just with requiredPlan "protect".
 */
export async function requireProtect(req: Request, res: Response, next: NextFunction) {
  const user = req.userId ? await getUserById(req.userId) : null;
  const plan = entitledPlan(user);
  if (plan !== "protect") {
    return res.status(402).json({
      error: "This feature requires an active PROTECT subscription",
      subscriptionRequired: true,
      requiredPlan: "protect",
      plan,
      subscriptionStatus: user?.subscriptionStatus ?? "none",
    });
  }
  next();
}
