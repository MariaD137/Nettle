import type { NextFunction, Request, Response } from "express";
import { getUserById, type User } from "../auth/users";

/**
 * THE single source of truth for "does this account currently have paid
 * access." Every paid feature — dashboard, project creation, scans, URL
 * scans, scan jobs, scan reports, Tier 1/Tier 2 functionality — must go
 * through hasPaidEntitlement()/resolveEntitlement() below rather than
 * inventing its own plan check. A plan string alone is never sufficient: an
 * account can carry plan="tier2" long after its subscription lapsed if
 * nothing ever reset it, so subscriptionStatus is always part of the check.
 */
export const PAID_PLANS = ["tier1", "tier2"] as const;
export type PaidPlan = (typeof PAID_PLANS)[number];

// Stripe subscription states treated as paid-up right now. Everything else
// — past_due, canceled, unpaid, incomplete, incomplete_expired, and any
// future status Stripe introduces — is deliberately excluded by omission:
// new statuses fail closed (no access) rather than needing to be added to
// an allowlist of what to reject.
const ACTIVE_STATUSES = new Set(["active", "trialing"]);

export type EntitlementInput = Pick<User, "plan" | "subscriptionStatus"> | null | undefined;

export function hasPaidEntitlement(user: EntitlementInput): boolean {
  if (!user) return false;
  return (PAID_PLANS as readonly string[]).includes(user.plan) && ACTIVE_STATUSES.has(user.subscriptionStatus);
}

// Full scan reports and paid-tier scan quota gate on exactly the same
// condition as dashboard/project access — no plan today unlocks one without
// the other. Named separately (rather than importing hasPaidEntitlement
// directly everywhere) so a future product change, e.g. a report-only tier,
// has one obvious place to diverge instead of several call sites to find.
export const hasFullScanAccess = hasPaidEntitlement;

/**
 * Resolves the account whose entitlement governs a request: the caller's
 * own session if authenticated, otherwise the owning project's account when
 * a project API key was presented (so CI/CD runs authenticated only by a
 * project key still get the full report the project's owner pays for).
 * Always re-reads the user from the database rather than trusting a value
 * cached earlier in the request — the backend is the ultimate authority on
 * entitlement, and a subscription that lapsed seconds ago must be honored
 * immediately, not after whatever cached it happens to refresh.
 */
export function resolveEntitlement(userId: string | undefined, apiKeyProjectUserId?: string): Pick<User, "plan" | "subscriptionStatus"> {
  const id = userId ?? apiKeyProjectUserId;
  const user = id ? getUserById(id) : null;
  if (user) return { plan: user.plan, subscriptionStatus: user.subscriptionStatus };
  return { plan: "free", subscriptionStatus: "none" };
}

/**
 * Blocks a route behind an active subscription. Runs after requireAuth, so
 * an unauthenticated caller still gets a 401 rather than a misleading "go
 * pay" response.
 *
 * The 402 body carries `subscriptionRequired` so the frontend can tell a
 * paywall bounce apart from any other error and route to /subscribe.
 */
export function requireSubscription(req: Request, res: Response, next: NextFunction) {
  const user = req.userId ? getUserById(req.userId) : null;
  if (!hasPaidEntitlement(user)) {
    return res.status(402).json({
      error: "An active Tier 1 or Tier 2 subscription is required",
      subscriptionRequired: true,
      plan: user?.plan ?? "free",
      subscriptionStatus: user?.subscriptionStatus ?? "none",
    });
  }
  next();
}
