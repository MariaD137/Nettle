import type { NextFunction, Request, Response } from "express";
import type { Organization } from "../organizations/types";
import { getOrganization } from "../organizations/organizations";
import { entitledPlan, PAID_PLANS } from "./subscription";
import { getUserById } from "../auth/users";
import { getProject, canAccessProject } from "../patrol/projects";
import type { Project } from "../patrol/types";

// Same "active" definition as subscription.ts's hasActiveSubscription —
// deliberately excludes "past_due": a failed payment should stop granting
// access, for an organization exactly as it does for an individual account.
const ACTIVE_STATUSES = new Set(["active", "trialing"]);

export function hasActiveOrgSubscription(org: Pick<Organization, "plan" | "subscriptionStatus"> | null): boolean {
  if (!org) return false;
  return (PAID_PLANS as readonly string[]).includes(org.plan) && ACTIVE_STATUSES.has(org.subscriptionStatus);
}

/** The plan an organization's OWN subscription actually entitles it to — "free" if it isn't subscribed, mirroring subscription.ts's entitledPlan(). */
export function entitledOrgPlan(org: Pick<Organization, "plan" | "subscriptionStatus"> | null): string {
  return hasActiveOrgSubscription(org) ? org!.plan : "free";
}

/**
 * Resolves the entitled plan for a specific project: the organization's own
 * subscription if the project belongs to one AND that organization is
 * actively subscribed, else `fallbackPlan` — whatever plan the caller had
 * already computed under the pre-existing per-user model (see
 * subscription.ts's entitledPlan(), usually applied to either the viewing
 * user or the project's creator, unchanged at every call site).
 *
 * This is the one seam "additive per-organization billing" adds: an
 * organization that subscribes itself unlocks its plan's entitlement for
 * *every* member viewing one of its projects, not just whichever member
 * happens to also have a paid personal subscription. An unsubscribed
 * organization (the default, and the only state that existed before this
 * feature) changes nothing — this always falls through to `fallbackPlan`.
 */
export async function resolvePlanForProject(
  project: Pick<Project, "organizationId">,
  fallbackPlan: string
): Promise<string> {
  if (!project.organizationId) return fallbackPlan;
  const org = await getOrganization(project.organizationId);
  return hasActiveOrgSubscription(org) ? org!.plan : fallbackPlan;
}

/**
 * Resolves the plan an organization's team-member limit is checked against:
 * the organization's own subscription if it has one, else `fallbackPlan`
 * (the owner's personal entitled plan — the pre-existing behavior, see
 * routes/organizations.routes.ts and organizations/invitations.ts). Lets an
 * owner grow their team by subscribing the organization itself, without
 * needing their own personal account to also carry a paid plan.
 */
export function resolveTeamPlan(org: Pick<Organization, "plan" | "subscriptionStatus"> | null, fallbackPlan: string): string {
  return hasActiveOrgSubscription(org) ? org!.plan : fallbackPlan;
}

/**
 * Project-aware counterpart to subscription.ts's requireSubscription/
 * requireProtect. Those gate a route on the CALLER's own personal plan,
 * which is right for account-level routes but wrong for a route scoped to
 * one project (:id) — a FREE member of an organization that has its own
 * active PROTECT subscription must still see that organization's projects'
 * paid content, not get a 402 because their own personal account never
 * subscribed.
 *
 * Runs after requireAuth (needs req.userId) and before the route handler,
 * which still does its own accessibleProjectOr404 lookup — that duplicate
 * query is deliberate rather than threading the project through res.locals:
 * it keeps this middleware fully self-contained, matches this codebase's
 * existing tolerance for a second lookup on the same request (see
 * routes/scans.routes.ts's planForScan, which re-derives ownership the same
 * way), and means a project made inaccessible between the two checks (e.g.
 * removed from the org mid-request) is never treated as reachable by the
 * handler just because this middleware saw it a moment earlier.
 *
 * 404, not 403, for a missing/inaccessible project — same reasoning as
 * accessibleProjectOr404 elsewhere in this codebase: don't confirm a
 * project id exists to a caller with no relationship to it.
 */
export function requireProjectPlan(minPlan: "build" | "protect") {
  return async function (req: Request, res: Response, next: NextFunction) {
    const project = await getProject(req.params.id);
    if (!project || !(await canAccessProject(req.userId!, project))) {
      return res.status(404).json({ error: "Project not found" });
    }

    const requester = await getUserById(req.userId!);
    const plan = await resolvePlanForProject(project, entitledPlan(requester));
    const satisfied = minPlan === "protect" ? plan === "protect" : (PAID_PLANS as readonly string[]).includes(plan);

    if (!satisfied) {
      return res.status(402).json({
        error: `This feature requires an active ${minPlan === "protect" ? "PROTECT" : "BUILD or PROTECT"} subscription`,
        subscriptionRequired: true,
        requiredPlan: minPlan,
        plan,
        subscriptionStatus: requester?.subscriptionStatus ?? "none",
      });
    }
    next();
  };
}
