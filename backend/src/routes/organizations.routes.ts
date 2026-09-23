import { Router } from "express";
import {
  createOrganization,
  getOrganization,
  renameOrganization,
  listOrganizationsForUser,
  listMembers,
  getMembership,
  addMember,
  removeMember,
  AlreadyMemberError,
  CannotRemoveOwnerError,
} from "../organizations/organizations";
import { getUserByEmail, getUserById } from "../auth/users";
import { entitledPlan } from "../billing/subscription";
import { getTeamMemberLimit } from "../billing/entitlements";
import { requireAuth } from "../auth/middleware";
import { rateLimit } from "../middleware/rateLimit";

export const organizationsRouter = Router();

// Matches projects.routes.ts's dashboardLimiter: generous, account-keyed,
// covers ordinary org-management usage rather than an expensive operation.
const orgLimiter = rateLimit({
  windowMs: 60 * 1000,
  maxRequests: 60,
  message: "Too many requests — try again shortly",
  scope: "organizations:dashboard",
  keyFn: (req) => (req.userId ? `user:${req.userId}` : null),
});

const guarded = [requireAuth, orgLimiter];

/**
 * Loads the organization and the caller's membership in it, or responds and
 * returns null. A non-member gets 404, not 403 — same reasoning
 * ownedProjectOr404 in projects.routes.ts already uses: 403 would confirm
 * the organization id exists to someone with no relationship to it at all.
 */
async function accessibleOrgOr404(req: import("express").Request, res: import("express").Response) {
  const org = await getOrganization(req.params.id);
  if (!org) {
    res.status(404).json({ error: "Organization not found" });
    return null;
  }
  const membership = await getMembership(org.id, req.userId!);
  if (!membership) {
    res.status(404).json({ error: "Organization not found" });
    return null;
  }
  return { org, membership };
}

organizationsRouter.post("/api/organizations", ...guarded, async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide an organization 'name'" });
  }
  const org = await createOrganization(req.userId!, name);
  res.status(201).json({ organization: org, role: "owner" });
});

organizationsRouter.get("/api/organizations", ...guarded, async (req, res) => {
  res.json({ organizations: await listOrganizationsForUser(req.userId!) });
});

organizationsRouter.get("/api/organizations/:id", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  const members = await listMembers(loaded.org.id);
  res.json({ organization: loaded.org, role: loaded.membership.role, members });
});

organizationsRouter.patch("/api/organizations/:id", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can rename it" });
  }
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) {
    return res.status(400).json({ error: "Provide an organization 'name'" });
  }
  const updated = await renameOrganization(loaded.org.id, name);
  res.json({ organization: updated });
});

organizationsRouter.get("/api/organizations/:id/members", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  res.json({ members: await listMembers(loaded.org.id) });
});

/**
 * Direct add by email — no invitation flow (accepted scope cut for this
 * round, see 004_organizations.sql). The target user must already have a
 * Nettle account; there's no pending/invited state, so this either succeeds
 * immediately or fails with a clear reason.
 */
organizationsRouter.post("/api/organizations/:id/members", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can add members" });
  }
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!email) {
    return res.status(400).json({ error: "Provide a member 'email'" });
  }
  const user = await getUserByEmail(email);
  if (!user) {
    return res.status(404).json({ error: "No Nettle account exists for that email address" });
  }

  // Team size is entitled by the organization owner's plan (Phase D scoped
  // MVP keeps billing per-user, not per-org — same precedent as the project
  // count limit above). The caller here IS the owner (checked above), so
  // this is their own plan, not a lookup of someone else's.
  const owner = await getUserById(loaded.org.ownerId);
  const plan = entitledPlan(owner);
  const limit = getTeamMemberLimit(plan);
  const currentMembers = await listMembers(loaded.org.id);
  if (currentMembers.length >= limit) {
    return res.status(403).json({
      error: `Team member limit reached (${limit}). Upgrade your plan to add more.`,
      teamLimitReached: true,
      limit,
      plan,
    });
  }

  try {
    const member = await addMember(loaded.org.id, user.id);
    res.status(201).json({ member });
  } catch (err) {
    if (err instanceof AlreadyMemberError) {
      return res.status(409).json({ error: err.message });
    }
    throw err;
  }
});

organizationsRouter.delete("/api/organizations/:id/members/:userId", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can remove members" });
  }
  try {
    await removeMember(loaded.org.id, req.params.userId);
    res.status(204).end();
  } catch (err) {
    if (err instanceof CannotRemoveOwnerError) {
      return res.status(400).json({ error: err.message });
    }
    throw err;
  }
});
