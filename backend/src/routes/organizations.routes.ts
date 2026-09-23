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
import {
  createInvitation,
  listPendingInvitations,
  getInvitationById,
  acceptInvitation,
  revokeInvitation,
  InvitationNotFoundError,
  InvitationExpiredError,
  InvitationAlreadyAcceptedError,
  InvitationEmailMismatchError,
  TeamMemberLimitError,
} from "../organizations/invitations";
import { deliverInvitationLink } from "../notifications/invitationDelivery";

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

// --- Invitations -----------------------------------------------------------
//
// Alongside, not replacing, the direct-add-by-email flow above: that path
// stays for an owner adding someone who already has a Nettle session handy
// (e.g. a teammate in the same call). Invitations are for the normal case
// — the invited person doesn't need an account yet, and gets a real email
// with a link. Neither the organization nor the role for an invitation
// accept ever comes from the client: both are looked up server-side from
// the token (see organizations/invitations.ts's acceptInvitation).

const VALID_ROLES = new Set(["member"]); // owner is never assignable via invitation — there is exactly one owner, set at creation

organizationsRouter.post("/api/organizations/:id/invitations", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can invite members" });
  }

  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!email) {
    return res.status(400).json({ error: "Provide an invitee 'email'" });
  }
  const role = typeof req.body?.role === "string" ? req.body.role : "member";
  if (!VALID_ROLES.has(role)) {
    return res.status(400).json({ error: 'role must be "member"' });
  }

  // Team size is entitled by the organization owner's plan — checked at
  // invite time (a clear, immediate error for the owner) and re-checked at
  // accept time (organizations/invitations.ts), since the owner's plan can
  // change in between.
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
  if (currentMembers.some((m) => m.email === email)) {
    return res.status(409).json({ error: "That email is already a member of this organization" });
  }

  const inviter = await getUserById(req.userId!);
  const { invitation, token } = await createInvitation(loaded.org.id, email, role as "member", req.userId!);

  // Delivery failure must not fail invitation creation — the invitation and
  // its token are real either way; the owner can relay it manually if email
  // isn't configured in this environment (see notifications/invitationDelivery.ts).
  let delivered = false;
  try {
    const result = await deliverInvitationLink(email, token, loaded.org.name, inviter?.email ?? "A Nettle user");
    delivered = result.delivered;
  } catch (err) {
    console.error(`[org-invitation] delivery failed: ${(err as Error).message}`);
  }

  res.status(201).json({
    invitation: { id: invitation.id, email: invitation.email, role: invitation.role, expiresAt: invitation.expiresAt },
    delivered,
  });
});

organizationsRouter.get("/api/organizations/:id/invitations", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can view pending invitations" });
  }
  const invitations = await listPendingInvitations(loaded.org.id);
  res.json({ invitations: invitations.map((i) => ({ id: i.id, email: i.email, role: i.role, createdAt: i.createdAt, expiresAt: i.expiresAt })) });
});

organizationsRouter.delete("/api/organizations/:id/invitations/:invitationId", ...guarded, async (req, res) => {
  const loaded = await accessibleOrgOr404(req, res);
  if (!loaded) return;
  if (loaded.membership.role !== "owner") {
    return res.status(403).json({ error: "Only the organization's owner can revoke invitations" });
  }
  const invitation = await getInvitationById(req.params.invitationId);
  if (!invitation || invitation.organizationId !== loaded.org.id) {
    return res.status(404).json({ error: "Invitation not found" });
  }
  await revokeInvitation(req.params.invitationId, loaded.org.id);
  res.status(204).end();
});

/**
 * Accepting an invitation is deliberately not scoped under
 * /api/organizations/:id — the token alone determines which organization,
 * so there is no :id for the client to (correctly or incorrectly) supply.
 * requireAuth, not the org-scoped `guarded`/accessibleOrgOr404 pattern
 * above: the accepting user isn't a member yet, so there's nothing for
 * that helper to load.
 */
organizationsRouter.post("/api/invitations/accept", requireAuth, orgLimiter, async (req, res) => {
  const token = typeof req.body?.token === "string" ? req.body.token : "";
  if (!token) {
    return res.status(400).json({ error: "Provide an invitation 'token'" });
  }
  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  try {
    const member = await acceptInvitation(token, req.userId!, user.email);
    const org = await getOrganization(member.organizationId);
    res.status(200).json({ member, organization: org });
  } catch (err) {
    if (err instanceof InvitationNotFoundError) return res.status(404).json({ error: err.message });
    if (err instanceof InvitationExpiredError) return res.status(410).json({ error: err.message });
    if (err instanceof InvitationAlreadyAcceptedError) return res.status(409).json({ error: err.message });
    if (err instanceof InvitationEmailMismatchError) return res.status(403).json({ error: err.message });
    if (err instanceof TeamMemberLimitError) return res.status(403).json({ error: err.message, teamLimitReached: true });
    throw err;
  }
});
