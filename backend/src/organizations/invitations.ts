import crypto from "crypto";
import { db, newId } from "../db";
import { hashToken } from "../auth/tokenHash";
import { entitledPlan } from "../billing/subscription";
import { resolveTeamPlan } from "../billing/orgSubscription";
import { getTeamMemberLimit } from "../billing/entitlements";
import { getUserById } from "../auth/users";
import { getOrganization, listMembers, isMember } from "./organizations";
import type { OrganizationMember, OrganizationRole } from "./types";

/**
 * Organization invitations. Mirrors auth/users.ts's password-reset tokens
 * deliberately: a cryptographically random 32-byte token, only its SHA-256
 * hash ever stored (tokenHash.ts), single-use (accepted_at), expiring, and
 * never returned to any API caller — it only ever exists in the delivery
 * boundary (notifications/invitationDelivery.ts) and the link a recipient
 * clicks. The server is the only thing that ever decides organization,
 * role, inviter authorization, or acceptance state — nothing here accepts
 * any of those from the client except the opaque token itself.
 */

const INVITATION_LIFETIME_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface OrganizationInvitation {
  id: string;
  organizationId: string;
  email: string;
  role: OrganizationRole;
  invitedBy: string;
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
}

interface InvitationRow {
  id: string;
  organization_id: string;
  email: string;
  role: string;
  invited_by: string;
  created_at: string;
  expires_at: string;
  accepted_at: string | null;
}

function toInvitation(row: InvitationRow): OrganizationInvitation {
  return {
    id: row.id,
    organizationId: row.organization_id,
    email: row.email,
    role: row.role as OrganizationRole,
    invitedBy: row.invited_by,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    acceptedAt: row.accepted_at,
  };
}

export class InvitationNotFoundError extends Error {
  constructor() {
    super("Invitation not found or already used");
    this.name = "InvitationNotFoundError";
  }
}

export class InvitationExpiredError extends Error {
  constructor() {
    super("This invitation has expired");
    this.name = "InvitationExpiredError";
  }
}

export class InvitationAlreadyAcceptedError extends Error {
  constructor() {
    super("This invitation has already been accepted");
    this.name = "InvitationAlreadyAcceptedError";
  }
}

/**
 * The invitation was issued to a different email address than the one the
 * currently-signed-in account holds. Without this check, anyone who can
 * obtain a valid token (a forwarded email, a leaked link) could join the
 * organization under their own account regardless of who was actually
 * invited — this is the specific privilege-escalation path the token's
 * single-use/server-validated design exists to close.
 */
export class InvitationEmailMismatchError extends Error {
  constructor() {
    super("This invitation was sent to a different email address than your account's");
    this.name = "InvitationEmailMismatchError";
  }
}

export class TeamMemberLimitError extends Error {
  constructor(limit: number) {
    super(`The organization's plan allows up to ${limit} team members`);
    this.name = "TeamMemberLimitError";
  }
}

/**
 * Creates a pending invitation and returns the raw token exactly once —
 * the caller (routes/organizations.routes.ts) hands it to the email
 * delivery boundary and never returns it in an HTTP response. Re-inviting
 * the same email while a pending invitation already exists creates a new,
 * independent token rather than reusing or extending the old one — the old
 * token stays valid until its own expiry, which is deliberately simple
 * (letting it lapse naturally) over adding revoke-on-reinvite semantics
 * this MVP doesn't need yet.
 */
export async function createInvitation(
  organizationId: string,
  email: string,
  role: OrganizationRole,
  invitedBy: string
): Promise<{ invitation: OrganizationInvitation; token: string }> {
  const token = crypto.randomBytes(32).toString("hex");
  const now = new Date();
  const invitation: OrganizationInvitation = {
    id: newId(),
    organizationId,
    email: email.trim().toLowerCase(),
    role,
    invitedBy,
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + INVITATION_LIFETIME_MS).toISOString(),
    acceptedAt: null,
  };
  await db.run(
    "INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, invited_by, created_at, expires_at, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
    [invitation.id, invitation.organizationId, invitation.email, invitation.role, hashToken(token), invitation.invitedBy, invitation.createdAt, invitation.expiresAt]
  );
  return { invitation, token };
}

/** Pending (not yet accepted, not yet expired) invitations for an organization — what an owner sees when managing membership. */
export async function listPendingInvitations(organizationId: string): Promise<OrganizationInvitation[]> {
  const rows = await db.all<InvitationRow>(
    "SELECT * FROM organization_invitations WHERE organization_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY created_at DESC",
    [organizationId, new Date().toISOString()]
  );
  return rows.map(toInvitation);
}

export async function getInvitationById(id: string): Promise<OrganizationInvitation | null> {
  const row = await db.get<InvitationRow>("SELECT * FROM organization_invitations WHERE id = ?", [id]);
  return row ? toInvitation(row) : null;
}

/** Looks up an invitation by its raw token — never by id from an untrusted caller. Does not check expiry/acceptance; callers that need the full validation should use acceptInvitation. */
export async function resolveInvitationToken(token: string): Promise<OrganizationInvitation | null> {
  const row = await db.get<InvitationRow>("SELECT * FROM organization_invitations WHERE token_hash = ?", [hashToken(token)]);
  return row ? toInvitation(row) : null;
}

/**
 * Validates and consumes an invitation in one transaction, creating the
 * membership. Every check the master spec requires is enforced here,
 * server-side, against the token and the *authenticated caller* — never
 * against anything the client separately asserts:
 *   - token resolves to a real, non-expired, not-already-accepted invitation
 *   - the accepting account's own email matches the invited email exactly
 *     (privilege-escalation guard — see InvitationEmailMismatchError)
 *   - the organization's current team-member limit isn't already at
 *     capacity (re-checked here, not just at invite-creation time, since
 *     the owner's plan may have changed since the invitation was sent)
 *
 * The accept itself is a conditional UPDATE — `WHERE accepted_at IS NULL`,
 * checking `changes` — not a plain SELECT-then-UPDATE. Wrapping the two in
 * one transaction is not sufficient on its own: at PostgreSQL's default
 * READ COMMITTED isolation, two concurrent transactions can both SELECT the
 * same not-yet-accepted row before either commits its UPDATE, so both would
 * pass a "not yet accepted" check read this way and both create a
 * membership (confirmed directly — this exact race, run for real against
 * PostgreSQL in backend/test/organizationInvitations.test.ts's concurrency
 * test, let 4 of 4 concurrent acceptances succeed before this fix). The
 * conditional UPDATE is what actually serializes the two: PostgreSQL takes
 * a row lock on the first UPDATE to reach it, and the second one's own
 * `WHERE accepted_at IS NULL` no longer matches once it can proceed,
 * so `changes` comes back 0 — the same atomic-claim shape
 * billing/scanQuota.ts's reservation primitive already uses. SQLite never
 * exposed this: this codebase's SQLite driver serializes all writes onto a
 * single connection, so two "concurrent" requests never actually overlap at
 * the database level the way two real PostgreSQL connections do.
 */
export async function acceptInvitation(token: string, acceptingUserId: string, acceptingUserEmail: string): Promise<OrganizationMember> {
  return db.transaction(async (tx) => {
    const row = await tx.get<InvitationRow>("SELECT * FROM organization_invitations WHERE token_hash = ?", [hashToken(token)]);
    if (!row) throw new InvitationNotFoundError();
    const invitation = toInvitation(row);

    if (invitation.acceptedAt) throw new InvitationAlreadyAcceptedError();
    if (new Date(invitation.expiresAt).getTime() < Date.now()) throw new InvitationExpiredError();
    if (invitation.email !== acceptingUserEmail.trim().toLowerCase()) throw new InvitationEmailMismatchError();

    const org = await getOrganization(invitation.organizationId);
    if (!org) throw new InvitationNotFoundError(); // organization deleted since the invite was sent

    const owner = await getUserById(org.ownerId);
    const plan = resolveTeamPlan(org, entitledPlan(owner));
    const limit = getTeamMemberLimit(plan);
    const currentMembers = await listMembers(org.id);
    if (!(await isMember(org.id, acceptingUserId)) && currentMembers.length >= limit) {
      throw new TeamMemberLimitError(limit);
    }

    const claimed = await tx.run(
      "UPDATE organization_invitations SET accepted_at = ? WHERE id = ? AND accepted_at IS NULL",
      [new Date().toISOString(), invitation.id]
    );
    if (claimed.changes === 0) throw new InvitationAlreadyAcceptedError();

    // Already a member (e.g. re-clicking an old link after being added a
    // different way): the invitation is still consumed above, but no
    // duplicate membership row is created.
    const existing = await tx.get<{ id: string }>(
      "SELECT id FROM organization_members WHERE organization_id = ? AND user_id = ?",
      [org.id, acceptingUserId]
    );
    if (existing) {
      const member = await tx.get<{ id: string; organization_id: string; user_id: string; role: string; created_at: string }>(
        "SELECT m.*, u.email AS email FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.id = ?",
        [existing.id]
      );
      return member as unknown as OrganizationMember;
    }

    const memberId = newId();
    const createdAt = new Date().toISOString();
    await tx.run(
      "INSERT INTO organization_members (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)",
      [memberId, org.id, acceptingUserId, invitation.role, createdAt]
    );
    return {
      id: memberId,
      organizationId: org.id,
      userId: acceptingUserId,
      email: acceptingUserEmail.trim().toLowerCase(),
      role: invitation.role,
      createdAt,
    };
  });
}

/** Owner cancels a pending invitation before it's accepted. */
export async function revokeInvitation(invitationId: string, organizationId: string): Promise<void> {
  await db.run(
    "DELETE FROM organization_invitations WHERE id = ? AND organization_id = ? AND accepted_at IS NULL",
    [invitationId, organizationId]
  );
}
