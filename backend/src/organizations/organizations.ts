import { db, newId } from "../db";
import type { Organization, OrganizationMember, OrganizationRole } from "./types";

interface OrganizationRow {
  id: string;
  name: string;
  owner_id: string;
  plan: string;
  stripe_customer_id: string | null;
  subscription_status: string;
  created_at: string;
}

interface MemberRow {
  id: string;
  organization_id: string;
  user_id: string;
  email: string;
  role: string;
  created_at: string;
}

function toOrganization(row: OrganizationRow): Organization {
  return {
    id: row.id,
    name: row.name,
    ownerId: row.owner_id,
    plan: row.plan,
    stripeCustomerId: row.stripe_customer_id,
    subscriptionStatus: row.subscription_status,
    createdAt: row.created_at,
  };
}

function toMember(row: MemberRow): OrganizationMember {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id,
    email: row.email,
    role: row.role as OrganizationRole,
    createdAt: row.created_at,
  };
}

/** Creates the organization and its owner's membership row in one transaction — a crash between the two must never leave an organization with no owner-role member. */
export async function createOrganization(ownerId: string, name: string): Promise<Organization> {
  const org: Organization = {
    id: newId(),
    name,
    ownerId,
    plan: "free",
    stripeCustomerId: null,
    subscriptionStatus: "none",
    createdAt: new Date().toISOString(),
  };
  await db.transaction(async (tx) => {
    await tx.run("INSERT INTO organizations (id, name, owner_id, created_at) VALUES (?, ?, ?, ?)", [org.id, org.name, org.ownerId, org.createdAt]);
    await tx.run("INSERT INTO organization_members (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)", [
      newId(),
      org.id,
      ownerId,
      "owner",
      org.createdAt,
    ]);
  });
  return org;
}

export async function getOrganization(id: string): Promise<Organization | null> {
  const row = await db.get<OrganizationRow>("SELECT * FROM organizations WHERE id = ?", [id]);
  return row ? toOrganization(row) : null;
}

export async function renameOrganization(id: string, name: string): Promise<Organization | null> {
  await db.run("UPDATE organizations SET name = ? WHERE id = ?", [name, id]);
  return getOrganization(id);
}

/** Every organization a user belongs to (owner or member), newest first. */
export async function listOrganizationsForUser(userId: string): Promise<(Organization & { role: OrganizationRole })[]> {
  const rows = await db.all<OrganizationRow & { role: string }>(
    `SELECT o.*, m.role AS role
     FROM organizations o
     JOIN organization_members m ON m.organization_id = o.id
     WHERE m.user_id = ?
     ORDER BY o.created_at DESC`,
    [userId]
  );
  return rows.map((r) => ({ ...toOrganization(r), role: r.role as OrganizationRole }));
}

export async function listMembers(organizationId: string): Promise<OrganizationMember[]> {
  const rows = await db.all<MemberRow>(
    `SELECT m.*, u.email AS email
     FROM organization_members m
     JOIN users u ON u.id = m.user_id
     WHERE m.organization_id = ?
     ORDER BY m.created_at ASC`,
    [organizationId]
  );
  return rows.map(toMember);
}

/** Null when the user isn't a member — the caller decides 403 vs 404 from that. */
export async function getMembership(organizationId: string, userId: string): Promise<OrganizationMember | null> {
  const row = await db.get<MemberRow>(
    `SELECT m.*, u.email AS email
     FROM organization_members m
     JOIN users u ON u.id = m.user_id
     WHERE m.organization_id = ? AND m.user_id = ?`,
    [organizationId, userId]
  );
  return row ? toMember(row) : null;
}

export async function isMember(organizationId: string, userId: string): Promise<boolean> {
  const row = await db.get("SELECT 1 AS present FROM organization_members WHERE organization_id = ? AND user_id = ?", [organizationId, userId]);
  return !!row;
}

export class AlreadyMemberError extends Error {
  constructor() {
    super("This user is already a member of the organization");
    this.name = "AlreadyMemberError";
  }
}

export async function addMember(organizationId: string, userId: string, role: OrganizationRole = "member"): Promise<OrganizationMember> {
  if (await isMember(organizationId, userId)) throw new AlreadyMemberError();
  const id = newId();
  const createdAt = new Date().toISOString();
  await db.run("INSERT INTO organization_members (id, organization_id, user_id, role, created_at) VALUES (?, ?, ?, ?, ?)", [id, organizationId, userId, role, createdAt]);
  const member = await getMembership(organizationId, userId);
  if (!member) throw new Error("Failed to read back the membership row that was just inserted");
  return member;
}

export class CannotRemoveOwnerError extends Error {
  constructor() {
    super("The organization's owner cannot be removed — transfer or delete the organization instead");
    this.name = "CannotRemoveOwnerError";
  }
}

export async function removeMember(organizationId: string, userId: string): Promise<void> {
  const org = await getOrganization(organizationId);
  if (org?.ownerId === userId) throw new CannotRemoveOwnerError();
  await db.run("DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?", [organizationId, userId]);
}

// --- Organization billing (additive, per-organization Stripe subscription) -
// Mirrors auth/users.ts's own setStripeCustomerId/setSubscriptionStatus/
// getUserByStripeCustomerId — same shape, same out-of-order-webhook guard,
// applied to the organizations table instead. See billing/orgSubscription.ts
// for how this is resolved into an actual entitlement.

export async function setOrgStripeCustomerId(organizationId: string, stripeCustomerId: string): Promise<void> {
  await db.run("UPDATE organizations SET stripe_customer_id = ? WHERE id = ?", [stripeCustomerId, organizationId]);
}

/**
 * Applies a subscription plan/status change to an organization. `eventCreatedAt`
 * (Stripe's own event timestamp) is passed only by the webhook handler and
 * guards against out-of-order delivery, exactly as setSubscriptionStatus does
 * for users — see that function's comment for the full reasoning.
 */
export async function setOrgSubscriptionStatus(
  organizationId: string,
  plan: string,
  status: string,
  eventCreatedAt?: string
): Promise<void> {
  await db.transaction(async (tx) => {
    if (eventCreatedAt !== undefined) {
      const row = await tx.get<{ last_subscription_event_at: string | null }>(
        "SELECT last_subscription_event_at FROM organizations WHERE id = ?",
        [organizationId]
      );
      if (row?.last_subscription_event_at && eventCreatedAt < row.last_subscription_event_at) {
        return; // stale/out-of-order event — a newer state is already applied
      }
      await tx.run("UPDATE organizations SET last_subscription_event_at = ? WHERE id = ?", [eventCreatedAt, organizationId]);
    }
    await tx.run("UPDATE organizations SET plan = ?, subscription_status = ? WHERE id = ?", [plan, status, organizationId]);
  });
}

export async function getOrganizationByStripeCustomerId(stripeCustomerId: string): Promise<Organization | null> {
  const row = await db.get<OrganizationRow>("SELECT * FROM organizations WHERE stripe_customer_id = ?", [stripeCustomerId]);
  return row ? toOrganization(row) : null;
}
