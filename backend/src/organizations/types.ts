export type OrganizationRole = "owner" | "member";

export interface Organization {
  id: string;
  name: string;
  ownerId: string;
  /**
   * The organization's own, optional Stripe subscription (additive per-
   * organization billing) — independent of any individual member's personal
   * plan/subscription on the users table. Defaults mirror users.ts's own
   * unsubscribed state ('free'/'none'/null): an organization that has never
   * been subscribed behaves exactly as it did before these fields existed.
   * See billing/orgSubscription.ts for how this is resolved against a
   * project's/team's entitlement, always falling back to the pre-existing
   * per-user model when the organization itself isn't subscribed.
   */
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  /** Stamped once, the first time the organization becomes actively subscribed — mirrors users.billingAnchor exactly. Null until then; drives billing/scanQuota.ts's shared org scan period. */
  billingAnchor: string | null;
  createdAt: string;
}

export interface OrganizationMember {
  id: string;
  organizationId: string;
  userId: string;
  email: string;
  role: OrganizationRole;
  createdAt: string;
}
