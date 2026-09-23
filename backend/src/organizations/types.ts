export type OrganizationRole = "owner" | "member";

export interface Organization {
  id: string;
  name: string;
  ownerId: string;
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
