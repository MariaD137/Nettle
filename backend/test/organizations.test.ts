import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { organizationsRouter } from "../src/routes/organizations.routes";
import { projectsRouter } from "../src/routes/projects.routes";

// Organizations with owner/member roles, and a project can optionally
// belong to one instead of just a user. This file covers the direct
// add-by-email flow from the original Phase D scoped MVP; invitations
// (organizationInvitations.test.ts) and per-organization billing
// (organizationBilling.test.ts) are covered separately.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

async function setUp() {
  const app = express();
  app.use(express.json());
  app.use(organizationsRouter);
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  return { server, base };
}

async function userAndToken(email: string, tier = true) {
  const user = await createUser(email, "correct horse battery staple");
  if (tier) await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);
  return { user, token };
}

test("POST /api/organizations creates an org and the creator becomes owner", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token } = await userAndToken("org-owner@example.com", false); // org creation itself isn't paywalled

  const res = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  assert.equal(res.status, 201);
  const body = (await res.json()) as any;
  assert.equal(body.organization.name, "Acme Corp");
  assert.equal(body.role, "owner");
});

test("GET /api/organizations lists orgs the caller belongs to, with their role", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token } = await userAndToken("org-list@example.com", false);
  await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });

  const res = await fetch(`${base}/api/organizations`, { headers: { Authorization: `Bearer ${token}` } });
  const body = (await res.json()) as any;
  assert.equal(body.organizations.length, 1);
  assert.equal(body.organizations[0].role, "owner");
});

test("a non-member gets 404 for an organization's detail, not 403 (existence not confirmed)", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("org-detail-owner@example.com", false);
  const { token: outsiderToken } = await userAndToken("org-detail-outsider@example.com", false);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  const res = await fetch(`${base}/api/organizations/${org.id}`, { headers: { Authorization: `Bearer ${outsiderToken}` } });
  assert.equal(res.status, 404);
});

test("owner can add a member by email; the member then sees the org", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  // The owner needs a paid plan here specifically: FREE's team-member limit
  // is 1 (the owner alone), so adding any member at all requires BUILD or
  // PROTECT — see billing/entitlements.ts's getTeamMemberLimit.
  const { token: ownerToken } = await userAndToken("org-add-owner@example.com", true);
  const { user: member, token: memberToken } = await userAndToken("org-add-member@example.com", false);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  const addRes = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-add-member@example.com" }),
  });
  assert.equal(addRes.status, 201);
  const added = (await addRes.json()) as any;
  assert.equal(added.member.userId, member.id);
  assert.equal(added.member.role, "member");

  const detailRes = await fetch(`${base}/api/organizations/${org.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(detailRes.status, 200);
  const detail = (await detailRes.json()) as any;
  assert.equal(detail.role, "member");
  assert.equal(detail.members.length, 2);
});

test("adding a member requires an existing Nettle account (404), and rejects a duplicate add (409)", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  // Paid owner — see the "owner can add a member" test above for why.
  const { token: ownerToken } = await userAndToken("org-add2-owner@example.com", true);
  await userAndToken("org-add2-member@example.com", false);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  const noSuchUserRes = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "no-such-user@example.com" }),
  });
  assert.equal(noSuchUserRes.status, 404);

  const firstAdd = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-add2-member@example.com" }),
  });
  assert.equal(firstAdd.status, 201);

  const duplicateAdd = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-add2-member@example.com" }),
  });
  assert.equal(duplicateAdd.status, 409);
});

test("a member (not owner) cannot add members, remove members, or rename the org", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  // Paid owner — see the "owner can add a member" test above for why.
  const { token: ownerToken } = await userAndToken("org-perm-owner@example.com", true);
  const { user: member, token: memberToken } = await userAndToken("org-perm-member@example.com", false);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-perm-member@example.com" }),
  });

  const renameRes = await fetch(`${base}/api/organizations/${org.id}`, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${memberToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Hijacked" }),
  });
  assert.equal(renameRes.status, 403);

  const addRes = await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${memberToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-perm-owner@example.com" }),
  });
  assert.equal(addRes.status, 403);

  const removeRes = await fetch(`${base}/api/organizations/${org.id}/members/${member.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${memberToken}` },
  });
  assert.equal(removeRes.status, 403);
});

test("the organization's owner cannot be removed via the member-removal endpoint", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { user: owner, token: ownerToken } = await userAndToken("org-remove-owner@example.com", false);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  const res = await fetch(`${base}/api/organizations/${org.id}/members/${owner.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  assert.equal(res.status, 400);
});

// --- project access under an organization ---

test("POST /api/projects with organizationId requires membership in that org (403 otherwise)", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("org-proj-owner@example.com", true);
  const { token: outsiderToken } = await userAndToken("org-proj-outsider@example.com", true);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${outsiderToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Shared App", organizationId: org.id }),
  });
  assert.equal(res.status, 403);
});

test("a project created under an organization is visible to every member, not just its creator, and invisible to a non-member", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("org-visible-owner@example.com", true);
  const { token: memberToken } = await userAndToken("org-visible-member@example.com", true);
  const { token: outsiderToken } = await userAndToken("org-visible-outsider@example.com", true);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-visible-member@example.com" }),
  });

  const projRes = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Shared App", organizationId: org.id }),
  });
  assert.equal(projRes.status, 201);
  const project = (await projRes.json()) as any;
  assert.equal(project.organizationId, org.id);

  // The member (who did not create it) can still see and reach it.
  const memberListRes = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${memberToken}` } });
  const memberList = (await memberListRes.json()) as any;
  assert.ok(memberList.projects.some((p: any) => p.id === project.id));

  const memberDetailRes = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(memberDetailRes.status, 200);

  // A non-member gets 404 for the same project.
  const outsiderDetailRes = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${outsiderToken}` } });
  assert.equal(outsiderDetailRes.status, 404);
});

test("removing a member revokes their access to that organization's projects", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("org-revoke-owner@example.com", true);
  const { user: member, token: memberToken } = await userAndToken("org-revoke-member@example.com", true);

  const createRes = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Acme Corp" }),
  });
  const org = ((await createRes.json()) as any).organization;

  await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "org-revoke-member@example.com" }),
  });

  const projRes = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Shared App", organizationId: org.id }),
  });
  const project = (await projRes.json()) as any;

  // Access confirmed before removal.
  const before = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(before.status, 200);

  const removeRes = await fetch(`${base}/api/organizations/${org.id}/members/${member.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  assert.equal(removeRes.status, 204);

  const after = await fetch(`${base}/api/projects/${project.id}`, { headers: { Authorization: `Bearer ${memberToken}` } });
  assert.equal(after.status, 404);
});

test("a personal project (no organizationId) is unaffected by organization membership logic", async (t) => {
  const { server, base } = await setUp();
  t.after(() => server.close());

  const { token } = await userAndToken("org-personal@example.com", true);

  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Just Mine" }),
  });
  assert.equal(res.status, 201);
  const project = (await res.json()) as any;
  assert.equal(project.organizationId, null);
});
