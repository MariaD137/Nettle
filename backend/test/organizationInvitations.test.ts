// Organization invitations (master spec Phase 2): security requirements
// checked directly against the real HTTP routes, not just the storage
// layer — token security, single-use, expiry, server-side authorization,
// and specifically the abuse cases the spec calls out: double acceptance,
// expired tokens, wrong-organization/privilege-escalation, and
// unauthorized invitation creation.
import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { organizationsRouter } from "../src/routes/organizations.routes";
import { createInvitation } from "../src/organizations/invitations";
import { db } from "../src/db";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(organizationsRouter);
  return app;
}

const PASSWORD = "correct horse battery staple";

async function userAndToken(email: string) {
  const user = await createUser(email, PASSWORD);
  const token = await createSession(user.id);
  return { user, token };
}

// FREE's team-member limit is 1 (the owner alone — see
// billing/entitlements.ts), so any test that actually needs to invite and
// accept needs the owner on a paid plan first. Only the "team limit
// reached" test itself wants a FREE owner.
async function subscribedOwner(email: string) {
  const { user, token } = await userAndToken(email);
  await setSubscriptionStatus(user.id, "build", "active");
  return { user, token };
}

async function createOrg(base: string, token: string, name: string) {
  const res = await fetch(`${base}/api/organizations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  return ((await res.json()) as any).organization;
}

test("owner can invite by email; the invitation is created but the raw token never appears in the response", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await subscribedOwner("invite-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");

  const res = await fetch(`${base}/api/organizations/${org.id}/invitations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "invitee@example.com" }),
  });
  assert.equal(res.status, 201);
  const body = (await res.json()) as any;
  assert.equal(body.invitation.email, "invitee@example.com");
  assert.equal(body.invitation.role, "member");
  assert.equal(body.delivered, false, "no EMAIL_FROM_ADDRESS configured in tests");
  // The response body must never contain anything that looks like the raw
  // 64-hex-char token — only the DB has (a hash of) it.
  assert.doesNotMatch(JSON.stringify(body), /^[0-9a-f]{64}$/m);

  const stored = await db.all<{ token_hash: string }>("SELECT token_hash FROM organization_invitations", []);
  assert.equal(stored.length, 1);
  assert.doesNotMatch(JSON.stringify(body), new RegExp(stored[0].token_hash));
});

test("a non-owner member cannot create invitations", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await subscribedOwner("invite-perm-owner@example.com");
  const { user: member, token: memberToken } = await userAndToken("invite-perm-member@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");

  // Add the member directly (existing add-by-email path) so there's a real
  // non-owner member to test with.
  await fetch(`${base}/api/organizations/${org.id}/members`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "invite-perm-member@example.com" }),
  });

  const res = await fetch(`${base}/api/organizations/${org.id}/invitations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${memberToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "someone-else@example.com" }),
  });
  assert.equal(res.status, 403, "unauthorized invitation creation must be refused");
  void member;
});

test("a stranger cannot create invitations for an organization they don't belong to at all", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await userAndToken("invite-stranger-owner@example.com");
  const { token: strangerToken } = await userAndToken("invite-stranger@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");

  const res = await fetch(`${base}/api/organizations/${org.id}/invitations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${strangerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "someone@example.com" }),
  });
  assert.equal(res.status, 404, "a non-member gets 404, not 403 — confirming the org exists to a stranger is its own leak");
});

test("accepting an invitation creates the correct membership with the server-determined role, not anything the client asserts", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken } = await subscribedOwner("accept-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { user: invitee, token: inviteeToken } = await userAndToken("accept-invitee@example.com");

  const { token } = await createInvitation(org.id, "accept-invitee@example.com", "member", (await userAndToken("dummy-inviter@example.com")).user.id);

  const res = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
    // A client attempting to assert a different organization/role must be
    // ignored — only the opaque token determines either.
    body: JSON.stringify({ token, organizationId: "some-other-org-id", role: "owner" }),
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;
  assert.equal(body.member.organizationId, org.id, "the organization comes from the token, never from the request body");
  assert.equal(body.member.role, "member", "the role comes from the invitation, never from the request body");
  assert.equal(body.member.userId, invitee.id);

  const detailRes = await fetch(`${base}/api/organizations/${org.id}`, { headers: { Authorization: `Bearer ${inviteeToken}` } });
  assert.equal(detailRes.status, 200);
});

test("an invitation cannot be accepted twice", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken, user: owner } = await subscribedOwner("double-accept-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { token: inviteeToken } = await userAndToken("double-accept-invitee@example.com");
  const { token } = await createInvitation(org.id, "double-accept-invitee@example.com", "member", owner.id);

  const first = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(first.status, 200);

  const second = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(second.status, 409, "a second acceptance of the same token must be refused");
});

test("concurrent acceptance attempts of the same token cannot both create a membership", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken, user: owner } = await subscribedOwner("race-accept-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { token: inviteeToken } = await userAndToken("race-accept-invitee@example.com");
  const { token } = await createInvitation(org.id, "race-accept-invitee@example.com", "member", owner.id);

  const attempts = await Promise.all(
    Array.from({ length: 5 }, () =>
      fetch(`${base}/api/invitations/accept`, {
        method: "POST",
        headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      })
    )
  );
  const succeeded = attempts.filter((r) => r.status === 200).length;
  assert.equal(succeeded, 1, `exactly one concurrent acceptance should succeed, got ${succeeded}`);

  const members = await db.all<{ id: string }>("SELECT id FROM organization_members WHERE organization_id = ? AND user_id != ?", [org.id, owner.id]);
  assert.equal(members.length, 1, "exactly one membership row must exist despite the race");
});

test("an expired invitation cannot be accepted", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken, user: owner } = await userAndToken("expired-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { token: inviteeToken } = await userAndToken("expired-invitee@example.com");
  const { invitation, token } = await createInvitation(org.id, "expired-invitee@example.com", "member", owner.id);

  // Force it into the past — this is what "expires" actually means, tested
  // directly rather than waiting 7 real days.
  await db.run("UPDATE organization_invitations SET expires_at = ? WHERE id = ?", ["2000-01-01T00:00:00.000Z", invitation.id]);

  const res = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(res.status, 410);
});

test("an invitation can only be accepted by the account whose email it was actually sent to — privilege escalation is refused", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken, user: owner } = await userAndToken("escalation-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { token } = await createInvitation(org.id, "the-real-invitee@example.com", "member", owner.id);

  // A completely different account somehow obtains the token (a forwarded
  // email, a leaked link) and tries to use it for themselves.
  const { token: attackerToken } = await userAndToken("attacker@example.com");

  const res = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${attackerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(res.status, 403, "an account whose email doesn't match the invitation must be refused, not silently joined");

  const members = await db.all<{ id: string }>("SELECT id FROM organization_members WHERE organization_id = ?", [org.id]);
  assert.equal(members.length, 1, "only the owner's own membership exists — the attacker was never added");
});

test("a nonexistent or garbage token is refused, not treated as valid", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: userToken } = await userAndToken("garbage-token-user@example.com");
  const res = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${userToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token: "not-a-real-token-at-all" }),
  });
  assert.equal(res.status, 404);
});

test("an invitation token is not predictable — two invitations never produce the same token or a related-looking one", async () => {
  const owner = await createUser("unpredictable-owner@example.com", PASSWORD);
  const org = await (async () => {
    const { createOrganization } = await import("../src/organizations/organizations");
    return createOrganization(owner.id, "Acme Corp");
  })();

  const first = await createInvitation(org.id, "a@example.com", "member", owner.id);
  const second = await createInvitation(org.id, "b@example.com", "member", owner.id);

  assert.notEqual(first.token, second.token);
  assert.equal(first.token.length, 64, "32 bytes of crypto.randomBytes, hex-encoded");
  assert.match(first.token, /^[0-9a-f]{64}$/);
  // Not literally sequential/derivable from each other.
  assert.notEqual(first.token.slice(0, 32), second.token.slice(0, 32));
});

test("revoking a pending invitation makes it unacceptable", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token: ownerToken, user: owner } = await userAndToken("revoke-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");
  const { token: inviteeToken } = await userAndToken("revoke-invitee@example.com");
  const { invitation, token } = await createInvitation(org.id, "revoke-invitee@example.com", "member", owner.id);

  const revokeRes = await fetch(`${base}/api/organizations/${org.id}/invitations/${invitation.id}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${ownerToken}` },
  });
  assert.equal(revokeRes.status, 204);

  const acceptRes = await fetch(`${base}/api/invitations/accept`, {
    method: "POST",
    headers: { Authorization: `Bearer ${inviteeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal(acceptRes.status, 404, "a revoked invitation's token must no longer resolve");
});

test("invitation creation is blocked once the organization's team-member limit is reached", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  // FREE plan (no subscription set) has a team limit of 1 — the owner alone.
  const { token: ownerToken } = await userAndToken("limit-owner@example.com");
  const org = await createOrg(base, ownerToken, "Acme Corp");

  const res = await fetch(`${base}/api/organizations/${org.id}/invitations`, {
    method: "POST",
    headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: "someone@example.com" }),
  });
  assert.equal(res.status, 403);
  assert.equal((await res.json() as any).teamLimitReached, true);
});
