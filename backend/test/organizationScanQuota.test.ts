// Organization-aware scan quotas: a project owned by an actively-subscribed
// organization draws from that organization's own shared monthly allowance
// — every member's scans pool against ONE limit, not one limit each —
// falling back to the pre-existing per-user model for a personal project
// or an unsubscribed organization's project. Mirrors scanQuota.test.ts's
// direct-function-call style (fast, precise, no HTTP/Semgrep needed) for
// the reservation/counting mechanics, plus a couple of end-to-end HTTP
// tests proving the real route wiring (routes/scans.routes.ts) actually
// uses this.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createOrganization, addMember, getOrganization, setOrgSubscriptionStatus } from "../src/organizations/organizations";
import { createProject } from "../src/patrol/projects";
import { db } from "../src/db";
import {
  SCAN_QUOTAS,
  reserveOrgScanSlot,
  getOrgQuotaState,
  countOrgScanUsage,
  recordQuotaUsage,
  getQuotaState,
  type QuotaSubject,
} from "../src/billing/scanQuota";
import { resolveQuotaSubject } from "../src/billing/orgSubscription";
import { organizationsRouter } from "../src/routes/organizations.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { scansRouter } from "../src/routes/scans.routes";
import { authRouter } from "../src/routes/auth.routes";
import { billingRouter, billingWebhookRouter } from "../src/routes/billing.routes";
import { flushScanQueue } from "../src/scanner/scanQueue";

const PASSWORD = "correct horse battery staple";

async function subscribedOwner(email: string, plan: "build" | "protect" = "build") {
  const user = await createUser(email, PASSWORD);
  await setSubscriptionStatus(user.id, plan, "active");
  return user;
}

/** Backdates an organization's billing_anchor directly, the same way organizationInvitations.test.ts backdates expires_at, since setOrgSubscriptionStatus always stamps "now". */
async function backdateOrgAnchor(organizationId: string, isoDate: string) {
  await db.run("UPDATE organizations SET billing_anchor = ? WHERE id = ?", [isoDate, organizationId]);
}

// --- Direct function tests: reservation, counting, resolution --------------

test("resolveQuotaSubject: an org-owned project under an actively-subscribed organization resolves to that organization", async () => {
  const owner = await createUser("resolve-org-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Acme Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  const { subject, plan } = await resolveQuotaSubject(owner.id, { organizationId: org.id }, "free");
  assert.deepEqual(subject, { type: "organization", organizationId: org.id });
  assert.equal(plan, "build");
});

test("resolveQuotaSubject: an unsubscribed organization's project falls back to the caller's personal plan", async () => {
  const owner = await createUser("resolve-unsub-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "No Sub Corp");
  // Never subscribed — org.plan stays 'free'.

  const { subject, plan } = await resolveQuotaSubject(owner.id, { organizationId: org.id }, "build");
  assert.deepEqual(subject, { type: "user", userId: owner.id });
  assert.equal(plan, "build", "falls back to the fallbackPlan the caller already computed");
});

test("resolveQuotaSubject: a personal project (no organizationId) always resolves to the user", async () => {
  const { subject, plan } = await resolveQuotaSubject("user-1", null, "protect");
  assert.deepEqual(subject, { type: "user", userId: "user-1" });
  assert.equal(plan, "protect");
});

test("reserveOrgScanSlot allows exactly up to the limit and rejects beyond it", async () => {
  const owner = await createUser("reserve-org-basic-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Basic Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");
  const limit = 3;

  assert.equal(await reserveOrgScanSlot(org.id, limit), true);
  assert.equal(await reserveOrgScanSlot(org.id, limit), true);
  assert.equal(await reserveOrgScanSlot(org.id, limit), true);
  assert.equal(await reserveOrgScanSlot(org.id, limit), false, "the 4th reservation against a limit of 3 must fail");
});

test("reserveOrgScanSlot: 5 members submitting simultaneously for the last slot — exactly one wins", async () => {
  const owner = await createUser("reserve-org-race-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Race Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");
  const limit = 10;

  // 9 already consumed (mirrors the master spec's own example: 10 allowed, 9 used).
  for (let i = 0; i < 9; i++) assert.equal(await reserveOrgScanSlot(org.id, limit), true);

  // 5 different members racing for the one remaining slot.
  const results = await Promise.all(Array.from({ length: 5 }, () => reserveOrgScanSlot(org.id, limit)));
  const wins = results.filter(Boolean).length;
  assert.equal(wins, 1, `expected exactly 1 of 5 concurrent member requests to win the last slot, got ${wins}`);
});

test("reserveOrgScanSlot is scoped per organization — one organization's burst never affects another's allowance", async () => {
  const owner = await createUser("reserve-org-scope-owner@example.com", PASSWORD);
  const orgA = await createOrganization(owner.id, "Org A");
  const orgB = await createOrganization(owner.id, "Org B");
  await setOrgSubscriptionStatus(orgA.id, "build", "active");
  await setOrgSubscriptionStatus(orgB.id, "build", "active");
  const limit = 2;

  const orgAResults = await Promise.all(Array.from({ length: 5 }, () => reserveOrgScanSlot(orgA.id, limit)));
  assert.equal(orgAResults.filter(Boolean).length, 2);

  // Org B's allowance is untouched by Org A's burst.
  assert.equal(await reserveOrgScanSlot(orgB.id, limit), true);
  assert.equal(await reserveOrgScanSlot(orgB.id, limit), true);
  assert.equal(await reserveOrgScanSlot(orgB.id, limit), false);
});

test("organization member sharing: Maria (4) + John (3) + Sarah (2) pool against ONE 10-scan allowance, not 10 each", async () => {
  const owner = await createUser("pooling-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Pooling Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  const maria = await createUser("pooling-maria@example.com", PASSWORD);
  const john = await createUser("pooling-john@example.com", PASSWORD);
  const sarah = await createUser("pooling-sarah@example.com", PASSWORD);
  await addMember(org.id, maria.id);
  await addMember(org.id, john.id);
  await addMember(org.id, sarah.id);

  const orgSubject: QuotaSubject = { type: "organization", organizationId: org.id };
  for (let i = 0; i < 4; i++) await recordQuotaUsage(orgSubject, maria.id, null, "upload");
  for (let i = 0; i < 3; i++) await recordQuotaUsage(orgSubject, john.id, null, "upload");
  for (let i = 0; i < 2; i++) await recordQuotaUsage(orgSubject, sarah.id, null, "upload");

  const state = (await getOrgQuotaState(org.id, "build"))!;
  assert.equal(state.used, 9, "9 total across all three members, not 9 each");
  assert.equal(state.remaining, 1);
  assert.equal(state.exhausted, false);

  // None of the three members' OWN personal quotas were touched — they
  // never had their individual 10-scan allowance consumed at all.
  assert.equal((await getQuotaState(maria.id))!.used, 0);
  assert.equal((await getQuotaState(john.id))!.used, 0);
  assert.equal((await getQuotaState(sarah.id))!.used, 0);
});

test("organization upgrade: build (10) to protect (unlimited) raises the shared limit for every member immediately", async () => {
  const owner = await createUser("org-upgrade-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Upgrade Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  const orgSubject: QuotaSubject = { type: "organization", organizationId: org.id };
  for (let i = 0; i < 10; i++) assert.equal(await reserveOrgScanSlot(org.id, SCAN_QUOTAS.build), true);
  assert.equal(await reserveOrgScanSlot(org.id, SCAN_QUOTAS.build), false, "exhausted at 10 under BUILD");

  await setOrgSubscriptionStatus(org.id, "protect", "active");
  const stateAfterUpgrade = (await getOrgQuotaState(org.id, "protect"))!;
  assert.equal(stateAfterUpgrade.limit, null, "PROTECT is unlimited/fair-use, never a large number standing in for it");
  assert.equal(stateAfterUpgrade.exhausted, false);
  void orgSubject;
});

test("organization downgrade/cancellation: enforced going forward, all data preserved", async () => {
  const owner = await createUser("org-downgrade-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Downgrade Corp");
  await setOrgSubscriptionStatus(org.id, "protect", "active");

  const project = await createProject(owner.id, "Downgrade Project", { organizationId: org.id });
  const orgSubject: QuotaSubject = { type: "organization", organizationId: org.id };
  await recordQuotaUsage(orgSubject, owner.id, project.id, "upload");
  await recordQuotaUsage(orgSubject, owner.id, project.id, "upload");

  // Cancel the organization's subscription entirely.
  await setOrgSubscriptionStatus(org.id, "protect", "canceled");

  // Historical usage/records are preserved — never deleted on downgrade.
  const since = new Date("2000-01-01T00:00:00Z");
  assert.equal(await countOrgScanUsage(org.id, since), 2, "usage history survives cancellation");
  assert.ok(await getOrganization(org.id), "the organization itself is never deleted");

  // Going forward, the organization no longer qualifies as an active quota
  // subject at all — resolveQuotaSubject falls back to the caller's own
  // personal plan (here, still FREE — the owner never had a personal
  // subscription).
  const { subject, plan } = await resolveQuotaSubject(owner.id, { organizationId: org.id }, "free");
  assert.deepEqual(subject, { type: "user", userId: owner.id });
  assert.equal(plan, "free");
});

test("billing period reset: a new period gives the organization a fresh allowance without touching prior history", async () => {
  const owner = await createUser("org-period-owner@example.com", PASSWORD);
  const org = await createOrganization(owner.id, "Period Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  // Backdate the anchor two full months so "now" falls in a later period.
  await backdateOrgAnchor(org.id, new Date(Date.now() - 62 * 24 * 60 * 60 * 1000).toISOString());

  // Reservation (bucket, enforcement) and usage recording (scan_usage,
  // display) are separate primitives in production too — a real scan
  // does both, so this test does too rather than asserting `used` off
  // reservations alone.
  const orgSubject: QuotaSubject = { type: "organization", organizationId: org.id };
  const limit = SCAN_QUOTAS.build;
  for (let i = 0; i < limit; i++) {
    assert.equal(await reserveOrgScanSlot(org.id, limit), true);
    await recordQuotaUsage(orgSubject, owner.id, null, "upload");
  }
  assert.equal(await reserveOrgScanSlot(org.id, limit), false, "exhausted in the (backdated) current period");

  const state = (await getOrgQuotaState(org.id, "build"))!;
  // The period the reservations landed in is NOT the original anchor month
  // two months ago — currentPeriod() rolled forward to contain "now".
  assert.ok(new Date(state.periodStart).getTime() > Date.now() - 62 * 24 * 60 * 60 * 1000);
  assert.equal(state.used, limit);
});

test("multiple organizations: a project's entitlement draws ONLY from its own organization's pool, never a different one the same user belongs to", async () => {
  const owner = await createUser("multi-org-owner@example.com", PASSWORD);
  const subscribedOrg = await createOrganization(owner.id, "Subscribed Org");
  const otherOrg = await createOrganization(owner.id, "Other Org");
  await setOrgSubscriptionStatus(subscribedOrg.id, "build", "active");
  await setOrgSubscriptionStatus(otherOrg.id, "build", "active");

  // Exhaust the FIRST organization's allowance entirely.
  for (let i = 0; i < SCAN_QUOTAS.build; i++) assert.equal(await reserveOrgScanSlot(subscribedOrg.id, SCAN_QUOTAS.build), true);
  assert.equal(await reserveOrgScanSlot(subscribedOrg.id, SCAN_QUOTAS.build), false);

  // The second organization's allowance is completely untouched.
  const otherState = (await getOrgQuotaState(otherOrg.id, "build"))!;
  assert.equal(otherState.used, 0);
  assert.equal(otherState.remaining, SCAN_QUOTAS.build);
});

test("personal project vs organization project: the same user's scans against each draw from independent allowances", async () => {
  const owner = await createUser("personal-vs-org-owner@example.com", PASSWORD);
  await setSubscriptionStatus(owner.id, "build", "active"); // personal BUILD subscription
  const org = await createOrganization(owner.id, "Personal Vs Org Corp");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  const personalProject = await createProject(owner.id, "Personal Project");
  const orgProject = await createProject(owner.id, "Org Project", { organizationId: org.id });

  const { subject: personalSubject } = await resolveQuotaSubject(owner.id, personalProject, "build");
  const { subject: orgSubject } = await resolveQuotaSubject(owner.id, orgProject, "build");
  assert.deepEqual(personalSubject, { type: "user", userId: owner.id });
  assert.deepEqual(orgSubject, { type: "organization", organizationId: org.id });

  await recordQuotaUsage(personalSubject, owner.id, personalProject.id, "upload");
  await recordQuotaUsage(personalSubject, owner.id, personalProject.id, "upload");
  await recordQuotaUsage(orgSubject, owner.id, orgProject.id, "upload");

  assert.equal((await getQuotaState(owner.id))!.used, 2, "only the personal-project scans count against the owner's own quota");
  assert.equal((await getOrgQuotaState(org.id, "build"))!.used, 1, "only the org-project scan counts against the organization's pool");
});

// --- End-to-end HTTP: proves routes/scans.routes.ts actually uses this ----

let zipPath: string;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-org-quota-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "sample-app"], { cwd: path.join(__dirname, "fixtures") });
});

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(billingWebhookRouter);
  app.use(express.json());
  app.use(organizationsRouter);
  app.use(projectsRouter);
  app.use(scansRouter);
  app.use(authRouter);
  app.use(billingRouter);
  return app;
}

async function createOrgProject(base: string, token: string, organizationId: string, name: string) {
  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name, organizationId }),
  });
  assert.equal(res.status, 201, JSON.stringify(await res.clone().json()));
  return res.json() as Promise<{ id: string; apiKey: string }>;
}

test("HTTP: a FREE member's project-tied scan against a PROTECT-subscribed organization's project is accepted, not 402", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const owner = await subscribedOwner("http-org-quota-owner@example.com", "protect");
  const org = await createOrganization(owner.id, "HTTP Org");
  await setOrgSubscriptionStatus(org.id, "protect", "active");

  const freeMember = await createUser("http-org-quota-member@example.com", PASSWORD);
  await addMember(org.id, freeMember.id);
  const ownerToken = await createSession(owner.id);
  const memberToken = await createSession(freeMember.id);
  void memberToken;

  const project = await createOrgProject(base, ownerToken, org.id, "HTTP Org Project");

  // The FREE member submits a scan authenticated only by the project's own
  // API key (the CI/CD path) — no personal subscription of their own.
  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");

  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { "x-nettle-api-key": project.apiKey },
    body: form,
  });

  // 202 (queued) — not 402 — proves the organization's own PROTECT
  // subscription governs this project-tied scan, not the triggering
  // member's personal (FREE) plan.
  assert.equal(res.status, 202, JSON.stringify(await res.clone().json().catch(() => null)));
  await flushScanQueue();
});

test("HTTP: exhausting an organization's shared BUILD allowance blocks further org-project scans with a real 402", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const owner = await subscribedOwner("http-org-exhaust-owner@example.com", "build");
  const org = await createOrganization(owner.id, "HTTP Exhaust Org");
  await setOrgSubscriptionStatus(org.id, "build", "active");

  const ownerToken = await createSession(owner.id);
  const project = await createOrgProject(base, ownerToken, org.id, "HTTP Exhaust Project");

  const orgSubject: QuotaSubject = { type: "organization", organizationId: org.id };
  for (let i = 0; i < SCAN_QUOTAS.build; i++) assert.equal(await reserveOrgScanSlot(org.id, SCAN_QUOTAS.build), true);
  void orgSubject;

  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");

  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { "x-nettle-api-key": project.apiKey },
    body: form,
  });

  assert.equal(res.status, 402);
  const body = (await res.json()) as any;
  assert.equal(body.quotaExceeded, true);
  assert.match(body.error, /organization/i, "the error must name the organization, not the individual caller");
});

test("HTTP: unauthorized quota manipulation — a client cannot redirect its scan onto a different organization's quota via request body", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const owner = await subscribedOwner("http-quota-manip-owner@example.com", "build");
  const realOrg = await createOrganization(owner.id, "Real Org");
  const victimOrg = await createOrganization(owner.id, "Victim Org");
  await setOrgSubscriptionStatus(realOrg.id, "build", "active");
  await setOrgSubscriptionStatus(victimOrg.id, "build", "active");

  const ownerToken = await createSession(owner.id);
  const project = await createOrgProject(base, ownerToken, realOrg.id, "Real Org Project");

  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  // organizationId is not even a recognized field on this endpoint, but the
  // point is: quota resolution never reads ANY client-supplied value — only
  // the project the API key actually resolves to (routes/scans.routes.ts ->
  // findProjectByApiKey -> resolveQuotaSubject).
  form.append("organizationId", victimOrg.id);

  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { "x-nettle-api-key": project.apiKey },
    body: form,
  });
  assert.equal(res.status, 202, JSON.stringify(await res.clone().json().catch(() => null)));
  await flushScanQueue();

  // The victim organization's allowance is completely untouched.
  const victimState = (await getOrgQuotaState(victimOrg.id, "build"))!;
  assert.equal(victimState.used, 0);

  // The real organization's allowance is what actually got consumed.
  const realState = (await getOrgQuotaState(realOrg.id, "build"))!;
  assert.equal(realState.used, 1);
});
