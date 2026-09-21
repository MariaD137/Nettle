import { test, before } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus, getUserById } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { entitledPlan, hasActiveSubscription } from "../src/billing/subscription";
import { scansRouter } from "../src/routes/scans.routes";

// Regression suite for the entitlement bug: `users.plan` stays populated after
// a subscription ends, and POST /api/scans keyed its report trimming off that
// raw plan. A canceled account therefore kept receiving the full paid report
// indefinitely, even though every dashboard route correctly returned 402.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

// A zip of the deliberately-flawed fixture, so the report has enough findings
// that a preview is visibly smaller than the full report.
let zipPath: string;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-entitlement-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "sample-app"], {
    cwd: path.join(__dirname, "fixtures"),
  });
});

async function scanAs(base: string, token?: string) {
  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });
  return { status: res.status, body: (await res.json()) as any };
}

async function userWith(email: string, plan: string, status: string) {
  const user = await createUser(email, "correct horse battery staple");
  if (plan !== "free") await setSubscriptionStatus(user.id, plan, status);
  return { user: (await getUserById(user.id))!, token: await createSession(user.id) };
}

// --- the rule itself, across every state the billing model can be in ---

test("entitledPlan: an active paid subscription keeps its plan", async () => {
  const { user } = await userWith("ent-active@example.com", "tier1", "active");
  assert.equal(entitledPlan(user), "tier1");
  assert.equal(hasActiveSubscription(user), true);
});

test("entitledPlan: a trialing subscription keeps its plan", async () => {
  const { user } = await userWith("ent-trialing@example.com", "tier2", "trialing");
  assert.equal(entitledPlan(user), "tier2");
});

test("entitledPlan: a canceled subscription drops to free", async () => {
  const { user } = await userWith("ent-canceled@example.com", "tier1", "canceled");
  assert.equal(user.plan, "tier1", "the purchased plan is still recorded for reconciliation");
  assert.equal(entitledPlan(user), "free", "but it no longer grants anything");
});

test("entitledPlan: a past_due subscription drops to free", async () => {
  const { user } = await userWith("ent-pastdue@example.com", "tier2", "past_due");
  assert.equal(entitledPlan(user), "free");
});

test("entitledPlan: an unpaid/incomplete subscription drops to free", async () => {
  const { user } = await userWith("ent-unpaid@example.com", "tier1", "unpaid");
  assert.equal(entitledPlan(user), "free");
});

test("entitledPlan: a never-subscribed free account is free", async () => {
  const { user } = await userWith("ent-free@example.com", "free", "none");
  assert.equal(entitledPlan(user), "free");
});

test("entitledPlan: an anonymous caller is free", () => {
  assert.equal(entitledPlan(null), "free");
});

// --- the same rule as observed through POST /api/scans ---

test("POST /api/scans enforces entitlement, not the recorded plan", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const active = await userWith("scan-active@example.com", "tier1", "active");
  const canceled = await userWith("scan-canceled@example.com", "tier1", "canceled");
  const pastDue = await userWith("scan-pastdue@example.com", "tier2", "past_due");
  const free = await userWith("scan-free@example.com", "free", "none");

  const activeRes = await scanAs(base, active.token);
  assert.equal(activeRes.status, 200);
  assert.equal(activeRes.body.access.tier, "full");
  assert.equal(activeRes.body.access.fullReport, true);
  const totalFindings = activeRes.body.access.totalFindings;
  assert.ok(totalFindings > 3, "fixture must produce more findings than a preview shows");

  // The regression: same plan string as the active user, no longer paying.
  const canceledRes = await scanAs(base, canceled.token);
  assert.equal(canceledRes.status, 200);
  assert.equal(canceledRes.body.access.tier, "preview", "canceled must not receive the full report");
  assert.equal(canceledRes.body.access.fullReport, false);
  assert.ok(canceledRes.body.access.lockedFindings > 0);
  assert.ok(canceledRes.body.findings.length < totalFindings);

  const pastDueRes = await scanAs(base, pastDue.token);
  assert.equal(pastDueRes.body.access.tier, "preview", "a failed payment must not keep paid output");

  const freeRes = await scanAs(base, free.token);
  assert.equal(freeRes.body.access.tier, "preview");

  const anonRes = await scanAs(base);
  assert.equal(anonRes.status, 200, "anonymous one-off scans stay supported");
  assert.equal(anonRes.body.access.tier, "preview");
});
