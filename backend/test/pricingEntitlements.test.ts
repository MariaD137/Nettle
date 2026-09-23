// End-to-end coverage of the pricing spec's explicit test checklist that
// isn't already covered by paywall.test.ts (route-level gating),
// scanQuota.test.ts (the atomic reservation primitive), or
// subscription-entitlement.test.ts (entitledPlan resolution). This file
// covers: BUILD's exact 10-scan cap through the real HTTP endpoint,
// PROTECT's uncapped scanning, project-limit enforcement per plan
// (including PROTECT's unlimited), downgrade preserving data while
// blocking new creation and PROTECT-only functionality, events ingestion
// being genuinely PROTECT-only (not just FREE-blocked), and that a
// client-supplied plan value cannot grant access the account isn't
// actually entitled to.
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
import { createProject } from "../src/patrol/projects";
import { scansRouter } from "../src/routes/scans.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { eventsRouter } from "../src/routes/events.routes";
import { findProjectByApiKey } from "../src/patrol/projects";

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
  app.use(scansRouter);
  app.use(projectsRouter);
  app.use(eventsRouter);
  return app;
}

const PASSWORD = "correct horse battery staple";

// A minimal, fast-to-scan fixture — these tests run many scans each, and
// this repo's clean-app fixture (no deliberate flaws) scans much faster
// than the larger sample-app fixture other suites use for finding content.
let zipPath: string;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-pricing-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "clean-app"], { cwd: path.join(__dirname, "fixtures") });
});

async function subscriber(email: string, plan: "build" | "protect") {
  const user = await createUser(email, PASSWORD);
  await setSubscriptionStatus(user.id, plan, "active");
  const token = await createSession(user.id);
  return { user: (await getUserById(user.id))!, token };
}

async function scanAs(base: string, token: string) {
  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  return { status: res.status, body: (await res.json()) as any };
}

// --- BUILD: exactly 10 scans, 11th rejected, through the real endpoint ----

test("BUILD: exactly 10 scans succeed in a billing period, the 11th is rejected", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-build-cap@example.com", "build");

  for (let i = 1; i <= 10; i++) {
    const res = await scanAs(base, token);
    assert.equal(res.status, 200, `scan ${i} of 10 should succeed`);
  }

  const eleventh = await scanAs(base, token);
  assert.equal(eleventh.status, 402);
  assert.equal(eleventh.body.quotaExceeded, true);
  assert.equal(eleventh.body.limit, 10);
  assert.equal(eleventh.body.requiredPlan, "protect");
});

test("BUILD: concurrent scan requests near the limit cannot exceed the allowance", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-build-race@example.com", "build");

  // 8 scans up front sequentially, leaving exactly 2 slots, then 10
  // concurrent requests racing for those 2 — the master spec's explicit
  // scenario: two (or more) simultaneous scan requests must not both
  // consume the final available scan.
  for (let i = 0; i < 8; i++) {
    const res = await scanAs(base, token);
    assert.equal(res.status, 200);
  }

  const results = await Promise.all(Array.from({ length: 10 }, () => scanAs(base, token)));
  const succeeded = results.filter((r) => r.status === 200).length;
  assert.equal(succeeded, 2, `expected exactly 2 of 10 concurrent requests to succeed (the 2 remaining slots), got ${succeeded}`);
});

// --- PROTECT: no numeric cap -------------------------------------------

test("PROTECT: scans continue succeeding past BUILD's numeric cap — no hidden ceiling", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-protect-uncapped@example.com", "protect");

  // 12 scans — more than BUILD's 10-scan allowance — all must succeed.
  for (let i = 1; i <= 12; i++) {
    const res = await scanAs(base, token);
    assert.equal(res.status, 200, `PROTECT scan ${i} of 12 should succeed — no numeric cap`);
  }
});

// --- Project limits per plan --------------------------------------------

async function createProjectAs(base: string, token: string, name: string) {
  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  return { status: res.status, body: (await res.json()) as any };
}

test("BUILD: up to 3 projects succeed, the 4th is blocked", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-build-projects@example.com", "build");

  for (let i = 1; i <= 3; i++) {
    const res = await createProjectAs(base, token, `Project ${i}`);
    assert.equal(res.status, 201, `project ${i} of 3 should succeed`);
  }
  const fourth = await createProjectAs(base, token, "Project 4");
  assert.equal(fourth.status, 403);
  assert.equal(fourth.body.projectLimitReached, true);
  assert.equal(fourth.body.limit, 3);
});

test("PROTECT: project creation has no numeric ceiling", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-protect-projects@example.com", "protect");

  // 5 — more than BUILD's limit of 3 — all must succeed.
  for (let i = 1; i <= 5; i++) {
    const res = await createProjectAs(base, token, `Unlimited Project ${i}`);
    assert.equal(res.status, 201, `project ${i} of 5 should succeed under PROTECT's unlimited entitlement`);
  }
});

// --- Downgrade: preserve data, block new creation, revoke PROTECT-only --

test("downgrade from PROTECT to BUILD preserves existing projects, blocks new ones beyond BUILD's limit, and revokes PROTECT-only access", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("pricing-downgrade@example.com", "protect");

  // While on PROTECT: 5 projects, more than BUILD would ever allow.
  const projectIds: string[] = [];
  for (let i = 1; i <= 5; i++) {
    const res = await createProjectAs(base, token, `Downgrade Project ${i}`);
    assert.equal(res.status, 201);
    projectIds.push(res.body.id);
  }

  // PROTECT-only route works while still on PROTECT.
  const alertsWhileProtect = await fetch(`${base}/api/projects/${projectIds[0]}/alerts`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(alertsWhileProtect.status, 200);

  // Downgrade to BUILD (mirrors what a real Stripe subscription.updated
  // webhook does on a plan change).
  await setSubscriptionStatus(user.id, "build", "active");

  // All 5 pre-existing projects are still there — downgrade never deletes data.
  const listRes = await fetch(`${base}/api/projects`, { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(listRes.status, 200);
  const listed = ((await listRes.json()) as any).projects;
  assert.equal(listed.length, 5, "all 5 projects survive the downgrade");
  for (const id of projectIds) {
    assert.ok(listed.some((p: any) => p.id === id), `project ${id} must still be listed after downgrade`);
  }

  // A 6th project is blocked — BUILD's limit (3) is already exceeded by the
  // preserved 5, so creation is blocked, not silently allowed up to a
  // recalculated ceiling.
  const sixth = await createProjectAs(base, token, "Downgrade Project 6");
  assert.equal(sixth.status, 403);
  assert.equal(sixth.body.projectLimitReached, true);

  // PROTECT-only alerts route is no longer reachable — BUILD alone doesn't
  // satisfy it, even though the alert data itself (from while on PROTECT)
  // still exists in the database, untouched.
  const alertsAfterDowngrade = await fetch(`${base}/api/projects/${projectIds[0]}/alerts`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(alertsAfterDowngrade.status, 402);
  assert.equal((await alertsAfterDowngrade.json()).requiredPlan, "protect");
});

// --- Continuous monitoring is genuinely PROTECT-only, not just FREE-blocked

test("POST /api/events rejects BUILD, not just FREE — continuous monitoring is PROTECT-only", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { user, token } = await subscriber("pricing-events-build@example.com", "build");
  const projectRes = await createProjectAs(base, token, "Monitored Project");
  const project = await findProjectByApiKey((projectRes.body as any).apiKey);
  assert.ok(project);

  const res = await fetch(`${base}/api/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-nettle-api-key": project!.apiKey },
    body: JSON.stringify({ ip: "203.0.113.9", method: "GET", path: "/", statusCode: 200 }),
  });
  assert.equal(res.status, 402);
  assert.equal((await res.json()).requiredPlan, "protect");

  // And PROTECT genuinely works.
  await setSubscriptionStatus(user.id, "protect", "active");
  const protectRes = await fetch(`${base}/api/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-nettle-api-key": project!.apiKey },
    body: JSON.stringify({ ip: "203.0.113.9", method: "GET", path: "/", statusCode: 200 }),
  });
  assert.equal(protectRes.status, 202);
});

// --- Security: a client-supplied plan value grants nothing ----------------

test("a client-supplied plan value in the request body/headers cannot grant paid access", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const { token } = await subscriber("pricing-spoof@example.com", "build");
  // Genuinely FREE — no subscription at all.
  const free = await createUser("pricing-spoof-free@example.com", PASSWORD);
  const freeToken = await createSession(free.id);

  // Forging a "plan" field in the project-creation body does nothing — the
  // server resolves entitlement from the session's user id, never from
  // anything the client sends.
  const res = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${freeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Spoofed", plan: "protect", userPlan: "protect", entitledPlan: "protect" }),
  });
  assert.equal(res.status, 201, "the first project for a genuinely FREE account still succeeds (FREE gets 1)");

  // The second project for the same (still actually FREE) account is still
  // blocked, regardless of what the body claims.
  const second = await fetch(`${base}/api/projects`, {
    method: "POST",
    headers: { Authorization: `Bearer ${freeToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Spoofed 2", plan: "protect" }),
  });
  assert.equal(second.status, 403, "a client-claimed plan in the body must not override the real, session-resolved entitlement");

  // Also try a bogus header some client might invent.
  const scanRes = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${freeToken}`, "x-nettle-plan": "protect", "x-user-plan": "build" } as any,
    body: (() => {
      const form = new FormData();
      form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
      return form;
    })(),
  });
  assert.equal(scanRes.status, 402, "an invented plan header must not grant scan access to a genuinely FREE account");

  // Sanity: the legitimately paid token from the top of this test is
  // completely unaffected by any of the above.
  const legitScan = await scanAs(base, token);
  assert.equal(legitScan.status, 200);
});
