import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { projectsRouter } from "../src/routes/projects.routes";

/**
 * API-level tests for GET /api/projects/:id/scans/compare, wired through the
 * real route, the real database, and (for the regression test, per Phase 6
 * §27's explicit "mandatory") the real scanner run against real source
 * files on disk — not synthetic CheckResult objects.
 */

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

async function subscribedUser(email: string) {
  const user = await createUser(email, "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  const token = await createSession(user.id);
  return { user, token };
}

function writeVulnerableAuthFile(dir: string) {
  fs.writeFileSync(
    path.join(dir, "auth.js"),
    "const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { algorithm: 'none' });\n",
    "utf8"
  );
}

function writeFixedAuthFile(dir: string) {
  fs.writeFileSync(
    path.join(dir, "auth.js"),
    "const jwt = require('jsonwebtoken');\njwt.sign(payload, secret, { algorithm: 'RS256' });\n",
    "utf8"
  );
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("GET /api/projects/:id/scans/compare: FIXED finding carries its original recommendation", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const { user, token } = await subscribedUser("compare-fixed@example.com");
  const project = await createProject(user.id, "Compare Fixed");

  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cmp-a-"));
  writeVulnerableAuthFile(dirA);
  const scanA = await recordScan(project.id, runScan(dirA));
  await sleep(5);

  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cmp-b-"));
  writeFixedAuthFile(dirB);
  const scanB = await recordScan(project.id, runScan(dirB));

  const res = await fetch(`${base}/api/projects/${project.id}/scans/compare?from=${scanA.id}&to=${scanB.id}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();

  assert.equal(body.summary.fixed, 1);
  const authFix = body.fixed.find((f: any) => f.finding.controlKey === "AUTH-002");
  assert.ok(authFix, "the algorithm:'none' finding should be reported FIXED");
  assert.ok(authFix.finding.recommendation, "a FIXED finding must keep its original recommendation, not lose it");
  assert.match(authFix.finding.recommendation.quickFix, /live authentication bypass/);

  fs.rmSync(dirA, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });
});

test("GET /api/projects/:id/scans/compare: a scan id from another project is never found, even inside your own project's compare", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const alice = await subscribedUser("compare-tenant-alice@example.com");
  const bob = await subscribedUser("compare-tenant-bob@example.com");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cmp-x-"));
  writeVulnerableAuthFile(dir);

  const alicesProject = await createProject(alice.user.id, "Alice's Project");
  const alicesScan = await recordScan(alicesProject.id, runScan(dir));
  await sleep(5);
  const alicesScan2 = await recordScan(alicesProject.id, runScan(dir));

  const bobsProject = await createProject(bob.user.id, "Bob's Project");
  const bobsScanA = await recordScan(bobsProject.id, runScan(dir));
  await sleep(5);
  const bobsScanB = await recordScan(bobsProject.id, runScan(dir));

  // Bob, authenticated as himself, tries to compare his own project but
  // supplies one of Alice's real scan ids as the baseline. This must not
  // leak Alice's scan data through Bob's own (legitimately-owned) project.
  const res = await fetch(
    `${base}/api/projects/${bobsProject.id}/scans/compare?from=${alicesScan.id}&to=${bobsScanB.id}`,
    { headers: { Authorization: `Bearer ${bob.token}` } }
  );
  assert.equal(res.status, 404);

  // And the reverse: Bob cannot reach Alice's project at all to compare her scans.
  const res2 = await fetch(
    `${base}/api/projects/${alicesProject.id}/scans/compare?from=${alicesScan.id}&to=${alicesScan2.id}`,
    { headers: { Authorization: `Bearer ${bob.token}` } }
  );
  assert.equal(res2.status, 404);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("end-to-end regression: scan A (open) -> fix -> scan B (fixed) -> reintroduce -> scan C (regressed)", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const { user, token } = await subscribedUser("compare-regression@example.com");
  const project = await createProject(user.id, "Regression Project");

  // Scan A: vulnerability present.
  const dirA = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-regress-a-"));
  writeVulnerableAuthFile(dirA);
  const scanA = await recordScan(project.id, runScan(dirA));
  await sleep(5);

  // Fix the application. Scan B: vulnerability absent.
  const dirB = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-regress-b-"));
  writeFixedAuthFile(dirB);
  const scanB = await recordScan(project.id, runScan(dirB));
  await sleep(5);

  // Reintroduce the vulnerability. Scan C: vulnerability returns.
  const dirC = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-regress-c-"));
  writeVulnerableAuthFile(dirC);
  const scanC = await recordScan(project.id, runScan(dirC));

  async function compare(fromId: string, toId: string) {
    const res = await fetch(`${base}/api/projects/${project.id}/scans/compare?from=${fromId}&to=${toId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    return res.json();
  }

  // A -> B: the finding was fixed.
  const aToB = await compare(scanA.id, scanB.id);
  assert.equal(aToB.summary.fixed, 1, "A -> B must show the AUTH-002 finding as fixed");
  assert.ok(aToB.fixed.some((f: any) => f.finding.controlKey === "AUTH-002"));

  // B -> C: the same finding came back -- a regression, not a fresh NEW finding.
  const bToC = await compare(scanB.id, scanC.id);
  assert.equal(bToC.summary.regressed, 1, "B -> C must show the AUTH-002 finding as regressed");
  assert.equal(bToC.summary.new, 0, "a regression must never be miscounted as NEW");
  const regressedItem = bToC.regressed.find((f: any) => f.finding.controlKey === "AUTH-002");
  assert.ok(regressedItem);
  assert.ok(regressedItem.finding.recommendation, "a regressed finding must still carry its recommendation");

  // A -> C: dirA and dirC are byte-identical, so every finding from A
  // (not just AUTH-002 -- this tiny fixture also trips several generic,
  // content-independent checks like missing rate limiting) legitimately
  // carries over as STILL_OPEN for this wider span; specifically the
  // AUTH-002 finding must be classified STILL_OPEN here, not FIXED or
  // REGRESSED, since the finding-level comparison must not be fooled by the
  // dip in between (§8's REGRESSED wording is about a comparison span that
  // actually starts after a fix, not any span that merely contains one).
  const aToC = await compare(scanA.id, scanC.id);
  assert.equal(aToC.summary.fixed, 0);
  assert.equal(aToC.summary.regressed, 0);
  assert.equal(aToC.summary.new, 0);
  assert.ok(aToC.stillOpen.some((f: any) => f.finding.controlKey === "AUTH-002"));

  fs.rmSync(dirA, { recursive: true, force: true });
  fs.rmSync(dirB, { recursive: true, force: true });
  fs.rmSync(dirC, { recursive: true, force: true });
});

test("GET /api/projects/:id/scans/compare: fewer than 2 scans returns 400, not a crash", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(projectsRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const { user, token } = await subscribedUser("compare-insufficient@example.com");
  const project = await createProject(user.id, "Only One Scan");

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cmp-one-"));
  writeVulnerableAuthFile(dir);
  await recordScan(project.id, runScan(dir));

  const res = await fetch(`${base}/api/projects/${project.id}/scans/compare`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 400);

  fs.rmSync(dir, { recursive: true, force: true });
});
