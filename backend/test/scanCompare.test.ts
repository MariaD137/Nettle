import { test } from "node:test";
import assert from "node:assert/strict";
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

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

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
  app.use(projectsRouter);
  return app;
}

test("GET /api/projects/:id/scans/compare returns remainingFindings alongside fixed/new", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("compare-remaining@example.com", "correct horse battery staple");
    await setSubscriptionStatus(user.id, "tier1", "active");
    const token = await createSession(user.id);
    const project = await createProject(user.id, "Compare Target");

    // Two scans of the SAME (flawed) fixture back to back: nothing is fixed
    // or new between them, so every finding from the first scan should show
    // up as "remaining" on the second, and that array should actually be
    // sent — not just its count.
    const older = runScan(FLAWED_APP);
    older.scannedAt = "2026-01-01T00:00:00.000Z";
    await recordScan(project.id, older);
    assert.ok(older.findings.length > 0, "fixture should produce real findings");

    const newer = runScan(FLAWED_APP);
    newer.scannedAt = "2026-01-02T00:00:00.000Z";
    await recordScan(project.id, newer);

    const res = await fetch(`${base}/api/projects/${project.id}/scans/compare`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.fixed, 0);
    assert.equal(body.new, 0);
    assert.equal(body.remaining, older.findings.length);
    assert.ok(Array.isArray(body.remainingFindings), "remainingFindings must be a real array, not just a count");
    assert.equal(body.remainingFindings.length, older.findings.length);
    assert.ok(body.remainingFindings.some((f: any) => f.title === older.findings[0].title));
  } finally {
    server.close();
  }
});

test("GET /api/projects/:id/scans/compare with explicit from/to picks arbitrary scans, not just the two most recent", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("compare-explicit-picks@example.com", "correct horse battery staple");
    await setSubscriptionStatus(user.id, "tier1", "active");
    const token = await createSession(user.id);
    const project = await createProject(user.id, "Explicit Picks Target");

    const clean = runScan(CLEAN_APP);
    clean.scannedAt = "2026-01-01T00:00:00.000Z";
    const cleanStored = await recordScan(project.id, clean);

    const middle = runScan(CLEAN_APP);
    middle.scannedAt = "2026-01-02T00:00:00.000Z";
    await recordScan(project.id, middle);

    const flawed = runScan(FLAWED_APP);
    flawed.scannedAt = "2026-01-03T00:00:00.000Z";
    const flawedStored = await recordScan(project.id, flawed);

    // Compare the OLDEST (clean) against the NEWEST (flawed) directly,
    // skipping the middle scan entirely — proves the picker isn't
    // hardcoded to "latest vs previous".
    const res = await fetch(
      `${base}/api/projects/${project.id}/scans/compare?from=${cleanStored.id}&to=${flawedStored.id}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.equal(body.from.id, cleanStored.id);
    assert.equal(body.to.id, flawedStored.id);
    assert.ok(body.new > 0, "the flawed fixture should introduce findings absent from the clean one");
  } finally {
    server.close();
  }
});
