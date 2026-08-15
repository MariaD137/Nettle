import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { runScan } from "../src/scanner";
import { projectsRouter } from "../src/routes/projects.routes";
import { authRouter } from "../src/routes/auth.routes";
import { applyScanAccess, limitFindings, hasFullScanAccess, PREVIEW_FINDING_LIMIT } from "../src/billing/scanAccess";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");

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
  app.use(authRouter);
  app.use(projectsRouter);
  return app;
}

async function tokenFor(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json();
  return body.token;
}

let report: ReturnType<typeof runScan>;
before(() => {
  report = runScan(FLAWED_APP);
  // The fixture must have more findings than a preview reveals, or the
  // gating assertions below would pass vacuously.
  assert.ok(report.findings.length > PREVIEW_FINDING_LIMIT);
});

test("hasFullScanAccess unlocks only the paid tiers", () => {
  assert.equal(hasFullScanAccess("tier1"), true);
  assert.equal(hasFullScanAccess("tier2"), true);
  assert.equal(hasFullScanAccess("free"), false);
  assert.equal(hasFullScanAccess(null), false);
  assert.equal(hasFullScanAccess(undefined), false);
  assert.equal(hasFullScanAccess("enterprise"), false);
});

test("a paid plan gets every finding, marked as a full report", () => {
  const result = applyScanAccess(report, "tier1");
  assert.equal(result.findings.length, report.findings.length);
  assert.equal(result.access?.fullReport, true);
  assert.equal(result.access?.tier, "full");
  assert.equal(result.access?.lockedFindings, 0);
});

test("the free plan gets a capped preview that reports the true total", () => {
  const result = applyScanAccess(report, "free");

  assert.equal(result.findings.length, PREVIEW_FINDING_LIMIT);
  assert.equal(result.access?.fullReport, false);
  assert.equal(result.access?.tier, "preview");
  assert.equal(result.access?.totalFindings, report.findings.length);
  assert.equal(result.access?.lockedFindings, report.findings.length - PREVIEW_FINDING_LIMIT);
  assert.ok(result.access?.message);
});

test("a preview reveals the most severe findings first", () => {
  const result = applyScanAccess(report, "free");
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  const worstWithheld = Math.min(
    ...report.findings
      .filter((f) => !result.findings.includes(f))
      .map((f) => rank[f.severity])
  );
  for (const shown of result.findings) {
    assert.ok(rank[shown.severity] <= worstWithheld);
  }
});

test("a preview withholds detail rather than blanking it", () => {
  const result = applyScanAccess(report, "free");
  // Every finding that does come back is intact — no half-redacted rows.
  for (const f of result.findings) {
    assert.ok(f.title);
    assert.ok(f.detail);
  }
});

test("score, summary and passed checks survive redaction untouched", () => {
  const result = applyScanAccess(report, "free");
  assert.equal(result.score, report.score);
  assert.deepEqual(result.summary, report.summary);
  assert.deepEqual(result.passed, report.passed);
});

test("redaction does not mutate the report it was given", () => {
  const before = report.findings.length;
  applyScanAccess(report, "free");
  assert.equal(report.findings.length, before);
  assert.equal(report.access, undefined);
});

test("limitFindings caps free plans and passes paid plans through", () => {
  assert.equal(limitFindings(report.findings, "tier2").length, report.findings.length);
  assert.equal(limitFindings(report.findings, "free").length, PREVIEW_FINDING_LIMIT);
});

test("stored scans keep the full report so upgrading unlocks history", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const password = "correct horse battery staple";
    const user = await createUser("access-upgrade@example.com", password);
    const project = createProject(user.id, "Gated Project");
    recordScan(project.id, report);

    // On the free plan the API trims the response...
    let token = await tokenFor(base, "access-upgrade@example.com", password);
    let res = await fetch(`${base}/api/projects/${project.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    let body = await res.json();
    assert.equal(body.latestScan.report.access.fullReport, false);
    assert.equal(body.latestScan.report.findings.length, PREVIEW_FINDING_LIMIT);
    assert.equal(body.latestScan.report.access.totalFindings, report.findings.length);

    // ...and the same stored scan comes back whole once the plan changes,
    // which only works because storage was never redacted.
    setSubscriptionStatus(user.id, "tier1", "active");
    token = await tokenFor(base, "access-upgrade@example.com", password);
    res = await fetch(`${base}/api/projects/${project.id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    body = await res.json();
    assert.equal(body.latestScan.report.access.fullReport, true);
    assert.equal(body.latestScan.report.findings.length, report.findings.length);
  } finally {
    server.close();
  }
});

test("export is refused on the free plan and allowed on a paid one", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const password = "correct horse battery staple";
    const user = await createUser("access-export@example.com", password);
    const project = createProject(user.id, "Export Target");
    const stored = recordScan(project.id, report);

    let token = await tokenFor(base, "access-export@example.com", password);
    let res = await fetch(`${base}/api/projects/${project.id}/scans/${stored.id}/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 402);
    const err = await res.json();
    assert.equal(err.upgradeRequired, true);

    setSubscriptionStatus(user.id, "tier2", "active");
    token = await tokenFor(base, "access-export@example.com", password);
    res = await fetch(`${base}/api/projects/${project.id}/scans/${stored.id}/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const exported = await res.json();
    assert.equal(exported.findings.length, report.findings.length);
  } finally {
    server.close();
  }
});

test("scan comparison keeps counts exact but gates the finding lists", async () => {
  const { server, base } = await listen(buildApp());
  try {
    const password = "correct horse battery staple";
    const user = await createUser("access-compare@example.com", password);
    const project = createProject(user.id, "Compare Target");

    // Two different scans so the diff has something to report. Both are
    // referenced by id below rather than relying on default ordering, which
    // is ambiguous when two scans land in the same millisecond.
    const clean = recordScan(project.id, runScan(path.join(__dirname, "fixtures", "clean-app")));
    const flawed = recordScan(project.id, report);

    const token = await tokenFor(base, "access-compare@example.com", password);
    const res = await fetch(
      `${base}/api/projects/${project.id}/scans/compare?from=${clean.id}&to=${flawed.id}`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    const body = await res.json();

    assert.equal(body.fullReport, false);
    // The headline numbers stay truthful even on the free plan.
    assert.ok(body.new > PREVIEW_FINDING_LIMIT);
    assert.equal(body.newFindings.length, PREVIEW_FINDING_LIMIT);
  } finally {
    server.close();
  }
});
