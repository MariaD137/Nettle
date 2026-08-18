import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { analyzeAuth, isAdminRoute } from "../src/scanner/authAnalysis";
import { scanAuthAnalysis } from "../src/scanner/authAnalysisScan";
import { runScan } from "../src/scanner";

// --- isAdminRoute ---

test("isAdminRoute recognizes administrative path segments", () => {
  const admin = ["/admin", "/admin/users", "/api/admin/settings", "/internal/debug", "/management/reports", "/superuser/panel"];
  for (const p of admin) assert.equal(isAdminRoute(p), true, `${p} should be recognized as an admin route`);
});

test("isAdminRoute recognizes admin-ish Django/Flask function names (no leading slash)", () => {
  assert.equal(isAdminRoute("admin_dashboard"), true);
  assert.equal(isAdminRoute("administrator_panel"), true);
});

test("isAdminRoute does not flag ordinary routes", () => {
  const ordinary = ["/users", "/api/posts", "/profile", "public_page", "/administration-request-form"];
  for (const p of ordinary) assert.equal(isAdminRoute(p), false, `${p} should not be flagged as an admin route`);
});

// --- hasRoleCheck via analyzeAuth ---

test("analyzeAuth marks a route with a role check accordingly", () => {
  const code = `
    const app = express();
    app.delete('/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => res.sendStatus(204));
  `;
  const result = analyzeAuth(code);
  const route = result.allRoutes.find((r) => r.path === "/admin/users/:id");
  assert.ok(route);
  assert.equal(route!.isProtected, true);
  assert.equal(route!.hasRoleCheck, true);
});

test("analyzeAuth marks an authenticated-but-not-role-checked route accordingly", () => {
  const code = `
    const app = express();
    app.delete('/admin/users/:id', requireAuth, (req, res) => res.sendStatus(204));
  `;
  const result = analyzeAuth(code);
  const route = result.allRoutes.find((r) => r.path === "/admin/users/:id");
  assert.ok(route);
  assert.equal(route!.isProtected, true);
  assert.equal(route!.hasRoleCheck, false);
});

// --- scanAuthAnalysis: public admin routes ---

function tempSourceFile(contents: string): { dir: string; file: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-admin-auth-"));
  const file = path.join(dir, "app.js");
  fs.writeFileSync(file, contents);
  return { dir, file };
}

test("an unauthenticated admin route is escalated to a critical, admin-specific finding", () => {
  const { dir, file } = tempSourceFile(`
    const app = express();
    app.get('/admin/dashboard', (req, res) => res.json({ stats: {} }));
  `);
  try {
    const { findings } = scanAuthAnalysis([file], dir);
    const finding = findings.find((f) => f.title.startsWith("Public admin route:"));
    assert.ok(finding, "expected a public-admin-route finding");
    assert.equal(finding!.severity, "critical");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an unauthenticated GET on a non-admin path keeps the ordinary medium severity", () => {
  const { dir, file } = tempSourceFile(`
    const app = express();
    app.get('/api/public-data', (req, res) => res.json({}));
  `);
  try {
    const { findings } = scanAuthAnalysis([file], dir);
    const finding = findings.find((f) => f.title.includes("/api/public-data"));
    assert.ok(finding);
    assert.equal(finding!.severity, "medium");
    assert.equal(finding!.title.startsWith("Public admin route:"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- scanAuthAnalysis: missing role checks ---

test("an authenticated admin route with no role check gets its own high-severity finding", () => {
  const { dir, file } = tempSourceFile(`
    const app = express();
    app.delete('/admin/users/:id', requireAuth, (req, res) => res.sendStatus(204));
  `);
  try {
    const { findings } = scanAuthAnalysis([file], dir);
    const finding = findings.find((f) => f.title.includes("no role or permission check"));
    assert.ok(finding, "expected a missing-role-check finding");
    assert.equal(finding!.severity, "high");
    assert.match(finding!.remediation!, /requireRole|role/i);
    // Must not also fire the "no authentication check" finding — it IS authenticated.
    assert.equal(findings.some((f) => f.title.includes("no detected authentication check")), false);
    assert.equal(findings.some((f) => f.title.startsWith("Public admin route:")), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an authenticated admin route WITH a role check produces no finding for that route", () => {
  const { dir, file } = tempSourceFile(`
    const app = express();
    app.delete('/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => res.sendStatus(204));
  `);
  try {
    const { findings, passed } = scanAuthAnalysis([file], dir);
    assert.equal(findings.length, 0);
    assert.ok(passed.some((p) => p.title.includes("role checks")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an authenticated non-admin route with no role check is not flagged (would be noise)", () => {
  const { dir, file } = tempSourceFile(`
    const app = express();
    app.get('/api/profile', requireAuth, (req, res) => res.json({}));
  `);
  try {
    const { findings } = scanAuthAnalysis([file], dir);
    assert.equal(findings.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("both admin-route checks reach the aggregated scan report", () => {
  // Two files rather than two routes in one file — the extractor's handler
  // section is a fixed-size slice *after* a route declaration, so two
  // routes placed close together in the same file can bleed into each
  // other's slice (a pre-existing property of that heuristic, not
  // something this test is trying to exercise).
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-admin-auth-multi-"));
  fs.writeFileSync(
    path.join(dir, "public.js"),
    `const app = express();\napp.get('/admin/dashboard', (req, res) => res.json({}));\n`
  );
  fs.writeFileSync(
    path.join(dir, "delete.js"),
    `const app = express();\napp.delete('/admin/users/:id', requireAuth, (req, res) => res.sendStatus(204));\n`
  );
  try {
    const report = runScan(dir);
    assert.ok(report.findings.some((f) => f.title.startsWith("Public admin route:")));
    assert.ok(report.findings.some((f) => f.title.includes("no role or permission check")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
