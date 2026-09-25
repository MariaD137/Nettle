import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { scanAuthorizationControl } from "../src/scanner/controls/checks/authorizationControl";

/**
 * AUTHZ-001: authorization is distinct from authentication — none of the
 * AUTH-* controls (session/JWT/cookie mechanics) or MT-002 (object-level/
 * resource-ownership authorization) check whether a privileged/admin route
 * enforces a role or permission check as opposed to merely requiring some
 * authenticated session. Confirmed via grep before writing this that no
 * existing control covered route-level/role-based authorization.
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("AUTHZ-001 is registered", () => {
  const control = getControl("AUTHZ-001");
  assert.ok(control);
  assert.equal(control!.category, "Authorization");
});

test("no result at all when neither admin routes nor authentication evidence exist", () => {
  const dir = tmpDir("nettle-authz-none-");
  const file = writeTempFile(dir, "math.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanAuthorizationControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("FAILs an admin route with no authorization evidence in the file", () => {
  const dir = tmpDir("nettle-authz-fail-");
  const file = writeTempFile(
    dir,
    "adminRoutes.js",
    `app.get('/admin/users', requireAuth, (req, res) => {\n  res.json(listAllUsers());\n});\n`
  );

  const results = scanAuthorizationControl([file], dir);
  const result = results.find((r) => r.controlKey === "AUTHZ-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");
  assert.match(result!.title, /admin\/users/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("PASSes an admin route with role-based middleware", () => {
  const dir = tmpDir("nettle-authz-pass-role-");
  const file = writeTempFile(
    dir,
    "adminRoutes.js",
    `app.get('/admin/users', requireAuth, requireRole('admin'), (req, res) => {\n  res.json(listAllUsers());\n});\n`
  );

  const results = scanAuthorizationControl([file], dir);
  const result = results.find((r) => r.controlKey === "AUTHZ-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("PASSes an admin route with permission-check middleware", () => {
  const dir = tmpDir("nettle-authz-pass-perm-");
  const file = writeTempFile(
    dir,
    "internalRoutes.ts",
    `router.post('/internal/reindex', requireAuth, hasPermission('ops:write'), handler);\n`
  );

  const results = scanAuthorizationControl([file], dir);
  const result = results.find((r) => r.controlKey === "AUTHZ-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("PASSes an admin route with an explicit role comparison in the handler", () => {
  const dir = tmpDir("nettle-authz-pass-inline-");
  const file = writeTempFile(
    dir,
    "adminRoutes.js",
    `app.delete('/admin/projects/:id', requireAuth, (req, res) => {\n` +
      `  if (!isAdmin(req.user)) return res.status(403).end();\n` +
      `  deleteProject(req.params.id);\n` +
      `});\n`
  );

  const results = scanAuthorizationControl([file], dir);
  const result = results.find((r) => r.controlKey === "AUTHZ-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("NOT_VERIFIED when authentication exists but no admin route was found — authentication is never treated as authorization evidence", () => {
  const dir = tmpDir("nettle-authz-notverified-");
  const file = writeTempFile(
    dir,
    "userRoutes.js",
    `app.get('/api/profile', requireAuth, (req, res) => {\n  res.json(req.user);\n});\n`
  );

  const results = scanAuthorizationControl([file], dir);
  const result = results.find((r) => r.controlKey === "AUTHZ-001");
  assert.ok(result, "authentication evidence alone must still produce a result, never silence");
  assert.equal(result!.status, "NOT_VERIFIED");
  assert.match(result!.detail ?? "", /Authentication alone is not evidence/);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("never fabricates a PASS from login/session/JWT functionality alone", () => {
  const dir = tmpDir("nettle-authz-no-fake-pass-");
  const file = writeTempFile(
    dir,
    "auth.js",
    `passport.use(new Strategy(...));\napp.post('/login', (req, res) => { req.session.userId = user.id; });\n`
  );

  const results = scanAuthorizationControl([file], dir);
  assert.ok(!results.some((r) => r.status === "PASS"), "login/session code alone must never itself yield an AUTHZ-001 PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});
