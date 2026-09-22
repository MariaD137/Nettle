import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanPathTraversalControl } from "../src/scanner/controls/checks/pathTraversalControl";
import { scanTransportSecurityControl } from "../src/scanner/controls/checks/transportSecurityControl";

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content, "utf8");
  return file;
}

test("INPUT-001 and NET-001 are registered", () => {
  assert.ok(getControl("INPUT-001"));
  assert.ok(getControl("NET-001"));
});

test("scanPathTraversalControl: FAIL when request params reach readFile unsanitized", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-input-"));
  const file = writeTempFile(
    dir,
    "files.js",
    "app.get('/download/:name', (req, res) => {\n  fs.readFileSync(path.join(uploadsDir, req.params.name));\n});\n"
  );

  const results = scanPathTraversalControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "INPUT-001");
  assert.equal(fail!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPathTraversalControl: PASS when no request-derived path reaches the file system", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-input-"));
  const file = writeTempFile(dir, "files.js", `function add(a, b) { return a + b; }\n`);

  const results = scanPathTraversalControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  assert.equal(results[0].controlKey, "INPUT-001");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanTransportSecurityControl: FAIL (critical) for disabled TLS verification", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-net-"));
  const file = writeTempFile(dir, "client.js", `const agent = new https.Agent({ rejectUnauthorized: false });\n`);

  const results = scanTransportSecurityControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.controlKey, "NET-001");
  assert.equal(fail!.title, "TLS certificate verification disabled");
  assert.equal(fail!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanTransportSecurityControl: FAIL (medium) for a non-localhost HTTP URL", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-net-"));
  const file = writeTempFile(dir, "client.js", `const API_URL = "http://api.example.com/v1";\n`);

  const results = scanTransportSecurityControl([file], dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail);
  assert.equal(fail!.title, "Non-HTTPS URL in server code");
  assert.equal(fail!.severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanTransportSecurityControl: localhost HTTP is not flagged", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-net-"));
  const file = writeTempFile(dir, "client.js", `const DEV_URL = "http://localhost:3000";\n`);

  const results = scanTransportSecurityControl([file], dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("hydration gives INPUT-001 and NET-001 real fixes", () => {
  const input = hydrateCheckResult({
    checkId: "x", status: "FAIL", category: "Security", title: "Potential path traversal vulnerability",
    severity: "critical", confidence: 75, controlKey: "INPUT-001",
  });
  assert.ok(input.recommendation);
  assert.match(input.recommendation!.developerFix, /resolve|base directory/i);
  assert.equal(input.releaseImpact, "BLOCK_RELEASE");

  const net = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Security", title: "TLS certificate verification disabled", severity: "critical", confidence: 85, controlKey: "NET-001" },
    { detectedTechnology: "node" }
  );
  assert.ok(net.recommendation);
  assert.match(net.recommendation!.quickFix, /rejectUnauthorized/);
  assert.equal(net.releaseImpact, "BLOCK_RELEASE");
});
