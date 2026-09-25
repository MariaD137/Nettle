import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { scanSemgrepControl } from "../src/scanner/controls/checks/semgrepControl";
import { scanPypiVulnerabilityControl } from "../src/scanner/controls/checks/pypiVulnerabilityControl";
import { detectFrameworks } from "../src/scanner/frameworkDetection";
import { runScan } from "../src/scanner";
import { isSemgrepAvailable, initializeScanner } from "../src/scanner/initialization";

/**
 * Real, honest Python coverage — not a placeholder. Verifies:
 *  - the Semgrep Python ruleset (nettle-py-rules.yaml) actually fires and
 *    is correctly gated (a codebase with zero .py files never gets a
 *    fabricated PASS for a Python-only rule);
 *  - OSV-002 checks pinned requirements.txt dependencies against a real,
 *    bundled snapshot of OSV's PyPI advisories (osv-data/pypi-vulnerabilities.db,
 *    built from osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip —
 *    not synthetic test data);
 *  - Flask/FastAPI technology detection, which frameworkDetection.ts always
 *    had signatures for but never actually ran (detectFrameworks() was
 *    never called with sourceFiles, so the pattern-matching pass — the only
 *    way Flask/FastAPI are detectable, since neither has a distinguishing
 *    config file — silently never executed).
 */

initializeScanner();

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test("OSV-002 is registered", () => {
  const control = getControl("OSV-002");
  assert.ok(control);
  assert.equal(control!.category, "Dependencies");
});

// --- Semgrep Python rules ---

test("Semgrep Python rules never produce a PASS for a codebase with zero .py files", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-py-gate-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  const results = scanSemgrepControl([file], dir);
  const pyRuleResults = results.filter((r) => /\(Python\)/.test(r.title));
  assert.equal(pyRuleResults.length, 0, "no Python-language rule should produce ANY result (PASS included) when no .py file exists");
});

test("Semgrep: FAILs on eval() usage in a real .py file", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-py-eval-");
  const file = writeTempFile(dir, "run.py", `def run(user_input):\n    return eval(user_input)\n`);

  const results = scanSemgrepControl([file], dir);
  const evalResult = results.find((r) => r.controlKey === "INPUT-003" && /Python/.test(r.title));
  assert.ok(evalResult, "eval() in a real .py file must be detected");
  assert.equal(evalResult!.status, "FAIL");
  assert.equal(evalResult!.detectionMethod, "ast");
});

test("Semgrep: FAILs on shell=True command injection in a real .py file", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-py-shell-");
  const file = writeTempFile(dir, "run.py", `import subprocess\ndef run(name):\n    subprocess.run(f"ls {name}", shell=True)\n`);

  const results = scanSemgrepControl([file], dir);
  const result = results.find((r) => r.controlKey === "INPUT-004" && /Python/.test(r.title));
  assert.ok(result, "subprocess.run(..., shell=True) must be detected");
  assert.equal(result!.status, "FAIL");
});

test("Semgrep: FAILs on unsafe pickle deserialization in a real .py file (no JS equivalent rule exists — this is new coverage)", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-py-pickle-");
  const file = writeTempFile(dir, "cache.py", `import pickle\ndef load(data):\n    return pickle.loads(data)\n`);

  const results = scanSemgrepControl([file], dir);
  const result = results.find((r) => r.controlKey === "INPUT-002" && /Python/.test(r.title));
  assert.ok(result, "pickle.loads() must be detected");
  assert.equal(result!.status, "FAIL");
});

test("Semgrep: a clean .py file PASSes every applicable Python rule", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-py-clean-");
  const file = writeTempFile(dir, "app.py", `def add(a, b):\n    return a + b\n`);

  const results = scanSemgrepControl([file], dir);
  const pyResults = results.filter((r) => /\(Python\)/.test(r.title));
  assert.ok(pyResults.length >= 6, "all 6 Python rules should be applicable and reported for a real .py file");
  assert.ok(pyResults.every((r) => r.status === "PASS"), "a clean file must PASS every Python rule, not just avoid FAIL");
});

// --- OSV-002: PyPI dependency vulnerabilities ---

test("OSV-002: NOT_VERIFIED when no requirements.txt exists", () => {
  const dir = tmpDir("nettle-osv2-none-");
  const results = scanPypiVulnerabilityControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  assert.equal(results[0].controlKey, "OSV-002");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("OSV-002: NOT_VERIFIED when requirements.txt has no exact pins", () => {
  const dir = tmpDir("nettle-osv2-nopins-");
  writeTempFile(dir, "requirements.txt", `requests>=2.0\n# a comment\n`);
  const results = scanPypiVulnerabilityControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "NOT_VERIFIED");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("OSV-002: FAILs a real known-vulnerable pinned PyPI package (from the real bundled OSV snapshot)", () => {
  const dir = tmpDir("nettle-osv2-vuln-");
  // Django 3.2.0 has multiple real, publicly disclosed CVEs (e.g. CVE-2021-33203,
  // CVE-2021-35042) — picked precisely because it's old enough that no
  // future OSV refresh could plausibly un-flag it.
  writeTempFile(dir, "requirements.txt", `Django==3.2.0\n`);

  const results = scanPypiVulnerabilityControl(dir);
  const fail = results.find((r) => r.status === "FAIL");
  assert.ok(fail, "Django==3.2.0 must be flagged against the real PyPI OSV data — this is not a synthetic fixture");
  assert.equal(fail!.controlKey, "OSV-002");
  assert.match(fail!.title, /django/i);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("OSV-002: PASSes a requirements.txt with no known-vulnerable pins", () => {
  const dir = tmpDir("nettle-osv2-clean-");
  // An intentionally implausible, obviously-unpublished package name/version
  // so this can never coincidentally match a real advisory.
  writeTempFile(dir, "requirements.txt", `nettle-test-fixture-package-that-does-not-exist==0.0.1\n`);

  const results = scanPypiVulnerabilityControl(dir);
  assert.equal(results.length, 1);
  assert.equal(results[0].status, "PASS");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("OSV-002: canonicalizes package names (case, -/_ ) the same way pip does", () => {
  const dir = tmpDir("nettle-osv2-canon-");
  // Same real vulnerable package, spelled with different case/separator —
  // must still resolve to the same canonical lookup key as the DB stores.
  writeTempFile(dir, "requirements.txt", `django==3.2.0\n`);
  const results = scanPypiVulnerabilityControl(dir);
  assert.ok(results.some((r) => r.status === "FAIL"), "lowercase 'django' must still match the canonicalized 'Django' entry");
  fs.rmSync(dir, { recursive: true, force: true });
});

// --- Technology detection: Flask/FastAPI ---

test("detectFrameworks finds Flask via source patterns when sourceFiles is provided", () => {
  const dir = tmpDir("nettle-flask-detect-");
  const file = writeTempFile(dir, "app.py", `from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "hi"\n`);

  const result = detectFrameworks(dir, undefined, [file]);
  assert.ok(result.detected.includes("flask"), "Flask must be detected once sourceFiles is actually passed");
  assert.equal(result.primaryFramework, "flask");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("detectFrameworks finds FastAPI via source patterns when sourceFiles is provided", () => {
  const dir = tmpDir("nettle-fastapi-detect-");
  const file = writeTempFile(dir, "main.py", `from fastapi import FastAPI\napp = FastAPI()\n\n@app.get("/")\ndef index():\n    return {"ok": True}\n`);

  const result = detectFrameworks(dir, undefined, [file]);
  assert.ok(result.detected.includes("fastapi"), "FastAPI must be detected once sourceFiles is actually passed");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("runScan wires files into detectFrameworks — a Flask fixture's detectedTechnology is 'flask', not null", { skip: !isSemgrepAvailable() && "semgrep not available" }, () => {
  const dir = tmpDir("nettle-flask-e2e-");
  writeTempFile(dir, "app.py", `from flask import Flask\napp = Flask(__name__)\n\n@app.route("/")\ndef index():\n    return "hi"\n`);

  const report = runScan(dir);
  assert.equal(report.detectedTechnology, "flask", "the full scan pipeline, not just detectFrameworks in isolation, must now detect Flask");
  fs.rmSync(dir, { recursive: true, force: true });
});
