import { test, before } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { runScan } from "../src/scanner";
import type { ScanReport } from "../src/scanner/types";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

// Semgrep has real subprocess startup cost — run each fixture exactly once
// and share the report across assertions, rather than re-scanning per test.
let flawedReport: ScanReport;
let cleanReport: ScanReport;

before(() => {
  flawedReport = runScan(FLAWED_APP);
  cleanReport = runScan(CLEAN_APP);
});

test("flags a hardcoded AWS access key", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("AWS Access Key ID")));
});

test("flags a hardcoded Stripe live secret key", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("Stripe live secret key")));
});

test("flags the known-vulnerable lodash version", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("lodash@4.17.4")));
});

test("flags a missing privacy policy", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "No privacy policy found"));
});

test("flags undisclosed AI-generated content", () => {
  assert.ok(flawedReport.findings.some((f) => f.category === "AI Disclosure"));
});

test("flags routes with no visible auth check", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("no authentication check")));
});

test("Semgrep catches the SQL-injection-shaped query", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "Sql string concat"), JSON.stringify(flawedReport.findings, null, 2));
});

test("Semgrep catches the command-injection-shaped exec call", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "Child process exec template"));
});

test("Semgrep catches the inline hardcoded JWT secret", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "Hardcoded jwt secret"));
});

test("Semgrep catches TLS verification being disabled", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "Disabled tls verification"));
});

test("Semgrep catches wildcard CORS", () => {
  assert.ok(flawedReport.findings.some((f) => f.title === "Wildcard cors"));
});

test("flawed app scores low and has only critical/caution findings, no clears", () => {
  assert.ok(flawedReport.score < 50, `expected a low score, got ${flawedReport.score}`);
  assert.ok(flawedReport.summary.critical > 0);
});

test("a clean app with a privacy policy, terms, safe deps, and auth checks scores well", () => {
  assert.equal(cleanReport.summary.critical, 0, JSON.stringify(cleanReport.findings, null, 2));
  assert.ok(cleanReport.score >= 90, `expected a high score, got ${cleanReport.score}`);
});

test("clean app is recognized as having a privacy policy and terms", () => {
  assert.ok(cleanReport.passed.some((p) => p.title === "Privacy policy file present"));
  assert.ok(cleanReport.passed.some((p) => p.title === "Terms of service file present"));
});

test("score never drops below 0", () => {
  assert.ok(flawedReport.score >= 0);
});

test("flags missing security headers in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("security headers middleware")));
});

test("clean app passes security headers via Helmet", () => {
  assert.ok(cleanReport.passed.some((p) => p.title.includes("Helmet")));
});

test("flags SQL injection pattern in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("SQL query built with string concatenation")));
});

test("flags CORS wildcard in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("CORS allows all origins")));
});

test("flags TLS verification disabled in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("TLS certificate verification disabled")));
});

test("flags missing rate limiting in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("No rate limiting")));
});

test("clean app passes rate limiting check", () => {
  assert.ok(cleanReport.passed.some((p) => p.title.includes("Rate limiting")));
});

test("flags JWT without expiration in flawed app", () => {
  assert.ok(flawedReport.findings.some((f) => f.title.includes("JWT tokens issued without expiration")));
});

test("clean app passes JWT expiration check", () => {
  assert.ok(cleanReport.passed.some((p) => p.title.includes("JWT tokens have expiration")));
});

test("clean app passes request body size limit check", () => {
  assert.ok(cleanReport.passed.some((p) => p.title.includes("Request body size limit")));
});
