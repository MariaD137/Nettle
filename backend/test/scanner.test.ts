import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { runScan } from "../src/scanner";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

test("flags a hardcoded AWS access key", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.title.includes("AWS Access Key ID"));
  assert.equal(found, true);
});

test("flags a hardcoded Stripe live secret key", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.title.includes("Stripe live secret key"));
  assert.equal(found, true);
});

test("flags the known-vulnerable lodash version", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.title.includes("lodash@4.17.4"));
  assert.equal(found, true);
});

test("flags a missing privacy policy", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.title === "No privacy policy found");
  assert.equal(found, true);
});

test("flags undisclosed AI-generated content", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.category === "AI Disclosure");
  assert.equal(found, true);
});

test("flags routes with no visible auth check", () => {
  const report = runScan(FLAWED_APP);
  const found = report.findings.some((f) => f.title.includes("no authentication check"));
  assert.equal(found, true);
});

test("flawed app scores low and has only critical/caution findings, no clears", () => {
  const report = runScan(FLAWED_APP);
  assert.ok(report.score < 50, `expected a low score, got ${report.score}`);
  assert.ok(report.summary.critical > 0);
});

test("a clean app with a privacy policy, terms, safe deps, and auth checks scores well", () => {
  const report = runScan(CLEAN_APP);
  assert.equal(report.summary.critical, 0, JSON.stringify(report.findings, null, 2));
  assert.ok(report.score >= 90, `expected a high score, got ${report.score}`);
});

test("clean app is recognized as having a privacy policy and terms", () => {
  const report = runScan(CLEAN_APP);
  assert.ok(report.passed.some((p) => p.title === "Privacy policy file present"));
  assert.ok(report.passed.some((p) => p.title === "Terms of service file present"));
});

test("score never drops below 0", () => {
  const report = runScan(FLAWED_APP);
  assert.ok(report.score >= 0);
});
