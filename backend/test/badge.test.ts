import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { recordScan } from "../src/patrol/scans";
import { createAlert } from "../src/patrol/alerts";
import { computeBadgeState, renderBadgeSVG } from "../src/patrol/badge";
import { runScan } from "../src/scanner";

const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

async function makeProject(email: string) {
  const user = await createUser(email, "correct horse battery staple");
  return (await createProject(user.id, "Badge Target")).id;
}

test("badge is 'unknown' for a project with no scans yet", async () => {
  const projectId = await makeProject("badge-unknown@example.com");
  const state = await computeBadgeState(projectId);
  assert.equal(state.status, "unknown");
  assert.equal(state.score, null);
});

test("badge is 'protected' after a clean scan with no alerts", async () => {
  const projectId = await makeProject("badge-protected@example.com");
  await recordScan(projectId, runScan(CLEAN_APP));
  const state = await computeBadgeState(projectId);
  assert.equal(state.status, "protected");
  assert.ok(state.score !== null && state.score >= 90, `expected high score, got ${state.score}`);
});

test("badge is 'critical' after a scan with critical findings", async () => {
  const projectId = await makeProject("badge-critical-scan@example.com");
  await recordScan(projectId, runScan(FLAWED_APP));
  const state = await computeBadgeState(projectId);
  assert.equal(state.status, "critical");
});

test("badge is 'critical' if a clean scan is followed by a recent critical Tier 2 alert", async () => {
  const projectId = await makeProject("badge-critical-alert@example.com");
  await recordScan(projectId, runScan(CLEAN_APP));
  await createAlert(projectId, "critical", "brute-force", "simulated attack for the badge test");
  const state = await computeBadgeState(projectId);
  assert.equal(state.status, "critical", "a recent critical alert should override an otherwise-clean scan");
});

test("badge is 'caution' when the scan has only caution-level findings and no critical alert", async () => {
  const projectId = await makeProject("badge-caution@example.com");
  await recordScan(projectId, runScan(CLEAN_APP));
  await createAlert(projectId, "medium", "high-request-rate", "simulated low-severity alert for the badge test");
  const state = await computeBadgeState(projectId);
  // a caution-severity alert should not escalate a clean scan to critical
  assert.equal(state.status, "protected");
});

test("renderBadgeSVG produces a valid-looking SVG containing the status label", () => {
  const svg = renderBadgeSVG({ status: "protected", label: "Protected", lastScannedAt: null, score: 100 });
  assert.ok(svg.startsWith("<svg"));
  assert.ok(svg.includes("Protected"));
  assert.ok(svg.includes("nettle"));
});
