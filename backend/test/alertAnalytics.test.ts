import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { createAlert } from "../src/patrol/alerts";
import {
  getAlertAnalytics,
  normalizeAttackType,
  extractEndpoint,
  extractIp,
} from "../src/patrol/alertAnalytics";

test("normalizeAttackType strips the per-IP/per-path suffix detection.ts appends", () => {
  assert.equal(normalizeAttackType("suspicious-path-203.0.113.5"), "suspicious-path");
  assert.equal(normalizeAttackType("sqli-shaped-10.0.0.1"), "sqli-shaped");
  assert.equal(normalizeAttackType("credential-stuffing-/login"), "credential-stuffing");
  assert.equal(normalizeAttackType("custom-rule-abc123"), "custom-rule");
  // Unsuffixed rule names pass through unchanged.
  assert.equal(normalizeAttackType("brute-force"), "brute-force");
  assert.equal(normalizeAttackType("high-request-rate"), "high-request-rate");
});

test("extractEndpoint pulls the quoted path out of a real detection.ts message", () => {
  assert.equal(
    extractEndpoint('Request to "/wp-admin" from 203.0.113.5 matches a common attack-probe pattern.'),
    "/wp-admin"
  );
  assert.equal(extractEndpoint("5 failed-auth responses from 203.0.113.5 in the last 60s."), null);
});

test("extractIp finds the IP from the rule suffix or the message text", () => {
  assert.equal(extractIp("suspicious-path-203.0.113.5", "irrelevant"), "203.0.113.5");
  assert.equal(extractIp("brute-force", "5 failed-auth responses (401/403) from 203.0.113.5 in the last 60s."), "203.0.113.5");
  assert.equal(extractIp("credential-stuffing-/login", "3 failed-auth responses against \"/login\" from 3 different IPs in the last 60s."), null);
});

let projectId: string;
before(async () => {
  const user = await createUser("alert-analytics-tests@example.com", "correct horse battery staple");
  projectId = createProject(user.id, "Alert Analytics Target").id;
});

test("getAlertAnalytics buckets alerts into the current hour and reports severity breakdown", () => {
  createAlert(projectId, "critical", "suspicious-path-203.0.113.5", 'Request to "/wp-admin" from 203.0.113.5 matches a common attack-probe pattern.');
  createAlert(projectId, "medium", "high-request-rate", "50 requests from 203.0.113.5 in 10s.");

  const analytics = getAlertAnalytics(projectId, 24);
  const totalCount = analytics.timeline.reduce((sum, b) => sum + b.count, 0);
  assert.equal(totalCount, 2);

  const currentHourKey = new Date().toISOString().slice(0, 13) + ":00:00Z";
  const currentBucket = analytics.timeline.find((b) => b.hour === currentHourKey);
  assert.ok(currentBucket);
  assert.equal(currentBucket!.count, 2);
  assert.equal(currentBucket!.bySeverity.critical, 1);
  assert.equal(currentBucket!.bySeverity.medium, 1);

  assert.equal(analytics.timeline.length, 25); // 24 hours back through the current hour, inclusive
});

test("getAlertAnalytics ranks attack types by normalized name, not raw rule", async () => {
  const user = await createUser("alert-analytics-types@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Attack Types Target").id;

  createAlert(project, "critical", "suspicious-path-203.0.113.1", 'Request to "/a" from 203.0.113.1 matches a common attack-probe pattern.');
  createAlert(project, "critical", "suspicious-path-203.0.113.2", 'Request to "/b" from 203.0.113.2 matches a common attack-probe pattern.');
  createAlert(project, "medium", "high-request-rate", "60 requests from 203.0.113.1 in 10s.");

  const { topAttackTypes } = getAlertAnalytics(project, 24);
  assert.deepEqual(topAttackTypes[0], { label: "suspicious-path", count: 2 });
  assert.ok(topAttackTypes.some((t) => t.label === "high-request-rate" && t.count === 1));
});

test("getAlertAnalytics ranks the endpoints named in alert messages, excluding alerts with none", async () => {
  const user = await createUser("alert-analytics-endpoints@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Endpoints Target").id;

  createAlert(project, "critical", "sqli-shaped-203.0.113.1", 'Request to "/api/login" from 203.0.113.1 contains a SQL-injection-shaped pattern.');
  createAlert(project, "critical", "sqli-shaped-203.0.113.2", 'Request to "/api/login" from 203.0.113.2 contains a SQL-injection-shaped pattern.');
  createAlert(project, "medium", "high-request-rate", "60 requests from 203.0.113.1 in 10s."); // no endpoint

  const { topEndpoints } = getAlertAnalytics(project, 24);
  assert.deepEqual(topEndpoints, [{ label: "/api/login", count: 2 }]);
});

test("getAlertAnalytics ranks source countries by geoip-resolving the alert's IP, skipping unresolvable ones", async () => {
  const user = await createUser("alert-analytics-geo@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Geo Target").id;

  createAlert(project, "critical", "suspicious-path-8.8.8.8", 'Request to "/a" from 8.8.8.8 matches a common attack-probe pattern.');
  createAlert(project, "critical", "suspicious-path-8.8.4.4", 'Request to "/a" from 8.8.4.4 matches a common attack-probe pattern.');
  createAlert(project, "critical", "suspicious-path-5.5.5.5", 'Request to "/a" from 5.5.5.5 matches a common attack-probe pattern.');
  // A reserved/documentation-range IP geoip-lite cannot resolve — must not
  // silently show up under a fabricated "unknown" bucket.
  createAlert(project, "critical", "suspicious-path-203.0.113.9", 'Request to "/a" from 203.0.113.9 matches a common attack-probe pattern.');

  const { topCountries } = getAlertAnalytics(project, 24);
  assert.deepEqual(topCountries.find((c) => c.label === "US"), { label: "US", count: 2 });
  assert.deepEqual(topCountries.find((c) => c.label === "DE"), { label: "DE", count: 1 });
  assert.equal(topCountries.reduce((sum, c) => sum + c.count, 0), 3, "the unresolvable IP must not be counted anywhere");
});

test("getAlertAnalytics only counts alerts within the requested time window", async () => {
  const user = await createUser("alert-analytics-window@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Window Target").id;

  createAlert(project, "critical", "brute-force", "in window");
  const { timeline } = getAlertAnalytics(project, 1);
  const total = timeline.reduce((sum, b) => sum + b.count, 0);
  assert.equal(total, 1);
  assert.equal(timeline.length, 2); // 1 hour back through the current hour, inclusive
});
