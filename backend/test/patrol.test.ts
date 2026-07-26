// NETTLE_DB_PATH=:memory: is set by the `test` npm script, not here — a plain
// assignment in this file would run *after* the hoisted `require`s below
// (TS compiles `import` to hoisted `require`), too late to affect which
// database src/db/index.ts opens.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createProject, findProjectByApiKey } from "../src/patrol/projects";
import { recordEvent } from "../src/patrol/events";
import { runDetection } from "../src/patrol/detection";
import { listAlerts } from "../src/patrol/alerts";

test("creates a project with a unique API key", () => {
  const a = createProject("App A");
  const b = createProject("App B");
  assert.notEqual(a.apiKey, b.apiKey);
  assert.equal(findProjectByApiKey(a.apiKey)?.id, a.id);
});

test("flags a brute-force pattern: 5+ failed-auth responses from the same IP within 60s", () => {
  const project = createProject("Brute Force Target");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.5", method: "POST", path: "/login", statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  assert.ok(alerts.some((a) => a.rule === "brute-force"), "expected a brute-force alert on the 5th failed attempt");
  assert.equal(alerts.find((a) => a.rule === "brute-force")?.severity, "critical");
});

test("does not flag brute-force for a normal handful of successful requests", () => {
  const project = createProject("Normal Traffic");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.9", method: "GET", path: "/home", statusCode: 200 });
    alerts = runDetection(project.id, event);
  }
  assert.equal(alerts.length, 0);
});

test("flags a path-traversal probe", () => {
  const project = createProject("Traversal Target");
  const event = recordEvent(project.id, { ip: "203.0.113.10", method: "GET", path: "/../../etc/passwd", statusCode: 404 });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")));
});

test("flags an exposed .env probe", () => {
  const project = createProject(".env Target");
  const event = recordEvent(project.id, { ip: "203.0.113.11", method: "GET", path: "/.env", statusCode: 404 });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")));
});

test("flags a SQL-injection-shaped query", () => {
  const project = createProject("SQLi Target");
  const event = recordEvent(project.id, {
    ip: "203.0.113.12",
    method: "GET",
    path: "/products?id=1' OR '1'='1",
    statusCode: 200,
  });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("sqli-shaped")));
});

test("does not flag an ordinary path with no attack pattern", () => {
  const project = createProject("Boring Target");
  const event = recordEvent(project.id, { ip: "203.0.113.13", method: "GET", path: "/products?id=42", statusCode: 200 });
  const alerts = runDetection(project.id, event);
  assert.equal(alerts.length, 0);
});

test("does not re-alert on the same ongoing brute-force pattern every request (cooldown)", () => {
  const project = createProject("Sustained Attack");
  let totalAlerts = 0;
  for (let i = 0; i < 10; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.20", method: "POST", path: "/login", statusCode: 401 });
    totalAlerts += runDetection(project.id, event).filter((a) => a.rule === "brute-force").length;
  }
  assert.equal(totalAlerts, 1, "expected exactly one brute-force alert, not one per request, during the cooldown window");
});

test("alerts persist and are listable per project", () => {
  const project = createProject("Listable Target");
  const event = recordEvent(project.id, { ip: "203.0.113.30", method: "GET", path: "/wp-admin", statusCode: 404 });
  runDetection(project.id, event);
  const alerts = listAlerts(project.id);
  assert.ok(alerts.length >= 1);
  assert.equal(alerts[0].projectId, project.id);
});

test("alerts for one project never leak into another project's list", () => {
  const projectA = createProject("Isolated A");
  const projectB = createProject("Isolated B");
  const event = recordEvent(projectA.id, { ip: "203.0.113.40", method: "GET", path: "/.git/config", statusCode: 404 });
  runDetection(projectA.id, event);
  assert.equal(listAlerts(projectB.id).length, 0);
});
