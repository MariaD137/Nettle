// NETTLE_DB_PATH=:memory: is set by the `test` npm script, not here — a plain
// assignment in this file would run *after* the hoisted `require`s below
// (TS compiles `import` to hoisted `require`), too late to affect which
// database src/db/index.ts opens.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createProject, findProjectByApiKey } from "../src/patrol/projects";
import { recordEvent } from "../src/patrol/events";
import { runDetection } from "../src/patrol/detection";
import { listAlerts } from "../src/patrol/alerts";
import { createUser } from "../src/auth/users";
import { updateDetectionSettings } from "../src/patrol/detectionSettings";

// projects.user_id has a real foreign key to users(id), enforced by
// node:sqlite — these tests need one real user to own the test projects,
// not a placeholder string.
let userId: string;
before(async () => {
  const user = await createUser("patrol-tests@example.com", "correct horse battery staple");
  userId = user.id;
});

test("creates a project with a unique API key", () => {
  const a = createProject(userId, "App A");
  const b = createProject(userId, "App B");
  assert.notEqual(a.apiKey, b.apiKey);
  assert.equal(findProjectByApiKey(a.apiKey)?.id, a.id);
});

test("flags a brute-force pattern: 5+ failed-auth responses from the same IP within 60s", () => {
  const project = createProject(userId, "Brute Force Target");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.5", method: "POST", path: "/login", statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  assert.ok(alerts.some((a) => a.rule === "brute-force"), "expected a brute-force alert on the 5th failed attempt");
  assert.equal(alerts.find((a) => a.rule === "brute-force")?.severity, "critical");
});

test("does not flag brute-force for a normal handful of successful requests", () => {
  const project = createProject(userId, "Normal Traffic");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.9", method: "GET", path: "/home", statusCode: 200 });
    alerts = runDetection(project.id, event);
  }
  assert.equal(alerts.length, 0);
});

test("flags a path-traversal probe", () => {
  const project = createProject(userId, "Traversal Target");
  const event = recordEvent(project.id, { ip: "203.0.113.10", method: "GET", path: "/../../etc/passwd", statusCode: 404 });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")));
});

test("flags an exposed .env probe", () => {
  const project = createProject(userId, ".env Target");
  const event = recordEvent(project.id, { ip: "203.0.113.11", method: "GET", path: "/.env", statusCode: 404 });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")));
});

test("flags a SQL-injection-shaped query", () => {
  const project = createProject(userId, "SQLi Target");
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
  const project = createProject(userId, "Boring Target");
  const event = recordEvent(project.id, { ip: "203.0.113.13", method: "GET", path: "/products?id=42", statusCode: 200 });
  const alerts = runDetection(project.id, event);
  assert.equal(alerts.length, 0);
});

test("does not re-alert on the same ongoing brute-force pattern every request (cooldown)", () => {
  const project = createProject(userId, "Sustained Attack");
  let totalAlerts = 0;
  for (let i = 0; i < 10; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.20", method: "POST", path: "/login", statusCode: 401 });
    totalAlerts += runDetection(project.id, event).filter((a) => a.rule === "brute-force").length;
  }
  assert.equal(totalAlerts, 1, "expected exactly one brute-force alert, not one per request, during the cooldown window");
});

test("alerts persist and are listable per project", () => {
  const project = createProject(userId, "Listable Target");
  const event = recordEvent(project.id, { ip: "203.0.113.30", method: "GET", path: "/wp-admin", statusCode: 404 });
  runDetection(project.id, event);
  const alerts = listAlerts(project.id);
  assert.ok(alerts.length >= 1);
  assert.equal(alerts[0].projectId, project.id);
});

test("alerts for one project never leak into another project's list", () => {
  const projectA = createProject(userId, "Isolated A");
  const projectB = createProject(userId, "Isolated B");
  const event = recordEvent(projectA.id, { ip: "203.0.113.40", method: "GET", path: "/.git/config", statusCode: 404 });
  runDetection(projectA.id, event);
  assert.equal(listAlerts(projectB.id).length, 0);
});

test("flags a broadened scanner-probe path (Spring Boot actuator)", () => {
  const project = createProject(userId, "Actuator Target");
  const event = recordEvent(project.id, { ip: "203.0.113.50", method: "GET", path: "/actuator/env", statusCode: 404 });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")));
});

test("flags an XSS-shaped query", () => {
  const project = createProject(userId, "XSS Target");
  const event = recordEvent(project.id, {
    ip: "203.0.113.51",
    method: "GET",
    path: "/search?q=<script>alert(1)</script>",
    statusCode: 200,
  });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("xss-shaped")));
});

test("flags a command-injection-shaped query", () => {
  const project = createProject(userId, "CmdI Target");
  const event = recordEvent(project.id, {
    ip: "203.0.113.52",
    method: "GET",
    path: "/ping?host=127.0.0.1;cat%20/etc/passwd",
    statusCode: 200,
  });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("cmdi-shaped")));
});

test("flags a known security-scanner User-Agent", () => {
  const project = createProject(userId, "Scanner UA Target");
  const event = recordEvent(project.id, {
    ip: "203.0.113.53",
    method: "GET",
    path: "/",
    statusCode: 200,
    userAgent: "sqlmap/1.7.2#stable (http://sqlmap.org)",
  });
  const alerts = runDetection(project.id, event);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-user-agent")));
  assert.equal(alerts.find((a) => a.rule.startsWith("suspicious-user-agent"))?.severity, "critical");
});

test("does not flag an ordinary browser User-Agent", () => {
  const project = createProject(userId, "Ordinary UA Target");
  const event = recordEvent(project.id, {
    ip: "203.0.113.54",
    method: "GET",
    path: "/",
    statusCode: 200,
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
  });
  const alerts = runDetection(project.id, event);
  assert.equal(alerts.filter((a) => a.rule.startsWith("suspicious-user-agent")).length, 0);
});

test("flags credential-stuffing shape: many different IPs failing auth on the same endpoint", () => {
  const project = createProject(userId, "Credential Stuffing Target");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: `198.51.100.${i}`, method: "POST", path: "/login", statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  const hit = alerts.find((a) => a.rule.startsWith("credential-stuffing"));
  assert.ok(hit, "expected a credential-stuffing alert once 5 distinct IPs have failed auth on the same path");
  assert.equal(hit?.severity, "critical");
});

test("a project's custom brute-force threshold is honored instead of the built-in default", () => {
  const project = createProject(userId, "Custom Threshold Target");
  updateDetectionSettings(project.id, { bruteForceThreshold: 2 });

  let alerts: ReturnType<typeof runDetection> = [];
  const event1 = recordEvent(project.id, { ip: "203.0.113.90", method: "POST", path: "/login", statusCode: 401 });
  alerts = runDetection(project.id, event1);
  assert.equal(alerts.filter((a) => a.rule === "brute-force").length, 0, "1 failure should not yet trip a threshold of 2");

  const event2 = recordEvent(project.id, { ip: "203.0.113.90", method: "POST", path: "/login", statusCode: 401 });
  alerts = runDetection(project.id, event2);
  assert.ok(alerts.some((a) => a.rule === "brute-force"), "the 2nd failure should trip the customized threshold of 2");
});

test("a project with no customized thresholds still uses the original built-in default of 5", () => {
  const project = createProject(userId, "Default Threshold Target");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 4; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.91", method: "POST", path: "/login", statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  assert.equal(alerts.filter((a) => a.rule === "brute-force").length, 0, "4 failures should not trip the default threshold of 5");
});

test("does not flag credential-stuffing for repeated failures from a single IP (that's brute-force's job)", () => {
  const project = createProject(userId, "Single IP Repeats");
  let alerts: ReturnType<typeof runDetection> = [];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: "203.0.113.60", method: "POST", path: "/login", statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  assert.equal(alerts.filter((a) => a.rule.startsWith("credential-stuffing")).length, 0);
  assert.ok(alerts.some((a) => a.rule === "brute-force"), "the same-IP case should still be caught, just by the brute-force rule instead");
});

test("credential-stuffing does not fire for distinct IPs hitting different endpoints", () => {
  const project = createProject(userId, "Scattered Failures");
  let alerts: ReturnType<typeof runDetection> = [];
  const paths = ["/login", "/reset-password", "/admin", "/api/token", "/account"];
  for (let i = 0; i < 5; i++) {
    const event = recordEvent(project.id, { ip: `198.51.100.${100 + i}`, method: "POST", path: paths[i], statusCode: 401 });
    alerts = runDetection(project.id, event);
  }
  assert.equal(alerts.filter((a) => a.rule.startsWith("credential-stuffing")).length, 0);
});
