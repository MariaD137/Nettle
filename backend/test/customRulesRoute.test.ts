import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createSession, resolveSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import customRulesRouter from "../src/routes/customRules.routes";

// H-3: the existing phase12-custom-rules.test.ts exercises the underlying
// business logic (patrol/customRules.ts) directly, calling
// createCustomRule/listCustomRules/etc. in-process. It never sends a real
// HTTP request, so it never actually proves the router/middleware chain —
// verifyProjectAccess and getOwnedRule in customRules.routes.ts — protects
// the endpoint. These tests do that: real HTTP requests through the real
// Express app, asserting the auth/ownership boundary itself, not the rule
// logic behind it.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/custom-rules", customRulesRouter);
  return app;
}

const PASSWORD = "correct horse battery staple";
let counter = 0;

async function ownerWithProjectAndRule() {
  const app = buildApp();
  const { server, base } = await listen(app);
  const user = await createUser(`customrules-owner-${counter++}@example.com`, PASSWORD);
  const token = await createSession(user.id);
  const project = await createProject(user.id, "Owner Project");

  const createRes = await fetch(`${base}/api/custom-rules/${project.id}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ name: "Admin path", pattern_type: "exact", pattern_value: "/admin" }),
  });
  const rule = await createRes.json();

  return { server, base, token, projectId: project.id, ruleId: rule.id as string };
}

test("an authenticated owner can create and read a custom rule for their own project", async () => {
  const { server, base, token, projectId } = await ownerWithProjectAndRule();
  try {
    const res = await fetch(`${base}/api/custom-rules/${projectId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.rules.length, 1);
    assert.equal(body.rules[0].pattern_value, "/admin");
  } finally {
    server.close();
  }
});

test("an authenticated owner can read a single rule by id", async () => {
  const { server, base, token, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const res = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.id, ruleId);
  } finally {
    server.close();
  }
});

test("an unauthenticated request is rejected on every route in the router", async () => {
  const { server, base, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const routes: [string, string][] = [
      ["POST", `/api/custom-rules/${projectId}`],
      ["GET", `/api/custom-rules/${projectId}`],
      ["GET", `/api/custom-rules/${projectId}/${ruleId}`],
      ["PATCH", `/api/custom-rules/${projectId}/${ruleId}`],
      ["DELETE", `/api/custom-rules/${projectId}/${ruleId}`],
      ["POST", `/api/custom-rules/${projectId}/${ruleId}/test`],
      ["GET", `/api/custom-rules/${projectId}/${ruleId}/versions`],
      ["GET", `/api/custom-rules/${projectId}/${ruleId}/test-results`],
    ];
    for (const [method, path] of routes) {
      const res = await fetch(`${base}${path}`, {
        method,
        headers: { "Content-Type": "application/json" },
        body: method === "GET" || method === "DELETE" ? undefined : "{}",
      });
      assert.equal(res.status, 401, `${method} ${path} should require authentication`);
    }
  } finally {
    server.close();
  }
});

test("an authenticated non-owner is refused access to another account's project (403), not shown its rules", async () => {
  const { server, base, projectId } = await ownerWithProjectAndRule();
  try {
    const intruder = await createUser(`customrules-intruder-${counter++}@example.com`, PASSWORD);
    const intruderToken = await createSession(intruder.id);

    const res = await fetch(`${base}/api/custom-rules/${projectId}`, {
      headers: { Authorization: `Bearer ${intruderToken}` },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("a request against a project id that doesn't exist gets the same 403 as one that isn't yours — no existence leak", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser(`customrules-missingproj-${counter++}@example.com`, PASSWORD);
    const token = await createSession(user.id);

    const res = await fetch(`${base}/api/custom-rules/00000000-0000-0000-0000-000000000000`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("a non-owner cannot create a rule under someone else's project", async () => {
  const { server, base, projectId } = await ownerWithProjectAndRule();
  try {
    const intruder = await createUser(`customrules-intruder-create-${counter++}@example.com`, PASSWORD);
    const intruderToken = await createSession(intruder.id);

    const res = await fetch(`${base}/api/custom-rules/${projectId}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${intruderToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Malicious rule", pattern_type: "exact", pattern_value: "/x" }),
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("a rule id valid for one of the caller's own projects does not resolve under a different project id (rule-to-project binding is enforced)", async () => {
  const { server, base, token, ruleId } = await ownerWithProjectAndRule();
  try {
    // A second project owned by the SAME user — proves getOwnedRule checks
    // the rule's actual project_id, not merely "does this caller own *a*
    // project," which the outer verifyProjectAccess alone wouldn't catch.
    const session = (await resolveSession(token))!;
    const secondProject = await createProject(session.userId, "Second Project");

    const res = await fetch(`${base}/api/custom-rules/${secondProject.id}/${ruleId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 404, "a rule id valid for one of the caller's projects must not resolve under a different project id");
  } finally {
    server.close();
  }
});

test("accessing an unauthorized rule id under the caller's own (different) project returns 404, not the rule", async () => {
  const owner = await ownerWithProjectAndRule();
  try {
    // Owner's rule lives under owner.projectId. A second project belonging
    // to a *different* user should not expose that rule via a mismatched
    // (projectId, ruleId) pair even if somehow guessed.
    const other = await createUser(`customrules-otherproj-${counter++}@example.com`, PASSWORD);
    const otherToken = await createSession(other.id);
    const otherProject = await createProject(other.id, "Other User Project");

    const res = await fetch(`${owner.base}/api/custom-rules/${otherProject.id}/${owner.ruleId}`, {
      headers: { Authorization: `Bearer ${otherToken}` },
    });
    // otherToken does own otherProject, so verifyProjectAccess (403 gate)
    // passes — but the ruleId belongs to a completely different project,
    // so getOwnedRule must still refuse it with 404.
    assert.equal(res.status, 404);
  } finally {
    owner.server.close();
  }
});

test("a malformed create request (missing required fields) is rejected with 400, not a 500 or a silent partial create", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser(`customrules-malformed-${counter++}@example.com`, PASSWORD);
    const token = await createSession(user.id);
    const project = await createProject(user.id, "Malformed Test Project");

    const missingFields = await fetch(`${base}/api/custom-rules/${project.id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "No pattern" }),
    });
    assert.equal(missingFields.status, 400);

    const badPatternType = await fetch(`${base}/api/custom-rules/${project.id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Bad type", pattern_type: "not-a-real-type", pattern_value: "x" }),
    });
    assert.equal(badPatternType.status, 400);

    const list = await fetch(`${base}/api/custom-rules/${project.id}`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal((await list.json()).rules.length, 0, "a rejected create must not have persisted anything");
  } finally {
    server.close();
  }
});

test("owner can update and delete their own rule; both 404 once deleted", async () => {
  const { server, base, token, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const patchRes = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ weight: 90 }),
    });
    assert.equal(patchRes.status, 200);
    assert.equal((await patchRes.json()).weight, 90);

    const deleteRes = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(deleteRes.status, 200);

    const afterDelete = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(afterDelete.status, 404);
  } finally {
    server.close();
  }
});

test("a non-owner cannot update or delete the owner's rule", async () => {
  const { server, base, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const intruder = await createUser(`customrules-intruder-mutate-${counter++}@example.com`, PASSWORD);
    const intruderToken = await createSession(intruder.id);

    const patchRes = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${intruderToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ weight: 1 }),
    });
    assert.equal(patchRes.status, 403);

    const deleteRes = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${intruderToken}` },
    });
    assert.equal(deleteRes.status, 403);
  } finally {
    server.close();
  }
});

test("the /test endpoint enforces the same ownership boundary as everything else", async () => {
  const { server, base, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const intruder = await createUser(`customrules-intruder-test-${counter++}@example.com`, PASSWORD);
    const intruderToken = await createSession(intruder.id);

    const res = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}/test`, {
      method: "POST",
      headers: { Authorization: `Bearer ${intruderToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ events: [{ path: "/admin" }] }),
    });
    assert.equal(res.status, 403);
  } finally {
    server.close();
  }
});

test("the /test endpoint rejects an empty or oversized events array with 400, not a crash", async () => {
  const { server, base, token, projectId, ruleId } = await ownerWithProjectAndRule();
  try {
    const empty = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}/test`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ events: [] }),
    });
    assert.equal(empty.status, 400);

    // Deliberately tiny event objects — the assertion is about the route's
    // own 10,000-event cap (customRules.routes.ts), not Express's separate
    // body-size limit, which a larger payload would trip first.
    const tooMany = await fetch(`${base}/api/custom-rules/${projectId}/${ruleId}/test`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ events: Array.from({ length: 10001 }, () => ({})) }),
    });
    assert.equal(tooMany.status, 400);
  } finally {
    server.close();
  }
});
