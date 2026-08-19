import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { getOwnedProject } from "../src/patrol/projectAccess";

// M-11: getOwnedProject is now the single authoritative ownership check
// projects.routes.ts, customRules.routes.ts, analytics.routes.ts, and
// integrations.routes.ts all depend on — previously each had its own
// separately-maintained copy of this exact query. Testing it directly
// here covers the property every one of those routers relies on, rather
// than re-deriving the same assertions once per router.

let counter = 0;
async function owner() {
  const user = await createUser(`project-access-${counter++}@example.com`, "correct horse battery staple");
  const project = await createProject(user.id, "Owned Project");
  return { user, project };
}

test("the owner gets their project back", async () => {
  const { user, project } = await owner();
  const result = await getOwnedProject(project.id, user.id);
  assert.ok(result);
  assert.equal(result!.id, project.id);
});

test("a different user gets null, not the project", async () => {
  const { project } = await owner();
  const intruder = await createUser(`project-access-intruder-${counter++}@example.com`, "correct horse battery staple");

  assert.equal(await getOwnedProject(project.id, intruder.id), null);
});

test("no userId at all gets null, even for a real project id", async () => {
  const { project } = await owner();
  assert.equal(await getOwnedProject(project.id, undefined), null);
  assert.equal(await getOwnedProject(project.id, null), null);
});

test("a project id that doesn't exist gets null, not a thrown error", async () => {
  const { user } = await owner();
  assert.equal(await getOwnedProject("00000000-0000-0000-0000-000000000000", user.id), null);
});

test("no projectId at all gets null", async () => {
  const { user } = await owner();
  assert.equal(await getOwnedProject(undefined, user.id), null);
  assert.equal(await getOwnedProject(null, user.id), null);
  assert.equal(await getOwnedProject("", user.id), null);
});

test("a user's second project doesn't get returned for a different project id they also own — no accidental wildcard match", async () => {
  const { user, project: projectA } = await owner();
  const projectB = await createProject(user.id, "Second Owned Project");

  const resultForA = await getOwnedProject(projectA.id, user.id);
  const resultForB = await getOwnedProject(projectB.id, user.id);
  assert.equal(resultForA!.id, projectA.id);
  assert.equal(resultForB!.id, projectB.id);
  assert.notEqual(resultForA!.id, resultForB!.id);
});
