import { test } from "node:test";
import assert from "node:assert/strict";
import { createProject, updateProject, getProject, deleteProject, rotateApiKey, findProjectByApiKey } from "../src/patrol/projects";
import { listApiKeys } from "../src/patrol/apiKeys";
import { createUser } from "../src/auth/users";

const PASSWORD = "correct horse battery staple";
let counter = 0;
async function testUserId(): Promise<string> {
  const user = await createUser(`projects-test-${counter++}@example.com`, PASSWORD);
  return user.id;
}

test("createProject persists repository info alongside the application url", async () => {
  const userId = await testUserId();
  const project = await createProject(userId, "My App", {
    url: "https://myapp.com",
    repoUrl: "https://github.com/owner/repo",
    repoBranch: "main",
  });

  assert.equal(project.url, "https://myapp.com");
  assert.equal(project.repoUrl, "https://github.com/owner/repo");
  assert.equal(project.repoBranch, "main");

  const fetched = await getProject(project.id);
  assert.equal(fetched?.repoUrl, "https://github.com/owner/repo");
  assert.equal(fetched?.repoBranch, "main");
});

test("createProject defaults repository info to null when omitted", async () => {
  const userId = await testUserId();
  const project = await createProject(userId, "No Repo");
  assert.equal(project.repoUrl, null);
  assert.equal(project.repoBranch, null);
});

test("updateProject can set, change, and clear repository info independently of other fields", async () => {
  const userId = await testUserId();
  const project = await createProject(userId, "Evolving App", { description: "original desc" });

  const withRepo = await updateProject(project.id, { repoUrl: "https://github.com/owner/repo", repoBranch: "develop" });
  assert.equal(withRepo?.repoUrl, "https://github.com/owner/repo");
  assert.equal(withRepo?.repoBranch, "develop");
  // Unrelated fields must survive an update that only touches repo info.
  assert.equal(withRepo?.description, "original desc");

  const rebranched = await updateProject(project.id, { repoBranch: "main" });
  assert.equal(rebranched?.repoUrl, "https://github.com/owner/repo");
  assert.equal(rebranched?.repoBranch, "main");

  const cleared = await updateProject(project.id, { repoUrl: "" });
  assert.equal(cleared?.repoUrl, "");
});

test("rotateApiKey (legacy, project-level) keeps projects.api_key and the default api_keys row in sync", async () => {
  const userId = await testUserId();
  const project = await createProject(userId, "Rotate Sync Target");
  const oldKey = project.apiKey;

  const rotated = await rotateApiKey(project.id);
  assert.notEqual(rotated?.apiKey, oldKey);

  const [defaultKey] = await listApiKeys(project.id);
  assert.equal(defaultKey.isDefault, true);
  // listApiKeys returns the masked form — confirm the *value* changed by
  // checking auth behavior instead of comparing strings directly.
  assert.equal(await findProjectByApiKey(oldKey), null, "the old key must stop working immediately");
  assert.ok(await findProjectByApiKey(rotated!.apiKey), "the new key (mirrored into both places) must work");
});

test("deleteProject removes its api_keys rows too — no orphaned keys left behind", async () => {
  const userId = await testUserId();
  const project = await createProject(userId, "To Delete");
  const key = project.apiKey;
  assert.ok(await findProjectByApiKey(key));

  await deleteProject(project.id);

  assert.equal(await findProjectByApiKey(key), null);
});
