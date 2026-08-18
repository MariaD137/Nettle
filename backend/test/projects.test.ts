import { test } from "node:test";
import assert from "node:assert/strict";
import { createProject, updateProject, getProject } from "../src/patrol/projects";
import { createUser } from "../src/auth/users";

const PASSWORD = "correct horse battery staple";
let counter = 0;
async function testUserId(): Promise<string> {
  const user = await createUser(`projects-test-${counter++}@example.com`, PASSWORD);
  return user.id;
}

test("createProject persists repository info alongside the application url", async () => {
  const userId = await testUserId();
  const project = createProject(userId, "My App", {
    url: "https://myapp.com",
    repoUrl: "https://github.com/owner/repo",
    repoBranch: "main",
  });

  assert.equal(project.url, "https://myapp.com");
  assert.equal(project.repoUrl, "https://github.com/owner/repo");
  assert.equal(project.repoBranch, "main");

  const fetched = getProject(project.id);
  assert.equal(fetched?.repoUrl, "https://github.com/owner/repo");
  assert.equal(fetched?.repoBranch, "main");
});

test("createProject defaults repository info to null when omitted", async () => {
  const userId = await testUserId();
  const project = createProject(userId, "No Repo");
  assert.equal(project.repoUrl, null);
  assert.equal(project.repoBranch, null);
});

test("updateProject can set, change, and clear repository info independently of other fields", async () => {
  const userId = await testUserId();
  const project = createProject(userId, "Evolving App", { description: "original desc" });

  const withRepo = updateProject(project.id, { repoUrl: "https://github.com/owner/repo", repoBranch: "develop" });
  assert.equal(withRepo?.repoUrl, "https://github.com/owner/repo");
  assert.equal(withRepo?.repoBranch, "develop");
  // Unrelated fields must survive an update that only touches repo info.
  assert.equal(withRepo?.description, "original desc");

  const rebranched = updateProject(project.id, { repoBranch: "main" });
  assert.equal(rebranched?.repoUrl, "https://github.com/owner/repo");
  assert.equal(rebranched?.repoBranch, "main");

  const cleared = updateProject(project.id, { repoUrl: "" });
  assert.equal(cleared?.repoUrl, "");
});
