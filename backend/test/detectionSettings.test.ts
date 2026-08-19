import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import {
  getDetectionSettings,
  updateDetectionSettings,
  resetDetectionSettings,
  DEFAULT_DETECTION_SETTINGS,
} from "../src/patrol/detectionSettings";

let userId: string;
before(async () => {
  const user = await createUser("detection-settings-tests@example.com", "correct horse battery staple");
  userId = user.id;
});

test("a project with no override uses the built-in defaults", async () => {
  const project = await createProject(userId, "Defaults Target");
  const settings = await getDetectionSettings(project.id);
  assert.equal(settings.bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
  assert.equal(settings.highRequestRateThreshold, DEFAULT_DETECTION_SETTINGS.highRequestRateThreshold);
  assert.equal(settings.credentialStuffingMinIps, DEFAULT_DETECTION_SETTINGS.credentialStuffingMinIps);
  assert.equal(settings.updatedAt, null);
});

test("updateDetectionSettings persists a real override and updates only the given fields", async () => {
  const project = await createProject(userId, "Override Target");
  const updated = await updateDetectionSettings(project.id, { bruteForceThreshold: 3 });
  assert.equal(updated.bruteForceThreshold, 3);
  // Untouched fields keep the default.
  assert.equal(updated.highRequestRateThreshold, DEFAULT_DETECTION_SETTINGS.highRequestRateThreshold);
  assert.ok(updated.updatedAt);

  const reloaded = await getDetectionSettings(project.id);
  assert.equal(reloaded.bruteForceThreshold, 3);
});

test("updateDetectionSettings updates only the fields provided across multiple calls", async () => {
  const project = await createProject(userId, "Partial Update Target");
  await updateDetectionSettings(project.id, { bruteForceThreshold: 2 });
  const second = await updateDetectionSettings(project.id, { highRequestRateThreshold: 200 });
  assert.equal(second.bruteForceThreshold, 2, "the first call's value must survive the second, unrelated update");
  assert.equal(second.highRequestRateThreshold, 200);
});

test("invalid threshold values (non-numeric, zero, negative) fall back to the current value instead of corrupting settings", async () => {
  const project = await createProject(userId, "Invalid Input Target");
  const before = await getDetectionSettings(project.id);

  const afterBogus = await updateDetectionSettings(project.id, { bruteForceThreshold: "not-a-number" });
  assert.equal(afterBogus.bruteForceThreshold, before.bruteForceThreshold);

  const afterZero = await updateDetectionSettings(project.id, { bruteForceThreshold: 0 });
  assert.equal(afterZero.bruteForceThreshold, before.bruteForceThreshold);

  const afterNegative = await updateDetectionSettings(project.id, { credentialStuffingMinIps: -5 });
  assert.equal(afterNegative.credentialStuffingMinIps, before.credentialStuffingMinIps);
});

test("resetDetectionSettings restores the built-in defaults", async () => {
  const project = await createProject(userId, "Reset Target");
  await updateDetectionSettings(project.id, { bruteForceThreshold: 1, highRequestRateThreshold: 1, credentialStuffingMinIps: 1 });
  assert.equal((await getDetectionSettings(project.id)).bruteForceThreshold, 1);

  const reset = await resetDetectionSettings(project.id);
  assert.equal(reset.bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
  assert.equal(reset.updatedAt, null);
});

test("settings for different projects never leak into each other", async () => {
  const a = await createProject(userId, "Isolated A");
  const b = await createProject(userId, "Isolated B");
  await updateDetectionSettings(a.id, { bruteForceThreshold: 1 });
  assert.equal((await getDetectionSettings(b.id)).bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
});
