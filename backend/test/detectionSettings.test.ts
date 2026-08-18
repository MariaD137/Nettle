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

test("a project with no override uses the built-in defaults", () => {
  const project = createProject(userId, "Defaults Target");
  const settings = getDetectionSettings(project.id);
  assert.equal(settings.bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
  assert.equal(settings.highRequestRateThreshold, DEFAULT_DETECTION_SETTINGS.highRequestRateThreshold);
  assert.equal(settings.credentialStuffingMinIps, DEFAULT_DETECTION_SETTINGS.credentialStuffingMinIps);
  assert.equal(settings.updatedAt, null);
});

test("updateDetectionSettings persists a real override and updates only the given fields", () => {
  const project = createProject(userId, "Override Target");
  const updated = updateDetectionSettings(project.id, { bruteForceThreshold: 3 });
  assert.equal(updated.bruteForceThreshold, 3);
  // Untouched fields keep the default.
  assert.equal(updated.highRequestRateThreshold, DEFAULT_DETECTION_SETTINGS.highRequestRateThreshold);
  assert.ok(updated.updatedAt);

  const reloaded = getDetectionSettings(project.id);
  assert.equal(reloaded.bruteForceThreshold, 3);
});

test("updateDetectionSettings updates only the fields provided across multiple calls", () => {
  const project = createProject(userId, "Partial Update Target");
  updateDetectionSettings(project.id, { bruteForceThreshold: 2 });
  const second = updateDetectionSettings(project.id, { highRequestRateThreshold: 200 });
  assert.equal(second.bruteForceThreshold, 2, "the first call's value must survive the second, unrelated update");
  assert.equal(second.highRequestRateThreshold, 200);
});

test("invalid threshold values (non-numeric, zero, negative) fall back to the current value instead of corrupting settings", () => {
  const project = createProject(userId, "Invalid Input Target");
  const before = getDetectionSettings(project.id);

  const afterBogus = updateDetectionSettings(project.id, { bruteForceThreshold: "not-a-number" });
  assert.equal(afterBogus.bruteForceThreshold, before.bruteForceThreshold);

  const afterZero = updateDetectionSettings(project.id, { bruteForceThreshold: 0 });
  assert.equal(afterZero.bruteForceThreshold, before.bruteForceThreshold);

  const afterNegative = updateDetectionSettings(project.id, { credentialStuffingMinIps: -5 });
  assert.equal(afterNegative.credentialStuffingMinIps, before.credentialStuffingMinIps);
});

test("resetDetectionSettings restores the built-in defaults", () => {
  const project = createProject(userId, "Reset Target");
  updateDetectionSettings(project.id, { bruteForceThreshold: 1, highRequestRateThreshold: 1, credentialStuffingMinIps: 1 });
  assert.equal(getDetectionSettings(project.id).bruteForceThreshold, 1);

  const reset = resetDetectionSettings(project.id);
  assert.equal(reset.bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
  assert.equal(reset.updatedAt, null);
});

test("settings for different projects never leak into each other", () => {
  const a = createProject(userId, "Isolated A");
  const b = createProject(userId, "Isolated B");
  updateDetectionSettings(a.id, { bruteForceThreshold: 1 });
  assert.equal(getDetectionSettings(b.id).bruteForceThreshold, DEFAULT_DETECTION_SETTINGS.bruteForceThreshold);
});
