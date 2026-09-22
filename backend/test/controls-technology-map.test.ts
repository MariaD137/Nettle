import { test } from "node:test";
import assert from "node:assert/strict";
import path from "path";
import { mapFrameworkToTechnology } from "../src/scanner/controls/technologyMap";
import { runScan } from "../src/scanner";

test("mapFrameworkToTechnology bridges frameworkDetection's names to control technology keys", () => {
  assert.equal(mapFrameworkToTechnology("express"), "express");
  assert.equal(mapFrameworkToTechnology("django"), "django");
  assert.equal(mapFrameworkToTechnology("flask"), "flask");
  assert.equal(mapFrameworkToTechnology("fastapi"), "fastapi");
  assert.equal(mapFrameworkToTechnology("next.js"), "nextjs"); // the dot is the whole point of this map
  assert.equal(mapFrameworkToTechnology("nuxt"), "nuxt");
});

test("mapFrameworkToTechnology returns undefined (not a wrong guess) for a framework no control has a fix for", () => {
  assert.equal(mapFrameworkToTechnology("react"), undefined);
  assert.equal(mapFrameworkToTechnology("tailwind"), undefined);
  assert.equal(mapFrameworkToTechnology(null), undefined);
});

test("runScan attaches detectedTechnology for a real Express fixture", () => {
  const report = runScan(path.join(__dirname, "fixtures", "sample-app"));
  assert.equal(report.detectedTechnology, "express");
});
