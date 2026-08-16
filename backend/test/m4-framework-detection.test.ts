import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { detectFrameworks } from "../src/scanner/frameworkDetection";

test("M-4: detect next.js from config file", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "next-test-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "next.config.js"), "module.exports = {}");
    const result = detectFrameworks(tmpDir);

    assert.ok(result.detected.includes("next.js"));
    assert.equal(result.primaryFramework, "next.js");
    assert.ok(result.confidence > 0);
    assert.ok(result.detectionMethod.includes("next.config.js"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: detect express from package.json", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "express-test-"));
  try {
    const pkg = {
      name: "app",
      dependencies: { express: "^4.18.0" },
    };

    const result = detectFrameworks(tmpDir, pkg);
    assert.ok(result.detected.includes("express"));
    assert.ok(result.detectionMethod.includes("package.json"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: detect django from package requirements", () => {
  // Django uses Python, not npm, so we test with file-based detection
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "django-test-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "settings.py"), "");
    fs.writeFileSync(path.join(tmpDir, "urls.py"), "");
    const sourceFiles = [
      path.join(tmpDir, "settings.py"),
      path.join(tmpDir, "urls.py"),
    ];

    const result = detectFrameworks(tmpDir, {}, sourceFiles);
    assert.ok(result.detected.includes("django"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: detect multiple frameworks in monorepo", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "monorepo-test-"));
  try {
    // Frontend: Next.js + React
    fs.writeFileSync(path.join(tmpDir, "next.config.js"), "");
    const pkg = {
      dependencies: {
        react: "^18.0.0",
        express: "^4.18.0",
        tailwindcss: "^3.0.0",
      },
    };

    const result = detectFrameworks(tmpDir, pkg);
    assert.ok(result.detected.includes("next.js"));
    assert.ok(result.detected.includes("react"));
    assert.ok(result.detected.includes("express"));
    assert.ok(result.detected.includes("tailwind")); // Package "tailwindcss" → framework "tailwind"
    // Primary should be Next.js (higher priority)
    assert.equal(result.primaryFramework, "next.js");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: confidence increases with multiple signals", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "confidence-test-"));
  try {
    // One signal: package.json only
    const pkg1 = { dependencies: { react: "^18.0.0" } };
    const result1 = detectFrameworks(tmpDir, pkg1);
    const confidence1 = result1.confidence;

    // Two signals: package.json + config file
    fs.writeFileSync(path.join(tmpDir, "next.config.js"), "");
    const pkg2 = { dependencies: { next: "^13.0.0" } };
    const result2 = detectFrameworks(tmpDir, pkg2);
    const confidence2 = result2.confidence;

    assert.ok(confidence2 > confidence1 || confidence2 === 100);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: framework detection from source patterns", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pattern-test-"));
  try {
    const testFile = path.join(tmpDir, "api.ts");
    fs.writeFileSync(testFile, "app.get('/users', (req, res) => { res.json([]) })");

    const result = detectFrameworks(tmpDir, {}, [testFile]);
    assert.ok(result.detected.includes("express"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: empty project returns null primary framework", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "empty-test-"));
  try {
    const result = detectFrameworks(tmpDir, {}, []);
    assert.equal(result.primaryFramework, null);
    assert.equal(result.detected.length, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: framework detection result includes method", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "method-test-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "tsconfig.json"), "{}");
    const pkg = { dependencies: { react: "^18.0.0" } };

    const result = detectFrameworks(tmpDir, pkg);
    assert.ok(result.detectionMethod.length > 0);
    assert.ok(
      result.detectionMethod.includes("tsconfig.json") ||
        result.detectionMethod.includes("package.json")
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: framework priority ordering", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "priority-test-"));
  try {
    // Both Next.js and React present; Next.js should be primary
    const pkg = {
      dependencies: { next: "^13.0.0", react: "^18.0.0" },
    };

    const result = detectFrameworks(tmpDir, pkg);
    assert.equal(result.primaryFramework, "next.js");

    // Both Express and Flask; Express should be primary (higher priority)
    const flaskPkg = {
      dependencies: { express: "^4.18.0", flask: "^2.0.0" },
    };

    const flaskResult = detectFrameworks(tmpDir, flaskPkg);
    assert.equal(flaskResult.primaryFramework, "express");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("M-4: confidence is 0-100", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bounds-test-"));
  try {
    const pkg = {
      dependencies: {
        react: "^18.0.0",
        express: "^4.18.0",
        django: "^4.0.0",
      },
    };

    const result = detectFrameworks(tmpDir, pkg);
    assert.ok(result.confidence >= 0 && result.confidence <= 100);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
