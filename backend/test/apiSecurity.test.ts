import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { scanApiSecurity } from "../src/scanner/apiSecurity";
import { runScan } from "../src/scanner";

function tempFile(contents: string, ext = ".js"): { dir: string; file: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-apisecurity-"));
  const file = path.join(dir, `app${ext}`);
  fs.writeFileSync(file, contents);
  return { dir, file };
}

// --- Path traversal ---

test("flags a file read built directly from request input", () => {
  const { dir, file } = tempFile(`
    app.get('/download', (req, res) => {
      const data = fs.readFileSync(req.query.file);
      res.send(data);
    });
  `);
  try {
    const { findings, passed } = scanApiSecurity([file], dir);
    const finding = findings.find((f) => f.title === "Potential path traversal vulnerability");
    assert.ok(finding, "expected a path traversal finding");
    assert.equal(finding!.severity, "critical");
    assert.equal(finding!.file, "app.js");
    assert.ok(finding!.line, "expected a line number to be attached");
    assert.equal(passed.some((p) => p.title === "No path traversal patterns detected"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not flag a file read that isn't built from request input", () => {
  const { dir, file } = tempFile(`
    app.get('/logo', (req, res) => {
      const data = fs.readFileSync('assets/logo.png');
      res.send(data);
    });
  `);
  try {
    const { findings, passed } = scanApiSecurity([file], dir);
    assert.equal(findings.some((f) => f.title === "Potential path traversal vulnerability"), false);
    assert.ok(passed.some((p) => p.title === "No path traversal patterns detected"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("path traversal detection reaches the aggregated scan report", () => {
  const { dir } = tempFile(`
    app.get('/download', (req, res) => {
      res.sendFile(path.join(baseDir, req.params.name));
    });
  `);
  try {
    const report = runScan(dir);
    assert.ok(report.findings.some((f) => f.title === "Potential path traversal vulnerability"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- Unsafe deserialization ---

test("flags node-serialize usage", () => {
  const { dir, file } = tempFile(`
    const serialize = require('node-serialize');
    app.post('/session', (req, res) => {
      const obj = serialize.unserialize(req.body.data);
      res.json(obj);
    });
  `);
  try {
    const { findings, passed } = scanApiSecurity([file], dir);
    const finding = findings.find((f) => f.title === "Potentially unsafe deserialization");
    assert.ok(finding, "expected an unsafe deserialization finding");
    assert.equal(finding!.severity, "high");
    assert.equal(passed.some((p) => p.title === "No unsafe deserialization patterns detected"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("flags unsafe YAML loading", () => {
  const { dir, file } = tempFile(`
    const yaml = require('js-yaml');
    app.post('/config', (req, res) => {
      const config = yaml.load(req.body.yaml);
      res.json(config);
    });
  `);
  try {
    const { findings } = scanApiSecurity([file], dir);
    assert.ok(findings.some((f) => f.title === "Potentially unsafe deserialization"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not flag code with no deserialization patterns at all", () => {
  const { dir, file } = tempFile(`
    app.post('/echo', (req, res) => {
      res.json({ ok: true });
    });
  `);
  try {
    const { findings, passed } = scanApiSecurity([file], dir);
    assert.equal(findings.some((f) => f.title === "Potentially unsafe deserialization"), false);
    assert.ok(passed.some((p) => p.title === "No unsafe deserialization patterns detected"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("does not flag plain JSON.parse(req.body) — it isn't RCE-capable the way the other patterns are", () => {
  const { dir, file } = tempFile(`
    app.post('/webhook', (req, res) => {
      const payload = JSON.parse(req.body.toString());
      res.json({ received: payload });
    });
  `);
  try {
    const { findings, passed } = scanApiSecurity([file], dir);
    assert.equal(findings.some((f) => f.title === "Potentially unsafe deserialization"), false);
    assert.ok(passed.some((p) => p.title === "No unsafe deserialization patterns detected"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("unsafe deserialization detection reaches the aggregated scan report", () => {
  const { dir } = tempFile(`
    app.post('/exec', (req, res) => {
      eval(JSON.parse(req.body.expr));
    });
  `);
  try {
    const report = runScan(dir);
    assert.ok(report.findings.some((f) => f.title === "Potentially unsafe deserialization"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
