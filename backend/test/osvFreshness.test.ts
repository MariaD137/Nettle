import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { DatabaseSync } from "node:sqlite";
import { getOSVDatabaseFreshness, scanOSVVulnerabilities } from "../src/scanner/osvVulnerabilities";

function buildDb(dir: string, opts?: { metadata?: { generated_at: string; record_count: number; source: string } }): string {
  const dbPath = path.join(dir, "test-osv.db");
  const db = new DatabaseSync(dbPath);
  db.exec(`
    CREATE TABLE vulnerabilities (
      package TEXT NOT NULL, vuln_id TEXT NOT NULL, introduced TEXT NOT NULL,
      fixed TEXT, severity TEXT NOT NULL, summary TEXT NOT NULL
    );
  `);
  if (opts?.metadata) {
    db.exec(`CREATE TABLE metadata (generated_at TEXT NOT NULL, record_count INTEGER NOT NULL, source TEXT NOT NULL);`);
    db.prepare("INSERT INTO metadata (generated_at, record_count, source) VALUES (?, ?, ?)").run(
      opts.metadata.generated_at,
      opts.metadata.record_count,
      opts.metadata.source
    );
  }
  db.close();
  return dbPath;
}

test("getOSVDatabaseFreshness reports UNKNOWN when the database file is missing", () => {
  const result = getOSVDatabaseFreshness("/nonexistent/path/to/nowhere.db");
  assert.equal(result.status, "UNKNOWN");
  assert.equal(result.generatedAt, null);
});

test("getOSVDatabaseFreshness reports UNKNOWN for a database with no metadata table (pre-dates freshness tracking)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-osv-fresh-"));
  try {
    const dbPath = buildDb(dir);
    const result = getOSVDatabaseFreshness(dbPath);
    assert.equal(result.status, "UNKNOWN");
    assert.ok(result.source.includes("pre-dates"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getOSVDatabaseFreshness reports CURRENT for a database generated a day ago", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-osv-fresh-"));
  try {
    const generatedAt = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const dbPath = buildDb(dir, { metadata: { generated_at: generatedAt, record_count: 42, source: "test" } });
    const result = getOSVDatabaseFreshness(dbPath);
    assert.equal(result.status, "CURRENT");
    assert.equal(result.ageDays, 1);
    assert.equal(result.recordCount, 42);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("getOSVDatabaseFreshness reports STALE for a database generated 60 days ago", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-osv-fresh-"));
  try {
    const generatedAt = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString();
    const dbPath = buildDb(dir, { metadata: { generated_at: generatedAt, record_count: 42, source: "test" } });
    const result = getOSVDatabaseFreshness(dbPath);
    assert.equal(result.status, "STALE");
    assert.equal(result.ageDays, 60);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("scanOSVVulnerabilities surfaces the bundled database's real freshness status in its output", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-osv-scan-"));
  try {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: {} }));
    const { findings, passed } = scanOSVVulnerabilities(dir);
    // The bundled database currently pre-dates freshness tracking, so this
    // should show up as an UNKNOWN-status finding rather than silence.
    const freshnessEntries = [...findings, ...passed].filter((f) =>
      f.title.toLowerCase().includes("osv vulnerability database")
    );
    assert.ok(freshnessEntries.length > 0, "should always report a freshness status, not stay silent about it");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
