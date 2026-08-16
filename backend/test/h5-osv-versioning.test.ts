import { test } from "node:test";
import assert from "node:assert/strict";
import {
  getOSVDatabase,
  initializeOSVDatabase,
  createOfflineDatabaseMetadata,
  createNpmDatabaseMetadata,
  createPyPIDatabaseMetadata,
  isDatabaseFresh,
  generateOSVReport,
  resetOSVDatabase,
} from "../src/scanner/osvVersioning";
import type { OSVDatabaseMetadata, VulnerabilityRecord } from "../src/scanner/osvVersioning";

test("H-5: OSV database singleton", () => {
  resetOSVDatabase();
  const db1 = getOSVDatabase();
  const db2 = getOSVDatabase();

  assert.equal(db1, db2);
});

test("H-5: Initialize OSV database with metadata", () => {
  resetOSVDatabase();
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 100,
    confidence: 95,
  };

  initializeOSVDatabase(metadata);
  const db = getOSVDatabase();
  const storedMetadata = db.getMetadata();

  assert.ok(storedMetadata);
  assert.equal(storedMetadata.version, "1.0.0");
  assert.equal(storedMetadata.confidence, 95);
});

test("H-5: Create offline database metadata", () => {
  const metadata = createOfflineDatabaseMetadata();

  assert.equal(metadata.source, "offline");
  assert.ok(metadata.fetchedAt);
  assert.ok(metadata.lastUpdated);
  assert.ok(metadata.version.includes("offline"));
  assert.ok(metadata.confidence <= 75); // Offline should have lower confidence
});

test("H-5: Create npm database metadata", () => {
  const npmData = {
    version: "npm-audit-v7",
    lastUpdated: new Date(2026, 7, 1).toISOString(),
    recordCount: 500,
  };

  const metadata = createNpmDatabaseMetadata(npmData);

  assert.equal(metadata.source, "npm");
  assert.ok(metadata.confidence >= 85); // npm should have high confidence
});

test("H-5: Create PyPI database metadata", () => {
  const pypiData = {
    version: "pypi-2026-08",
    lastUpdated: new Date(2026, 7, 10).toISOString(),
    recordCount: 300,
  };

  const metadata = createPyPIDatabaseMetadata(pypiData);

  assert.equal(metadata.source, "pypi");
  assert.ok(metadata.confidence >= 80); // PyPI should have high confidence
});

test("H-5: Database metadata tracks version", () => {
  resetOSVDatabase();
  const metadata: OSVDatabaseMetadata = {
    version: "2026-08-16",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 200,
    confidence: 90,
  };

  initializeOSVDatabase(metadata);
  const db = getOSVDatabase();

  assert.equal(db.getMetadata()?.version, "2026-08-16");
});

test("H-5: Check if database is fresh", () => {
  resetOSVDatabase();
  const now = new Date();
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: now.toISOString(),
    source: "npm",
    lastUpdated: now.toISOString(),
    recordCount: 100,
    confidence: 90,
  };

  initializeOSVDatabase(metadata);
  assert.ok(isDatabaseFresh(7)); // 7 days old, should be fresh
});

test("H-5: Check if stale database is detected", () => {
  resetOSVDatabase();
  const oldDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: oldDate.toISOString(),
    source: "npm",
    lastUpdated: oldDate.toISOString(),
    recordCount: 100,
    confidence: 50, // Lower confidence for old data
  };

  initializeOSVDatabase(metadata);
  assert.ok(!isDatabaseFresh(7)); // Should be stale
});

test("H-5: Uninitialized database is not fresh", () => {
  resetOSVDatabase();
  assert.ok(!isDatabaseFresh());
});

test("H-5: Generate OSV report with metadata", () => {
  resetOSVDatabase();
  const metadata: OSVDatabaseMetadata = {
    version: "test-1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 250,
    confidence: 88,
  };

  initializeOSVDatabase(metadata);
  const report = generateOSVReport();

  assert.ok(report.includes("test-1.0.0"));
  assert.ok(report.includes("npm"));
  assert.ok(report.includes("88%"));
  assert.ok(report.includes("OSV Database Report"));
});

test("H-5: Database report includes statistics", () => {
  resetOSVDatabase();
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 100,
    confidence: 90,
  };

  initializeOSVDatabase(metadata);
  const report = generateOSVReport();

  assert.ok(report.includes("Statistics"));
  assert.ok(report.includes("Total Records"));
});

test("H-5: Multiple metadata sources can coexist", () => {
  resetOSVDatabase();

  const npmMeta: OSVDatabaseMetadata = {
    version: "npm-1.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 500,
    confidence: 90,
  };

  initializeOSVDatabase(npmMeta);
  const db = getOSVDatabase();
  const meta = db.getMetadata();

  assert.equal(meta?.source, "npm");
  assert.equal(meta?.recordCount, 500);
});

test("H-5: Database metadata includes timestamps", () => {
  resetOSVDatabase();
  const now = new Date();
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: now.toISOString(),
    source: "npm",
    lastUpdated: now.toISOString(),
    recordCount: 100,
    confidence: 90,
  };

  initializeOSVDatabase(metadata);
  const db = getOSVDatabase();
  const meta = db.getMetadata()!;

  assert.ok(new Date(meta.fetchedAt) instanceof Date);
  assert.ok(new Date(meta.lastUpdated) instanceof Date);
});

test("H-5: Confidence level reflects data freshness", () => {
  resetOSVDatabase();

  // Fresh data should have high confidence
  const freshMeta: OSVDatabaseMetadata = {
    version: "fresh",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 100,
    confidence: 95,
  };

  initializeOSVDatabase(freshMeta);
  assert.equal(getOSVDatabase().getMetadata()?.confidence, 95);

  // Offline data should have lower confidence
  resetOSVDatabase();
  const offlineMeta = createOfflineDatabaseMetadata();
  initializeOSVDatabase(offlineMeta);
  assert.ok(getOSVDatabase().getMetadata()!.confidence < 75);
});

test("H-5: Reset clears database state", () => {
  resetOSVDatabase();
  const metadata: OSVDatabaseMetadata = {
    version: "1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: new Date().toISOString(),
    recordCount: 100,
    confidence: 90,
  };

  initializeOSVDatabase(metadata);
  assert.ok(getOSVDatabase().getMetadata());

  resetOSVDatabase();
  assert.equal(getOSVDatabase().getMetadata(), null);
});
