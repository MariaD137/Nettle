#!/usr/bin/env node
// Same purpose and process as build-osv-db.js, for the PyPI ecosystem
// instead of npm. Kept as a separate script rather than parameterizing the
// original because the two ecosystems' OSV range shapes actually differ:
// npm advisories use range.type "SEMVER"; PyPI advisories use "ECOSYSTEM"
// (confirmed by inspecting a real sample of the PyPI bulk export before
// writing this — see the check in this repo's history). Forcing one script
// to branch on ecosystem-specific range-type strings was judged less clear
// than two small, honest scripts.
//
// Usage: node scripts/build-osv-db-pypi.js <path-to-extracted-osv-pypi-json-dir>
// Source: https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip

const fs = require("fs");
const path = require("path");
const { DatabaseSync } = require("node:sqlite");

const SRC_DIR = process.argv[2];
const OUT_PATH = path.join(__dirname, "..", "src", "scanner", "osv-data", "pypi-vulnerabilities.db");

if (!SRC_DIR || !fs.existsSync(SRC_DIR)) {
  console.error("Usage: node scripts/build-osv-db-pypi.js <path-to-extracted-osv-pypi-json-dir>");
  process.exit(1);
}

fs.mkdirSync(path.dirname(OUT_PATH), { recursive: true });
fs.rmSync(OUT_PATH, { force: true });

const db = new DatabaseSync(OUT_PATH);
db.exec(`
  CREATE TABLE vulnerabilities (
    package TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    introduced TEXT NOT NULL,
    fixed TEXT,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL
  );
  CREATE INDEX idx_vuln_package ON vulnerabilities(package);
`);

function severityLabel(record) {
  const dbSev = record.database_specific && record.database_specific.severity;
  if (typeof dbSev === "string") return dbSev.toUpperCase();
  const cvss = (record.severity || []).find((s) => typeof s.score === "string" && /^[\d.]+$/.test(s.score));
  if (cvss) {
    const n = parseFloat(cvss.score);
    if (n >= 9) return "CRITICAL";
    if (n >= 7) return "HIGH";
    if (n >= 4) return "MODERATE";
    return "LOW";
  }
  return "MODERATE";
}

// PyPI package names are canonicalized by normalizing case and treating
// "-"/"_"/"." as equivalent (PEP 503) — a requirements.txt can spell the
// same package "Flask-SQLAlchemy", "flask_sqlalchemy", or
// "flask-sqlalchemy" and mean the same install. Store the canonical form so
// a lookup normalized the same way at scan time actually matches.
function canonicalize(name) {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

const insert = db.prepare(
  "INSERT INTO vulnerabilities (package, vuln_id, introduced, fixed, severity, summary) VALUES (?, ?, ?, ?, ?, ?)"
);

let filesProcessed = 0;
let rowsInserted = 0;
const files = fs.readdirSync(SRC_DIR).filter((f) => f.endsWith(".json"));

db.exec("BEGIN TRANSACTION");
for (const file of files) {
  filesProcessed++;
  if (filesProcessed % 5000 === 0) console.log(`...${filesProcessed}/${files.length} files`);

  let record;
  try {
    record = JSON.parse(fs.readFileSync(path.join(SRC_DIR, file), "utf8"));
  } catch {
    continue;
  }

  const summary = (record.summary || "").slice(0, 200);
  const sev = severityLabel(record);

  for (const affected of record.affected || []) {
    if (!affected.package || affected.package.ecosystem !== "PyPI") continue;
    for (const range of affected.ranges || []) {
      if (range.type !== "ECOSYSTEM") continue; // GIT ranges have no comparable version — skip, don't guess
      let introduced = "0.0.0";
      let fixed = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) introduced = event.introduced === "0" ? "0.0.0" : event.introduced;
        if (event.fixed !== undefined) fixed = event.fixed;
      }
      insert.run(canonicalize(affected.package.name), record.id, introduced, fixed, sev, summary);
      rowsInserted++;
    }
  }
}
db.exec("COMMIT");

console.log(`Processed ${filesProcessed} files, inserted ${rowsInserted} PyPI vulnerability ranges.`);
console.log(`Wrote ${OUT_PATH} (${(fs.statSync(OUT_PATH).size / 1024 / 1024).toFixed(1)} MB)`);
