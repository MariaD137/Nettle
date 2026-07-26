#!/usr/bin/env node
const path = require("path");
const { runScan } = require("../dist/scanner");

const [, , command, target] = process.argv;

if (command !== "scan") {
  console.error("Usage: nettle scan <path>");
  process.exit(1);
}

const report = runScan(target || ".");

console.log(`\nNettle Readiness Scan — ${report.target}`);
console.log(`Score: ${report.score}/100`);
console.log(`Critical: ${report.summary.critical}   Caution: ${report.summary.caution}   Clear: ${report.summary.clear}\n`);
for (const f of report.findings) {
  console.log(`[${f.severity.toUpperCase()}] ${f.category} — ${f.title}${f.file ? " (" + f.file + ")" : ""}`);
}

const outPath = path.join(process.cwd(), "nettle-report.json");
require("fs").writeFileSync(outPath, JSON.stringify(report, null, 2));
console.log(`\nWrote ${outPath}`);

process.exit(report.summary.critical > 0 ? 1 : 0);
