import chalk from "chalk";

const SEVERITY_COLORS = {
  critical: chalk.red.bold,
  high: chalk.yellow.bold,
  medium: chalk.cyan,
  low: chalk.dim,
  info: chalk.dim,
};

const SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function colorSeverity(severity) {
  const colorFn = SEVERITY_COLORS[severity] || chalk.white;
  return colorFn(severity.toUpperCase());
}

export function formatScore(score) {
  let colorFn;
  if (score >= 80) colorFn = chalk.green.bold;
  else if (score >= 60) colorFn = chalk.yellow.bold;
  else if (score >= 40) colorFn = chalk.hex("#FF8800").bold;
  else colorFn = chalk.red.bold;

  const lines = [
    "",
    chalk.bold("  Security Score"),
    "",
    `    ${colorFn(score + " / 100")}`,
    "",
  ];
  return lines.join("\n");
}

export function formatSummary(summary) {
  const lines = [
    chalk.bold("  Findings Summary"),
    "",
    `    ${chalk.red.bold(summary.critical)}  Critical`,
    `    ${chalk.yellow.bold(summary.high)}  High`,
    `    ${chalk.cyan(summary.medium)}  Medium`,
    `    ${chalk.dim(summary.low)}  Low`,
    `    ${chalk.dim(summary.info)}  Info`,
    `    ${chalk.green(summary.clear)}  Passed checks`,
    "",
  ];
  return lines.join("\n");
}

export function formatFindings(findings, limit = 20) {
  if (findings.length === 0) {
    return chalk.green("\n  No security findings detected.\n");
  }

  // Sort by severity
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 99) - (SEVERITY_RANK[b.severity] ?? 99)
  );

  const shown = sorted.slice(0, limit);
  const lines = [chalk.bold("  Top Findings"), ""];

  for (const f of shown) {
    const sev = colorSeverity(f.severity).padEnd(20);
    const cat = chalk.dim(`[${f.category}]`);
    lines.push(`    ${sev}  ${f.title}  ${cat}`);
    if (f.file) {
      lines.push(`    ${" ".repeat(12)}  ${chalk.dim(f.file)}`);
    }
    if (f.detail) {
      lines.push(`    ${" ".repeat(12)}  ${chalk.dim(f.detail)}`);
    }
    lines.push("");
  }

  if (findings.length > limit) {
    lines.push(chalk.dim(`    ... and ${findings.length - limit} more findings`));
    lines.push("");
  }

  return lines.join("\n");
}

export function formatProjectsTable(projects) {
  if (projects.length === 0) {
    return chalk.dim("\n  No projects found. Create one with: nettle projects create <name>\n");
  }

  const lines = [
    "",
    chalk.bold("  Projects"),
    "",
    `    ${chalk.dim("ID".padEnd(40))}  ${chalk.dim("Name".padEnd(30))}  ${chalk.dim("API Key")}`,
    `    ${chalk.dim("-".repeat(40))}  ${chalk.dim("-".repeat(30))}  ${chalk.dim("-".repeat(20))}`,
  ];

  for (const p of projects) {
    const id = (p.id || "").padEnd(40);
    const name = (p.name || "").padEnd(30);
    const key = p.apiKey ? chalk.dim(p.apiKey.slice(0, 16) + "...") : chalk.dim("n/a");
    lines.push(`    ${id}  ${name}  ${key}`);
  }

  lines.push("");
  return lines.join("\n");
}

export function formatScanHistory(scans, projectName) {
  if (scans.length === 0) {
    return chalk.dim("\n  No scan history for this project.\n");
  }

  const header = projectName ? `  Scan History: ${projectName}` : "  Scan History";
  const lines = [
    "",
    chalk.bold(header),
    "",
    `    ${chalk.dim("Date".padEnd(24))}  ${chalk.dim("Score".padEnd(8))}  ${chalk.dim("Critical".padEnd(10))}  ${chalk.dim("High".padEnd(8))}  ${chalk.dim("Medium")}`,
    `    ${chalk.dim("-".repeat(24))}  ${chalk.dim("-".repeat(8))}  ${chalk.dim("-".repeat(10))}  ${chalk.dim("-".repeat(8))}  ${chalk.dim("-".repeat(8))}`,
  ];

  for (const s of scans) {
    const date = (s.scannedAt || "").slice(0, 19).replace("T", " ").padEnd(24);

    let scoreStr;
    if (s.score >= 80) scoreStr = chalk.green.bold(String(s.score).padEnd(8));
    else if (s.score >= 60) scoreStr = chalk.yellow.bold(String(s.score).padEnd(8));
    else scoreStr = chalk.red.bold(String(s.score).padEnd(8));

    const crit = (s.criticalCount != null ? String(s.criticalCount) : String(s.summary?.critical ?? 0)).padEnd(10);
    const high = (s.cautionCount != null ? String(s.cautionCount) : String(s.summary?.high ?? 0)).padEnd(8);
    const med = String(s.summary?.medium ?? 0).padEnd(8);
    lines.push(`    ${date}  ${scoreStr}  ${chalk.red(crit)}  ${chalk.yellow(high)}  ${chalk.cyan(med)}`);
  }

  lines.push("");
  return lines.join("\n");
}

export function meetsThreshold(summary, threshold) {
  const levels = ["critical", "high", "medium", "low"];
  const idx = levels.indexOf(threshold);
  if (idx < 0) return false;
  for (let i = 0; i <= idx; i++) {
    if (summary[levels[i]] > 0) return true;
  }
  return false;
}
