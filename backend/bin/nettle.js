#!/usr/bin/env node
const path = require("path");
const fs = require("fs");
const { runScan } = require("../dist/scanner");

const CONFIG_PATH = path.join(require("os").homedir(), ".nettle.json");

function readConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")); }
  catch { return {}; }
}

function writeConfig(config) {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
}

const [,, command, ...args] = process.argv;

function printUsage() {
  console.log(`
Nettle CLI — scan AI-built apps for launch-readiness gaps

Commands:
  nettle scan [path]           Scan a local directory (default: current directory)
  nettle login                 Authenticate with your Nettle account
  nettle logout                Clear stored credentials
  nettle projects              List your projects
  nettle status [project-id]   Show project status and latest scan summary
  nettle help                  Show this help message
`);
}

async function login() {
  const config = readConfig();
  const endpoint = config.endpoint || "http://localhost:8080";

  const readline = require("readline");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q) => new Promise((resolve) => rl.question(q, resolve));

  const email = await ask("Email: ");
  const password = await ask("Password: ");
  rl.close();

  try {
    const res = await fetch(`${endpoint}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      console.error(`Login failed: ${data.error}`);
      process.exit(1);
    }
    writeConfig({ ...config, token: data.token, email: data.user.email, endpoint });
    console.log(`Logged in as ${data.user.email}`);
  } catch (err) {
    console.error(`Could not reach ${endpoint}: ${err.message}`);
    process.exit(1);
  }
}

async function logout() {
  const config = readConfig();
  delete config.token;
  delete config.email;
  writeConfig(config);
  console.log("Logged out");
}

async function listProjects() {
  const config = readConfig();
  if (!config.token) {
    console.error("Not logged in. Run: nettle login");
    process.exit(1);
  }
  const endpoint = config.endpoint || "http://localhost:8080";

  try {
    const res = await fetch(`${endpoint}/api/projects`, {
      headers: { Authorization: `Bearer ${config.token}` },
    });
    const data = await res.json();
    if (!res.ok) {
      console.error(`Failed: ${data.error}`);
      process.exit(1);
    }
    if (data.projects.length === 0) {
      console.log("No projects yet. Create one in the dashboard.");
      return;
    }
    console.log("\nYour projects:\n");
    for (const p of data.projects) {
      console.log(`  ${p.name}`);
      console.log(`    ID:  ${p.id}`);
      console.log(`    Key: ${p.apiKey}`);
      console.log();
    }
  } catch (err) {
    console.error(`Could not reach ${endpoint}: ${err.message}`);
    process.exit(1);
  }
}

async function status(projectId) {
  const config = readConfig();
  if (!config.token) {
    console.error("Not logged in. Run: nettle login");
    process.exit(1);
  }
  const endpoint = config.endpoint || "http://localhost:8080";

  if (!projectId) {
    console.error("Usage: nettle status <project-id>");
    process.exit(1);
  }

  try {
    const res = await fetch(`${endpoint}/api/projects/${projectId}`, {
      headers: { Authorization: `Bearer ${config.token}` },
    });
    const data = await res.json();
    if (!res.ok) {
      console.error(`Failed: ${data.error}`);
      process.exit(1);
    }

    const { project, badge, latestScan, alertCounts } = data;
    console.log(`\n${project.name}`);
    console.log(`Status: ${badge.label} (${badge.status})`);
    if (latestScan) {
      console.log(`Latest score: ${latestScan.score}/100`);
      console.log(`Last scanned: ${new Date(latestScan.scannedAt).toLocaleString()}`);
      console.log(`Critical: ${latestScan.criticalCount}  Caution: ${latestScan.cautionCount}`);
    } else {
      console.log("No scans yet");
    }
    console.log(`Alerts: ${alertCounts.new} new, ${alertCounts.acknowledged} acknowledged, ${alertCounts.resolved} resolved`);
    console.log();
  } catch (err) {
    console.error(`Could not reach ${endpoint}: ${err.message}`);
    process.exit(1);
  }
}

function scan(target) {
  const report = runScan(target || ".");

  console.log(`\nNettle Readiness Scan — ${report.target}`);
  console.log(`Score: ${report.score}/100`);
  console.log(`Critical: ${report.summary.critical}   High: ${report.summary.high}   Medium: ${report.summary.medium}   Low: ${report.summary.low}   Clear: ${report.summary.clear}\n`);
  for (const f of report.findings) {
    console.log(`[${f.severity.toUpperCase()}] ${f.category} — ${f.title}${f.file ? " (" + f.file + ")" : ""}`);
    if (f.remediation) {
      console.log(`         Fix: ${f.remediation}`);
    }
  }

  const outPath = path.join(process.cwd(), "nettle-report.json");
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote ${outPath}`);

  process.exit(report.summary.critical > 0 ? 1 : 0);
}

(async () => {
  switch (command) {
    case "scan":
      scan(args[0]);
      break;
    case "login":
      await login();
      break;
    case "logout":
      await logout();
      break;
    case "projects":
      await listProjects();
      break;
    case "status":
      await status(args[0]);
      break;
    case "help":
    case "--help":
    case "-h":
      printUsage();
      break;
    default:
      if (command) console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(command ? 1 : 0);
  }
})();
