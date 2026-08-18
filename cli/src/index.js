import { Command } from "commander";
import chalk from "chalk";
import readline from "readline";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { request } from "./api.js";
import { getToken, setToken, removeToken, getApiUrl } from "./config.js";
import {
  formatScore,
  formatSummary,
  formatFindings,
  formatProjectsTable,
  formatScanHistory,
  formatAccessNotice,
  meetsThreshold,
} from "./format.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// A prompter that asks a whole sequence of questions (e.g. email then
// password) through one readline.Interface, chaining each rl.question()
// call directly from the previous one's callback rather than `await`ing
// them one at a time from the caller.
//
// That chaining is load-bearing, not style: when stdin isn't a real TTY
// (piped input — scripted use, CI, or just this CLI's own tests), the
// whole answer set is often already buffered and the input stream can hit
// 'end' the moment nothing is actively reading from it. `await`ing between
// two separate rl.question() calls opens a microtask gap where exactly
// that happens — readline reacts to the stream ending by closing the
// interface, and the second question silently never gets asked (the
// process just exits with whatever answers it already had). Asking every
// question in one unbroken synchronous callback chain closes that gap.
function createPrompter() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  function askSequence(questions) {
    return new Promise((resolve) => {
      const answers = [];
      function next(i) {
        if (i >= questions.length) return resolve(answers);
        const { text, hidden } = questions[i];

        if (hidden) {
          // Mute output for password entry
          const origWrite = process.stdout.write.bind(process.stdout);
          process.stdout.write = (chunk, encoding, cb) => {
            // Only suppress characters typed after the question has been printed
            if (typeof chunk === "string" && !chunk.includes(text)) {
              // Write nothing — hide the typed characters
              if (typeof encoding === "function") {
                encoding();
                return true;
              }
              if (cb) cb();
              return true;
            }
            return origWrite(chunk, encoding, cb);
          };

          rl.question(text, (answer) => {
            process.stdout.write = origWrite;
            console.log(); // newline after hidden input
            answers.push(answer);
            next(i + 1);
          });
        } else {
          rl.question(text, (answer) => {
            answers.push(answer);
            next(i + 1);
          });
        }
      }
      next(0);
    });
  }

  return { askSequence, close: () => rl.close() };
}

function die(message) {
  console.error(chalk.red(`Error: ${message}`));
  process.exit(1);
}

function requireLoggedIn() {
  const token = getToken();
  if (!token) {
    die("You are not logged in. Run `nettle login` first.");
  }
  return token;
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

export function run() {
  const program = new Command();

  program
    .name("nettle")
    .description("Nettle — security scanner for your codebase")
    .version("0.1.0")
    .option("--api-url <url>", "Override the Nettle API base URL");

  // -----------------------------------------------------------------------
  // nettle login
  // -----------------------------------------------------------------------
  program
    .command("login")
    .description("Log in to your Nettle account")
    .action(async (_, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      const prompter = createPrompter();
      const [email, password] = await prompter.askSequence([
        { text: "Email: " },
        { text: "Password: ", hidden: true },
      ]);
      prompter.close();

      if (!email || !password) die("Email and password are required.");

      try {
        const { data } = await request("POST", "/api/auth/login", {
          body: { email, password },
          apiUrl,
        });
        setToken(data.token);
        console.log(chalk.green(`\nLogged in as ${data.user.email}`));
      } catch (err) {
        die(err.message);
      }
    });

  // -----------------------------------------------------------------------
  // nettle signup
  // -----------------------------------------------------------------------
  program
    .command("signup")
    .description("Create a new Nettle account")
    .action(async (_, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      const prompter = createPrompter();
      const [email, password] = await prompter.askSequence([
        { text: "Email: " },
        { text: "Password: ", hidden: true },
      ]);
      prompter.close();

      if (!email || !password) die("Email and password are required.");
      if (password.length < 8) die("Password must be at least 8 characters.");

      try {
        const { data } = await request("POST", "/api/auth/signup", {
          body: { email, password },
          apiUrl,
        });
        setToken(data.token);
        console.log(chalk.green(`\nAccount created. Logged in as ${data.user.email}`));
      } catch (err) {
        die(err.message);
      }
    });

  // -----------------------------------------------------------------------
  // nettle logout
  // -----------------------------------------------------------------------
  program
    .command("logout")
    .description("Log out of your Nettle account")
    .action(async (_, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        await request("POST", "/api/auth/logout", { apiUrl });
      } catch {
        // Ignore errors — we remove the token locally regardless
      }
      removeToken();
      console.log(chalk.green("Logged out."));
    });

  // -----------------------------------------------------------------------
  // nettle whoami
  // -----------------------------------------------------------------------
  program
    .command("whoami")
    .description("Show the current logged-in user")
    .action(async (_, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        const { data } = await request("GET", "/api/auth/me", { apiUrl });
        const user = data.user;
        console.log("");
        console.log(`  ${chalk.bold("Email:")}  ${user.email}`);
        if (user.plan) {
          console.log(`  ${chalk.bold("Plan:")}   ${user.plan}`);
        }
        console.log("");
      } catch (err) {
        die(err.message);
      }
    });

  // -----------------------------------------------------------------------
  // nettle projects [list]
  // -----------------------------------------------------------------------
  const projectsCmd = program
    .command("projects")
    .description("List your projects")
    .action(async (_, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        const { data } = await request("GET", "/api/projects", { apiUrl });
        console.log(formatProjectsTable(data.projects));
      } catch (err) {
        die(err.message);
      }
    });

  // -----------------------------------------------------------------------
  // nettle projects create <name>
  // -----------------------------------------------------------------------
  projectsCmd
    .command("create <name>")
    .description("Create a new project")
    .action(async (name, _, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        const { data } = await request("POST", "/api/projects", {
          body: { name },
          apiUrl,
        });
        console.log(chalk.green(`\nProject created: ${data.name}`));
        console.log(chalk.dim(`  ID:      ${data.id}`));
        if (data.apiKey) {
          console.log(chalk.dim(`  API Key: ${data.apiKey}`));
        }
        console.log("");
      } catch (err) {
        die(err.message);
      }
    });

  // -----------------------------------------------------------------------
  // nettle scan [path]
  // -----------------------------------------------------------------------
  program
    .command("scan [path]")
    .description("Scan a directory for security issues")
    .option("--api-key <key>", "API key to associate scan with a project")
    .option("--json", "Output raw JSON report")
    .option(
      "--fail-on <severity>",
      "Exit with code 1 if findings at this severity or above (critical, high, medium, low)"
    )
    .action(async (targetPath, opts, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      const scanPath = path.resolve(targetPath || ".");

      if (!fs.existsSync(scanPath)) {
        die(`Path does not exist: ${scanPath}`);
      }

      const stat = fs.statSync(scanPath);
      if (!stat.isDirectory()) {
        die(`Path is not a directory: ${scanPath}`);
      }

      // Create a temporary zip file
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cli-"));
      const zipFile = path.join(tmpDir, "codebase.zip");

      try {
        // stderr, not stdout: --json's whole point is a clean, parseable
        // report on stdout for scripts/CI to consume — a progress line
        // mixed into stdout would corrupt that.
        console.error(chalk.dim(`\nScanning ${scanPath} ...\n`));

        // Zip the directory, excluding common non-source directories
        execFileSync("zip", [
          "-r", "-q",
          zipFile,
          ".",
          "-x",
          "node_modules/*",
          ".git/*",
          "dist/*",
          "build/*",
          ".next/*",
          "__pycache__/*",
          "*.pyc",
          ".venv/*",
          "vendor/*",
        ], {
          cwd: scanPath,
          stdio: "pipe",
        });

        // Build multipart form data using a Blob-based approach
        const zipBuffer = fs.readFileSync(zipFile);
        const formData = new FormData();
        formData.append(
          "codebase",
          new Blob([zipBuffer], { type: "application/zip" }),
          "codebase.zip"
        );

        const extraHeaders = {};
        if (opts.apiKey) {
          extraHeaders["X-Nettle-Api-Key"] = opts.apiKey;
        }

        const { data: report } = await request("POST", "/api/scans", {
          body: formData,
          apiUrl,
          headers: extraHeaders,
        });

        // JSON output mode
        if (opts.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          // Formatted output
          console.log(formatScore(report.score));
          console.log(formatSummary(report.summary));
          console.log(formatFindings(report.findings));
          console.log(formatAccessNotice(report.access));
        }

        // CI exit code based on --fail-on threshold
        if (opts.failOn) {
          const threshold = opts.failOn.toLowerCase();
          if (!["critical", "high", "medium", "low"].includes(threshold)) {
            die(`Invalid --fail-on value: ${opts.failOn}. Use: critical, high, medium, low`);
          }
          if (meetsThreshold(report.summary, threshold)) {
            console.error(
              chalk.red.bold(`\nFailed: findings at ${threshold} severity or above detected.\n`)
            );
            process.exit(1);
          }
        }
      } catch (err) {
        if (err.message && err.status) {
          die(err.message);
        }
        // Re-throw non-API errors (zip failure, etc.)
        die(`Scan failed: ${err.message}`);
      } finally {
        // Clean up temp files
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

  // -----------------------------------------------------------------------
  // nettle scan-repo <url>
  // -----------------------------------------------------------------------
  program
    .command("scan-repo <url>")
    .description("Scan a public Git repository by URL")
    .option("--branch <branch>", "Branch to scan (defaults to the repo's default branch)")
    .option("--api-key <key>", "API key to associate scan with a project")
    .option("--json", "Output raw JSON report")
    .option(
      "--fail-on <severity>",
      "Exit with code 1 if findings at this severity or above (critical, high, medium, low)"
    )
    .action(async (url, opts, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        // stderr, not stdout — see the same note in `scan` above.
        console.error(chalk.dim(`\nCloning and scanning ${url}${opts.branch ? ` (branch: ${opts.branch})` : ""} ...\n`));

        const { data: report } = await request("POST", "/api/scans/repo", {
          body: { repoUrl: url, branch: opts.branch, apiKey: opts.apiKey },
          apiUrl,
        });

        if (opts.json) {
          console.log(JSON.stringify(report, null, 2));
        } else {
          console.log(formatScore(report.score));
          console.log(formatSummary(report.summary));
          console.log(formatFindings(report.findings));
          console.log(formatAccessNotice(report.access));
        }

        if (opts.failOn) {
          const threshold = opts.failOn.toLowerCase();
          if (!["critical", "high", "medium", "low"].includes(threshold)) {
            die(`Invalid --fail-on value: ${opts.failOn}. Use: critical, high, medium, low`);
          }
          if (meetsThreshold(report.summary, threshold)) {
            console.error(
              chalk.red.bold(`\nFailed: findings at ${threshold} severity or above detected.\n`)
            );
            process.exit(1);
          }
        }
      } catch (err) {
        die(err.message || `Scan failed: ${err}`);
      }
    });

  // -----------------------------------------------------------------------
  // nettle history <project-id>
  // -----------------------------------------------------------------------
  program
    .command("history <project-id>")
    .description("Show scan history for a project")
    .action(async (projectId, _, cmd) => {
      const apiUrl = cmd.optsWithGlobals().apiUrl;
      requireLoggedIn();

      try {
        const { data } = await request("GET", `/api/projects/${projectId}/scans`, { apiUrl });
        console.log(formatScanHistory(data.scans, data.project?.name));
      } catch (err) {
        die(err.message);
      }
    });

  program.parse();
}
