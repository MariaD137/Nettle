import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import fs from "fs";
import os from "os";
import path from "path";
import { spawn } from "child_process";
import { authRouter } from "../src/routes/auth.routes";
import { scansRouter } from "../src/routes/scans.routes";
import { projectsRouter } from "../src/routes/projects.routes";
import { getUserByEmail, setSubscriptionStatus } from "../src/auth/users";

// Real end-to-end coverage for the cli/ package: spawns the actual CLI
// binary as a child process against a real, ephemeral backend server (no
// mocking of the HTTP layer on either side) and asserts on real stdout,
// real exit codes, and a real ~/.nettle/config.json written to an isolated
// temp HOME.

const CLI_BIN = path.join(__dirname, "..", "..", "cli", "bin", "nettle.js");
const FLAWED_APP = path.join(__dirname, "fixtures", "sample-app");
const CLEAN_APP = path.join(__dirname, "fixtures", "clean-app");

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  app.use(scansRouter);
  app.use(projectsRouter);
  return app;
}

// Every CLI invocation gets its own isolated HOME so ~/.nettle/config.json
// never touches the real filesystem or leaks a token between tests.
function isolatedHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nettle-cli-home-"));
}

// Spawned asynchronously (not execFileSync/spawnSync) on purpose: the
// backend server these tests exercise runs in-process, in this same test
// runner. A *synchronous* child-process call would block this process's
// event loop for its entire duration — including the HTTP server the CLI
// child needs to talk to — deadlocking the moment the CLI tries to reach
// it. Async spawn keeps this process's event loop free to actually serve
// that request while we await the child's completion.
function runCli(args: string[], opts: { home: string; input?: string }): Promise<{ stdout: string; stderr: string; status: number }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI_BIN, ...args], {
      env: { ...process.env, HOME: opts.home, NO_COLOR: "1" },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => resolve({ stdout, stderr, status: code ?? 1 }));
    if (opts.input !== undefined) child.stdin.write(opts.input);
    child.stdin.end();
  });
}

test("nettle signup registers a real account and persists a token to ~/.nettle/config.json", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const home = isolatedHome();
  try {
    const email = `cli-signup-${Date.now()}@example.com`;
    const { stdout, status } = await runCli(["signup", "--api-url", base], { home, input: `${email}\ncorrect horse battery staple\n` });

    assert.equal(status, 0);
    assert.match(stdout, /Account created/);
    assert.match(stdout, new RegExp(email.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));

    const config = JSON.parse(fs.readFileSync(path.join(home, ".nettle", "config.json"), "utf8"));
    assert.ok(config.token, "a real session token should have been written");
  } finally {
    server.close();
  }
});

test("nettle scan runs a real scan (no login required) and --json prints a real parseable report", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const home = isolatedHome();
  try {
    const { stdout, status } = await runCli(["scan", FLAWED_APP, "--api-url", base, "--json"], { home });

    assert.equal(status, 0, "no --fail-on was passed, so a clean or flawed scan both exit 0");
    const report = JSON.parse(stdout);
    assert.ok(typeof report.score === "number");
    assert.ok(Array.isArray(report.findings));
    assert.ok(report.findings.length > 0, "the flawed fixture should produce real findings");
    assert.ok(report.summary.critical > 0, "the flawed fixture is known to contain critical findings (hardcoded secrets)");
  } finally {
    server.close();
  }
});

test("nettle scan --fail-on critical exits non-zero against the flawed fixture and zero against the clean one", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const flawed = await runCli(["scan", FLAWED_APP, "--api-url", base, "--json", "--fail-on", "critical"], { home: isolatedHome() });
    assert.equal(flawed.status, 1);
    assert.ok(JSON.parse(flawed.stdout).summary.critical > 0);

    const clean = await runCli(["scan", CLEAN_APP, "--api-url", base, "--json", "--fail-on", "critical"], { home: isolatedHome() });
    assert.equal(clean.status, 0);
    assert.equal(JSON.parse(clean.stdout).summary.critical, 0);
  } finally {
    server.close();
  }
});

test("nettle scan --api-key associates the scan with a real project, visible via nettle history", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  const home = isolatedHome();
  try {
    const email = `cli-project-${Date.now()}@example.com`;
    const password = "correct horse battery staple";
    await runCli(["signup", "--api-url", base], { home, input: `${email}\n${password}\n` });
    // Project creation is paywalled — a freshly signed-up account has no
    // subscription yet, same as in real life. Granting one here isn't a
    // CLI concern (that's Stripe's job in production); it's just what
    // this test needs to get past the same gate a real paying user would.
    await setSubscriptionStatus((await getUserByEmail(email))!.id, "tier1", "active");

    const created = await runCli(["projects", "create", "Real CLI Project", "--api-url", base], { home });
    assert.equal(created.status, 0);
    const idMatch = created.stdout.match(/ID:\s+(\S+)/);
    const keyMatch = created.stdout.match(/API Key:\s+(\S+)/);
    assert.ok(idMatch && keyMatch, "project creation should print a real ID and API key");
    const [, projectId] = idMatch!;
    const [, apiKey] = keyMatch!;

    const scanResult = await runCli(["scan", CLEAN_APP, "--api-url", base, "--api-key", apiKey, "--json"], { home });
    assert.equal(scanResult.status, 0);

    const history = await runCli(["history", projectId, "--api-url", base], { home });
    assert.equal(history.status, 0);
    assert.match(history.stdout, /Scan History/);
    assert.doesNotMatch(history.stdout, /No scan history/);
  } finally {
    server.close();
  }
});

test("nettle whoami fails clearly when not logged in, without a stack trace", async () => {
  const home = isolatedHome();
  const { stderr, status } = await runCli(["whoami"], { home });
  assert.equal(status, 1);
  assert.match(stderr, /not logged in/i);
  assert.doesNotMatch(stderr, /at Object\.<anonymous>/, "should be a clean error message, not a raw stack trace");
});
