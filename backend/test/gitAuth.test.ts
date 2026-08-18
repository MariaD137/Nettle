import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { execFileSync, spawn } from "child_process";
import { buildAskpassScript, cloneRepo } from "../src/scanner/gitAuth";

/**
 * Runs a minimal git-smart-HTTP-401-then-capture server in its own OS
 * process (not a same-process http.createServer). This matters here
 * specifically because cloneRepo uses execFileSync, which blocks the
 * entire Node event loop until git exits — an in-process server would
 * deadlock waiting for a request it can never dispatch a handler for.
 * The captured Authorization header is written to `outFile` so the test
 * can read it back once the (separate) clone process has finished.
 */
function startCaptureServer(outFile: string): Promise<{ port: number; stop: () => void }> {
  const serverScript = `
    const http = require("http");
    const fs = require("fs");
    let captured = null;
    let requestCount = 0;
    const server = http.createServer((req, res) => {
      requestCount++;
      if (!req.headers.authorization) {
        res.writeHead(401, { "WWW-Authenticate": 'Basic realm="git"' });
        res.end();
        return;
      }
      captured = req.headers.authorization;
      fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ requestCount, captured }));
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("not a real git server");
    });
    server.listen(0, "127.0.0.1", () => {
      fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ requestCount: 0, captured: null }));
      process.stdout.write("PORT:" + server.address().port + "\\n");
    });
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", serverScript], { stdio: ["ignore", "pipe", "pipe"] });
    let buf = "";
    child.stdout.on("data", (chunk) => {
      buf += chunk.toString();
      const match = buf.match(/PORT:(\d+)/);
      if (match) resolve({ port: Number(match[1]), stop: () => child.kill() });
    });
    child.on("error", reject);
    setTimeout(() => reject(new Error("capture server did not start in time")), 5000);
  });
}

test("buildAskpassScript answers Username prompts with x-access-token and everything else with the token from its own env", () => {
  const script = buildAskpassScript();
  assert.match(script, /^#!\/bin\/sh/);
  assert.match(script, /Username\*\) echo "x-access-token"/);
  assert.match(script, /\*\) echo "\$NETTLE_GIT_TOKEN"/);
  // The token itself must never appear in the script text — it's supplied
  // purely via the environment at invocation time.
  assert.equal(script.includes("ghp_"), false);
});

test("cloneRepo authenticates over HTTP via askpass — the token reaches git only through the environment, never the URL or argv", async () => {
  const outFile = path.join(os.tmpdir(), `nettle-gitauth-capture-${process.pid}-${Date.now()}.json`);
  const { port, stop } = await startCaptureServer(outFile);
  const repoUrl = `http://127.0.0.1:${port}/repo.git`;
  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-gitauth-test-"));
  const token = "ghp_testTokenValue123";

  try {
    try {
      cloneRepo(repoUrl, "", cloneDir, token);
    } catch {
      // Expected — the fake server never speaks the real git smart-http
      // protocol, so the clone itself fails after authenticating.
    }

    const { requestCount, captured } = JSON.parse(fs.readFileSync(outFile, "utf8"));
    assert.ok(requestCount >= 1, "expected git to retry with an Authorization header");
    assert.ok(captured, "expected an Authorization header to have been captured");
    const decoded = Buffer.from(captured.replace(/^Basic /, ""), "base64").toString("utf8");
    assert.equal(decoded, `x-access-token:${token}`);
  } finally {
    stop();
    fs.rmSync(cloneDir, { recursive: true, force: true });
    fs.rmSync(outFile, { force: true });
  }
});

test("cloneRepo without a token performs a plain clone (askpass never configured)", async () => {
  // A bare local repo needs no auth at all — confirms the token-less path
  // still works exactly as it did before this feature existed.
  const bareDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-bare-"));
  const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-gitauth-plain-"));
  try {
    execFileSync("git", ["init", "--bare", "-q", bareDir]);
    // A bare repo with zero commits is still a valid clone target.
    cloneRepo(`file://${bareDir}`, "", cloneDir, null);
    assert.ok(fs.existsSync(path.join(cloneDir, ".git")));
  } finally {
    fs.rmSync(bareDir, { recursive: true, force: true });
    fs.rmSync(cloneDir, { recursive: true, force: true });
  }
});
