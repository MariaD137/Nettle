import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";

/**
 * Structural regression guards for the isolation boundary described in
 * src/scanner/ISOLATION.md: the main API process must never extract or
 * scan untrusted customer input itself — that has to happen inside
 * scanner/isolatedRunner.ts's chosen backend (a worker_thread, or an
 * isolated Fargate task), not inline in a request handler. These tests
 * read source text rather than behavior on purpose — the bug class this
 * guards against (someone reintroducing a direct safeExtractZip/cloneRepo/
 * runScan call in a route handler "just this once") wouldn't necessarily
 * fail any functional test, since the scan would still produce a correct
 * report. It would just have quietly removed the isolation boundary.
 */

const SRC = path.join(__dirname, "..", "src");
function read(relPath: string): string {
  return fs.readFileSync(path.join(SRC, relPath), "utf8");
}

test("scans.routes.ts never imports the raw extraction/clone/scan primitives directly", () => {
  const source = read("routes/scans.routes.ts");
  // These are the functions that touch untrusted archive bytes or shell
  // out to git — every call site for them must live inside
  // scanner/isolatedRunner.ts's own backends (workerThreadRunner.ts /
  // fargateScanner.ts + taskEntrypoint.ts), never directly in a route.
  for (const banned of ["safeExtractZip", "cloneRepo", "resolveScanRoot"]) {
    assert.equal(source.includes(banned), false, `scans.routes.ts must not reference ${banned} directly`);
  }
  // runScan(...) (the in-process scanner entry point) must not be called
  // from this file either — only runScanIsolated should be. Guard against
  // the bare identifier `runScan(` specifically, since `runScanIsolated(`
  // legitimately appears throughout this file.
  assert.equal(/\brunScan\(/.test(source), false, "scans.routes.ts must call runScanIsolated, not runScan, directly");
  assert.equal(source.includes("runScanIsolated"), true, "scans.routes.ts should route source scans through runScanIsolated");
});

test("scans.routes.ts's upload and repo routes have no unzip/child_process/exec of their own", () => {
  const source = read("routes/scans.routes.ts");
  for (const banned of ["child_process", "execFileSync", "execSync", "spawn(", "eval("]) {
    assert.equal(source.includes(banned), false, `scans.routes.ts must not itself invoke ${banned}`);
  }
});

test("taskEntrypoint.ts (the isolated task's own code) imports nothing from db/, auth/, billing/, or integrations/", () => {
  const source = read("scanner/taskEntrypoint.ts");
  const importLines = source.match(/^import .+ from ["'][^"']+["'];?$/gm) ?? [];
  for (const line of importLines) {
    for (const forbidden of ["../db", "../auth", "../billing", "../integrations"]) {
      assert.equal(
        line.includes(forbidden),
        false,
        `taskEntrypoint.ts must never import from ${forbidden} (it has no database/session/billing credentials) — found: ${line}`
      );
    }
  }
});

test("jobs/fargateScanner.ts's task role env never includes an application secret or database credential", () => {
  const source = read("jobs/fargateScanner.ts");
  for (const forbidden of ["DATABASE_URL", "PGPASSWORD", "STRIPE_SECRET", "NETTLE_TOKEN_ENCRYPTION_KEY", "CRON_SECRET"]) {
    assert.equal(source.includes(forbidden), false, `fargateScanner.ts must never pass ${forbidden} into the scan task's environment`);
  }
});

test("workerThreadRunner.ts and isolatedRunner.ts do not import db/, auth/, or billing/ either", () => {
  for (const file of ["scanner/workerThreadRunner.ts", "scanner/isolatedRunner.ts"]) {
    const source = read(file);
    const importLines = source.match(/^import .+ from ["'][^"']+["'];?$/gm) ?? [];
    for (const line of importLines) {
      for (const forbidden of ["../db", "../auth", "../billing"]) {
        assert.equal(line.includes(forbidden), false, `${file} should not need ${forbidden} — found: ${line}`);
      }
    }
  }
});
