import { test, before } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";
import type { Server } from "http";
import { AddressInfo } from "net";
import { scansRouter } from "../src/routes/scans.routes";
import { createUser, setSubscriptionStatus } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";

// Proves hydration is actually wired into the live API response, not just
// present as tested-but-unreachable infrastructure — the same gap this
// session's earlier work found and fixed for authAnalysis.ts and the
// three-state model itself.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

let zipPath: string;
before(() => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-hydration-"));
  zipPath = path.join(dir, "app.zip");
  execFileSync("zip", ["-q", "-r", zipPath, "sample-app"], {
    cwd: path.join(__dirname, "fixtures"),
  });
});

test("POST /api/scans returns hydrated recommendations for migrated controls", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  // A paid (build) session, so the response is the full, untrimmed report —
  // this test is about hydration across multiple controls, not about the
  // preview's severity-ranked top-3 truncation (that's the next test).
  const user = await createUser("hydration-full@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");
  const token = await createSession(user.id);

  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  const res = await fetch(`${base}/api/scans`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  assert.equal(res.status, 200);
  const body = (await res.json()) as any;

  assert.equal(body.access.tier, "full");
  assert.equal(body.detectedTechnology, "express");

  const authFail = body.checkResults.find((r: any) => r.controlKey === "AUTH-001" && r.status === "FAIL");
  assert.ok(authFail, "fixture's unprotected route should produce an AUTH-001 FAIL");
  assert.ok(authFail.recommendation, "a FAIL with a controlKey must be hydrated with a recommendation");
  assert.equal(authFail.recommendation.technologyMatched, "express");
  assert.match(authFail.recommendation.quickFix, /verifyJWT/);
  assert.ok(authFail.recommendation.verificationMethod);
  assert.ok(authFail.recommendation.references.length > 0);
  assert.ok(authFail.releaseImpact, "a hydrated FAIL must carry a release impact");

  const secretFail = body.checkResults.find((r: any) => r.controlKey === "SECRET-001" && r.status === "FAIL");
  assert.ok(secretFail, "fixture's hardcoded keys should produce a SECRET-001 FAIL");
  assert.ok(secretFail.recommendation);
  assert.equal(secretFail.releaseImpact, "BLOCK_RELEASE");

  // A check not yet migrated onto the control library must come back with
  // recommendation: null, never a fabricated one. This fixture produced one
  // from every scanner module up through osvVulnerabilities.ts's migration;
  // as each remaining legacy module (codeQuality.ts, frontendSecurity.ts)
  // gets migrated in turn, this fixture will eventually stop producing any
  // unmigrated FAIL at all — that's expected, not a regression, so this
  // assertion only checks the invariant when the condition still applies.
  // The invariant itself is covered unconditionally by "hydration never
  // fabricates a recommendation for a result with no controlKey" in
  // controls-engine.test.ts.
  const unmigrated = body.checkResults.find((r: any) => r.status === "FAIL" && !r.controlKey);
  if (unmigrated) {
    assert.equal(unmigrated.recommendation, null);
  }
});

test("a free-tier preview still gets hydrated recommendations on the few findings it does show", async (t) => {
  const app = express();
  app.use(express.json());
  app.use(scansRouter);
  const { server, base } = await listen(app);
  t.after(() => server.close());

  const form = new FormData();
  form.append("codebase", new Blob([fs.readFileSync(zipPath)]), "app.zip");
  // No Authorization header — anonymous, so the response is the free-tier preview.
  const res = await fetch(`${base}/api/scans`, { method: "POST", body: form });
  const body = (await res.json()) as any;

  assert.equal(body.access.tier, "preview");
  const visibleFails = body.checkResults.filter((r: any) => r.status === "FAIL");
  assert.ok(visibleFails.length > 0);
  for (const f of visibleFails) {
    // Whatever detail a preview does show must be the real thing, not a
    // half-hydrated stub — matches the existing "withholds detail rather
    // than blanking it" rule for findings[] in billing/scanAccess.ts.
    if (f.controlKey) assert.ok(f.recommendation, `${f.controlKey} FAIL shown in preview must be hydrated`);
  }
});
