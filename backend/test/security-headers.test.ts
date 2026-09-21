import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import helmet from "helmet";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import { badgeRouter } from "../src/routes/badge.routes";
import { healthRouter } from "../src/routes/health.routes";

// Nettle's own scanner (src/scanner/securityHeaders.ts) fails apps that do not
// set these. The API set none of them, so the product did not pass its own
// check. Mirrors the helmet configuration in src/index.ts.
function buildApp() {
  const app = express();
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          "default-src": ["'none'"],
          "frame-ancestors": ["'none'"],
          "base-uri": ["'none'"],
          "form-action": ["'none'"],
        },
      },
      hsts: { maxAge: 31_536_000, includeSubDomains: true, preload: false },
      referrerPolicy: { policy: "no-referrer" },
    })
  );
  app.use(express.json());
  app.use(healthRouter);
  app.use(badgeRouter);
  return app;
}

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("the API sets the security headers its own scanner checks for", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);

  assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
  assert.match(res.headers.get("strict-transport-security") ?? "", /max-age=31536000/);
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.ok(res.headers.get("x-frame-options"), "X-Frame-Options must be set");
  assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  assert.equal(res.headers.get("x-powered-by"), null, "Express version disclosure should be off");
});

test("the embeddable badge opts out of same-origin resource policy", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("badge-headers@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Badge Headers");

  const svg = await fetch(`${base}/api/projects/${project.id}/badge.svg`);
  assert.equal(svg.status, 200);
  assert.match(svg.headers.get("content-type") ?? "", /^image\/svg\+xml/);
  // Without this the badge cannot be embedded from a customer's site, which
  // is the only reason the endpoint exists.
  assert.equal(svg.headers.get("cross-origin-resource-policy"), "cross-origin");

  const json = await fetch(`${base}/api/projects/${project.id}/badge.json`);
  assert.equal(json.headers.get("cross-origin-resource-policy"), "cross-origin");
});

test("non-embeddable routes keep the restrictive resource policy", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const res = await fetch(`${base}/health`);
  assert.equal(res.headers.get("cross-origin-resource-policy"), "same-origin");
});
