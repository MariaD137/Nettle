import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import cors from "cors";
import type { Server } from "http";
import { AddressInfo } from "net";
import { getAllowedOrigins } from "../src/corsConfig";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("getAllowedOrigins is empty with nothing configured (local dev default)", () => {
  const savedCors = process.env.CORS_ALLOWED_ORIGINS;
  const savedFrontend = process.env.FRONTEND_URL;
  delete process.env.CORS_ALLOWED_ORIGINS;
  delete process.env.FRONTEND_URL;
  try {
    assert.deepEqual(getAllowedOrigins(), []);
  } finally {
    process.env.CORS_ALLOWED_ORIGINS = savedCors;
    process.env.FRONTEND_URL = savedFrontend;
  }
});

test("getAllowedOrigins falls back to FRONTEND_URL when CORS_ALLOWED_ORIGINS is unset", () => {
  const savedCors = process.env.CORS_ALLOWED_ORIGINS;
  const savedFrontend = process.env.FRONTEND_URL;
  delete process.env.CORS_ALLOWED_ORIGINS;
  process.env.FRONTEND_URL = "https://app.nettle.example";
  try {
    assert.deepEqual(getAllowedOrigins(), ["https://app.nettle.example"]);
  } finally {
    process.env.CORS_ALLOWED_ORIGINS = savedCors;
    process.env.FRONTEND_URL = savedFrontend;
  }
});

test("getAllowedOrigins parses a comma-separated CORS_ALLOWED_ORIGINS override, trimmed", () => {
  const savedCors = process.env.CORS_ALLOWED_ORIGINS;
  process.env.CORS_ALLOWED_ORIGINS = "https://app.nettle.example, https://staging.nettle.example";
  try {
    assert.deepEqual(getAllowedOrigins(), ["https://app.nettle.example", "https://staging.nettle.example"]);
  } finally {
    process.env.CORS_ALLOWED_ORIGINS = savedCors;
  }
});

test("with a real allowed-origins list, a real cross-origin request from an allowed origin gets a matching CORS header, and a disallowed one doesn't", async () => {
  const app = express();
  app.use(cors({ origin: ["https://app.nettle.example"] }));
  app.get("/api/ping", (_req, res) => res.json({ ok: true }));
  const { server, base } = await listen(app);

  try {
    const allowed = await fetch(`${base}/api/ping`, {
      headers: { Origin: "https://app.nettle.example" },
    });
    assert.equal(allowed.headers.get("access-control-allow-origin"), "https://app.nettle.example");

    const disallowed = await fetch(`${base}/api/ping`, {
      headers: { Origin: "https://evil.example" },
    });
    // The cors middleware still lets the request through (CORS is
    // enforced by the browser reading the response header, not by the
    // server blocking the request) but must not echo back a mismatched
    // origin as allowed.
    assert.notEqual(disallowed.headers.get("access-control-allow-origin"), "https://evil.example");
  } finally {
    server.close();
  }
});
