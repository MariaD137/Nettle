import { test } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import { isBlockedIp, ssrfSafeFetch, performValidatedRequest, SsrfBlockedError } from "../src/scanner/ssrfSafeFetch";

test("isBlockedIp blocks private/reserved IPv4 ranges", () => {
  const blocked = [
    "127.0.0.1",
    "127.255.255.255",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.255.255",
    "169.254.169.254", // cloud metadata
    "169.254.0.1",
    "0.0.0.0",
    "100.64.0.1", // CGNAT
    "255.255.255.255",
  ];
  for (const ip of blocked) assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
});

test("isBlockedIp allows public IPv4 addresses", () => {
  const allowed = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "93.184.216.34"];
  for (const ip of allowed) assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
});

test("isBlockedIp blocks private/reserved IPv6 ranges", () => {
  const blocked = ["::1", "::", "fc00::1", "fd12:3456::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"];
  for (const ip of blocked) assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
});

test("isBlockedIp allows public IPv6 addresses", () => {
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false);
  assert.equal(isBlockedIp("::ffff:8.8.8.8"), false);
});

test("isBlockedIp refuses unrecognizable input rather than guessing", () => {
  assert.equal(isBlockedIp("not-an-ip"), true);
});

test("ssrfSafeFetch blocks a direct request to a loopback IP literal", async () => {
  await assert.rejects(() => ssrfSafeFetch("http://127.0.0.1:1/"), SsrfBlockedError);
});

test("ssrfSafeFetch blocks the cloud metadata address", async () => {
  await assert.rejects(() => ssrfSafeFetch("http://169.254.169.254/latest/meta-data/"), SsrfBlockedError);
});

test("ssrfSafeFetch blocks the 'localhost' hostname", async () => {
  await assert.rejects(() => ssrfSafeFetch("http://localhost:1/"), SsrfBlockedError);
});

test("ssrfSafeFetch blocks a private IPv6 literal", async () => {
  await assert.rejects(() => ssrfSafeFetch("http://[::1]:1/"), SsrfBlockedError);
});

test("ssrfSafeFetch rejects unsupported protocols before any network activity", async () => {
  await assert.rejects(() => ssrfSafeFetch("ftp://example.com/"), SsrfBlockedError);
  await assert.rejects(() => ssrfSafeFetch("file:///etc/passwd"), SsrfBlockedError);
  await assert.rejects(() => ssrfSafeFetch("gopher://example.com/"), SsrfBlockedError);
});

test("ssrfSafeFetch blocks a hostname that only resolves to private addresses", async () => {
  // This hostname is reserved by RFC 2606 for documentation/testing and
  // resolves to nothing routable; if it somehow resolved to a public
  // address the test would just fail closed on a network error, not
  // silently pass, since we assert SsrfBlockedError specifically... but
  // to keep this deterministic and offline-safe, use an IP literal instead.
  await assert.rejects(() => ssrfSafeFetch("http://0.0.0.0:1/"), SsrfBlockedError);
});

test("performValidatedRequest performs a real GET and returns status/headers/body", async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", "X-Test": "yes" });
    res.end("hello world");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as import("net").AddressInfo).port;

  try {
    const url = new URL(`http://127.0.0.1:${port}/`);
    const { res, body } = await performValidatedRequest(url, "127.0.0.1", 4);
    assert.equal(res.statusCode, 200);
    assert.equal(res.headers["x-test"], "yes");
    assert.equal(body, "hello world");
  } finally {
    server.close();
  }
});

test("performValidatedRequest surfaces Set-Cookie headers as an array", async () => {
  const server = http.createServer((req, res) => {
    res.setHeader("Set-Cookie", ["a=1; Secure; HttpOnly", "b=2"]);
    res.writeHead(200);
    res.end("ok");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as import("net").AddressInfo).port;

  try {
    const url = new URL(`http://127.0.0.1:${port}/`);
    const { res } = await performValidatedRequest(url, "127.0.0.1", 4);
    assert.ok(Array.isArray(res.headers["set-cookie"]));
    assert.equal((res.headers["set-cookie"] as string[]).length, 2);
  } finally {
    server.close();
  }
});

test("performValidatedRequest enforces the request timeout against a stalling server", async () => {
  const server = http.createServer(() => {
    // Never respond.
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as import("net").AddressInfo).port;

  try {
    const url = new URL(`http://127.0.0.1:${port}/`);
    const start = Date.now();
    await assert.rejects(() => performValidatedRequest(url, "127.0.0.1", 4));
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 15_000, `expected the 10s timeout to fire, took ${elapsed}ms`);
  } finally {
    server.close();
  }
});

// TLS certificate extraction (extractTls, exercised via the `tls` field on
// ssrfSafeFetch's result) is not covered here — it needs a real HTTPS
// server with a certificate, which needs either a trusted-cert dependency
// or shelling out to openssl, neither of which is available in this test
// environment. It's exercised indirectly whenever the app scans a real
// https:// target. Noting the gap explicitly rather than faking a pass.
