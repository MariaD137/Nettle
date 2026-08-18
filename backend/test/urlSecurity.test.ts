import { test } from "node:test";
import assert from "node:assert/strict";
import http from "http";
import {
  checkTls,
  checkHttpRedirectsToHttps,
  checkSecurityHeaders,
  checkCookies,
  checkTechnologyDisclosure,
  checkExposedPaths,
  scanUrl,
  UrlScanUnreachableError,
} from "../src/scanner/urlSecurity";
import { SsrfBlockedError, performValidatedRequest, type SafeFetchResult } from "../src/scanner/ssrfSafeFetch";

function fakeResult(overrides: Partial<SafeFetchResult> = {}): SafeFetchResult {
  return {
    statusCode: 200,
    headers: {},
    body: "<html></html>",
    finalUrl: "https://example.com/",
    redirectChain: [],
    tls: { authorized: true, protocol: "TLSv1.3", validTo: null, error: null },
    ...overrides,
  };
}

// --- checkTls ---

test("checkTls flags plain HTTP as critical", () => {
  const { findings } = checkTls(new URL("http://example.com/"), fakeResult());
  assert.ok(findings.some((f) => f.title === "Target does not use HTTPS" && f.severity === "critical"));
});

test("checkTls flags an unauthorized TLS certificate", () => {
  const res = fakeResult({ tls: { authorized: false, protocol: "TLSv1.2", validTo: null, error: "self signed certificate" } });
  const { findings } = checkTls(new URL("https://example.com/"), res);
  assert.ok(findings.some((f) => f.title === "TLS certificate is not valid"));
});

test("checkTls passes a valid HTTPS certificate", () => {
  const { findings, passed } = checkTls(new URL("https://example.com/"), fakeResult());
  assert.deepEqual(findings, []);
  assert.ok(passed.some((p) => p.title === "TLS certificate is valid and trusted"));
});

// --- checkHttpRedirectsToHttps ---

test("checkHttpRedirectsToHttps flags http that stays on http", () => {
  const { findings } = checkHttpRedirectsToHttps(new URL("http://example.com/"), "http://example.com/");
  assert.ok(findings.some((f) => f.title === "HTTP is not redirected to HTTPS"));
});

test("checkHttpRedirectsToHttps passes when http redirects to https", () => {
  const { findings, passed } = checkHttpRedirectsToHttps(new URL("http://example.com/"), "https://example.com/");
  assert.deepEqual(findings, []);
  assert.ok(passed.some((p) => p.title === "HTTP requests are redirected to HTTPS"));
});

test("checkHttpRedirectsToHttps is a no-op when the original target was already https", () => {
  const { findings, passed } = checkHttpRedirectsToHttps(new URL("https://example.com/"), "https://example.com/");
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

// --- checkSecurityHeaders ---

test("checkSecurityHeaders flags all 6 headers missing", () => {
  const { findings } = checkSecurityHeaders(fakeResult({ headers: {} }));
  assert.equal(findings.length, 6);
});

test("checkSecurityHeaders passes headers that are present", () => {
  const { findings, passed } = checkSecurityHeaders(
    fakeResult({
      headers: {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
      },
    })
  );
  assert.deepEqual(findings, []);
  assert.equal(passed.length, 6);
});

// --- checkCookies ---

test("checkCookies flags a cookie missing Secure/HttpOnly/SameSite", () => {
  const { findings } = checkCookies(fakeResult({ headers: { "set-cookie": ["session=abc123; Path=/"] } }));
  assert.equal(findings.length, 3);
  assert.ok(findings.some((f) => f.title.includes("Secure")));
  assert.ok(findings.some((f) => f.title.includes("HttpOnly")));
  assert.ok(findings.some((f) => f.title.includes("SameSite")));
});

test("checkCookies passes a fully-flagged cookie", () => {
  const { findings, passed } = checkCookies(
    fakeResult({ headers: { "set-cookie": ["session=abc123; Secure; HttpOnly; SameSite=Strict"] } })
  );
  assert.deepEqual(findings, []);
  assert.equal(passed.length, 3);
});

test("checkCookies is a no-op with no Set-Cookie header", () => {
  const { findings, passed } = checkCookies(fakeResult({ headers: {} }));
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

test("checkCookies handles multiple cookies independently", () => {
  const { findings } = checkCookies(
    fakeResult({ headers: { "set-cookie": ["good=1; Secure; HttpOnly; SameSite=Strict", "bad=2; Path=/"] } })
  );
  // Only the second cookie should generate findings (3 of them).
  assert.equal(findings.length, 3);
  assert.ok(findings.every((f) => f.title.includes('"bad"')));
});

// --- checkTechnologyDisclosure ---

test("checkTechnologyDisclosure flags X-Powered-By and a versioned Server header", () => {
  const { findings } = checkTechnologyDisclosure(
    fakeResult({ headers: { "x-powered-by": "Express", server: "nginx/1.18.0" } })
  );
  assert.ok(findings.some((f) => f.title.includes("X-Powered-By")));
  assert.ok(findings.some((f) => f.title.includes("Server header")));
});

test("checkTechnologyDisclosure does not flag a version-free Server header", () => {
  const { findings } = checkTechnologyDisclosure(fakeResult({ headers: { server: "nginx" } }));
  assert.equal(findings.some((f) => f.title.includes("Server header")), false);
});

test("checkTechnologyDisclosure passes when neither header is present", () => {
  const { findings, passed } = checkTechnologyDisclosure(fakeResult({ headers: {} }));
  assert.deepEqual(findings, []);
  assert.ok(passed.some((p) => p.title.includes("X-Powered-By")));
});

// --- checkExposedPaths (injected fetcher, no real network / SSRF gate) ---

test("checkExposedPaths flags a plausible exposed .env file", async () => {
  const fetcher = async (url: string): Promise<SafeFetchResult> => {
    if (url.endsWith("/.env")) {
      return fakeResult({ statusCode: 200, body: "DB_PASSWORD=hunter2\nAPI_KEY=sk_live_abc" });
    }
    return fakeResult({ statusCode: 404, body: "<html>Not Found</html>" });
  };
  const { findings } = await checkExposedPaths(new URL("https://example.com/"), fetcher);
  assert.ok(findings.some((f) => f.title.includes(".env file")));
});

test("checkExposedPaths does not flag a 200 HTML catch-all page", async () => {
  const fetcher = async (): Promise<SafeFetchResult> => fakeResult({ statusCode: 200, body: "<html><body>Not found</body></html>" });
  const { findings, passed } = await checkExposedPaths(new URL("https://example.com/"), fetcher);
  assert.deepEqual(findings, []);
  assert.equal(passed.length, 3);
});

test("checkExposedPaths does not flag a 404", async () => {
  const fetcher = async (): Promise<SafeFetchResult> => fakeResult({ statusCode: 404, body: "" });
  const { findings } = await checkExposedPaths(new URL("https://example.com/"), fetcher);
  assert.deepEqual(findings, []);
});

test("checkExposedPaths silently skips a probe that fails outright", async () => {
  const fetcher = async (): Promise<SafeFetchResult> => {
    throw new Error("connection reset");
  };
  const { findings, passed } = await checkExposedPaths(new URL("https://example.com/"), fetcher);
  assert.deepEqual(findings, []);
  assert.deepEqual(passed, []);
});

// --- scanUrl (SSRF gate + orchestration) ---

test("scanUrl propagates SsrfBlockedError for a private target without treating it as unreachable", async () => {
  await assert.rejects(() => scanUrl("http://127.0.0.1:1/"), SsrfBlockedError);
});

test("scanUrl wraps a genuine network failure as UrlScanUnreachableError", async () => {
  const fetcher = async (): Promise<SafeFetchResult> => {
    throw new Error("ECONNREFUSED");
  };
  await assert.rejects(() => scanUrl("https://example.com/", fetcher), UrlScanUnreachableError);
});

test("scanUrl runs the full check set end-to-end against a real local server", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/.env" || req.url === "/.git/HEAD" || req.url === "/.git/config") {
      res.writeHead(404);
      return res.end("<html>Not Found</html>");
    }
    res.setHeader("Set-Cookie", "session=abc; Path=/");
    res.setHeader("X-Powered-By", "Express");
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html>hi</html>");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as import("net").AddressInfo).port;
  const targetUrl = `http://127.0.0.1:${port}/`;

  // Inject a fetcher that performs a real request without going through
  // the SSRF gate (which would correctly refuse 127.0.0.1) — the gate
  // itself is tested separately in ssrfSafeFetch.test.ts.
  const fetcher = async (url: string): Promise<SafeFetchResult> => {
    const parsed = new URL(url);
    const { res, body } = await performValidatedRequest(parsed, "127.0.0.1", 4);
    return {
      statusCode: res.statusCode ?? 0,
      headers: res.headers as SafeFetchResult["headers"],
      body,
      finalUrl: url,
      redirectChain: [],
      tls: null,
    };
  };

  try {
    const result = await scanUrl(targetUrl, fetcher);
    // No HTTPS -> critical finding; no security headers -> 6 findings;
    // cookie missing Secure/HttpOnly/SameSite -> 3 findings; X-Powered-By -> 1.
    assert.ok(result.findings.some((f) => f.title === "Target does not use HTTPS"));
    assert.ok(result.findings.some((f) => f.title === "X-Powered-By header discloses backend technology"));
    assert.ok(result.findings.filter((f) => f.category === "Session Management").length === 3);
    assert.ok(result.passed.some((p) => p.title.includes(".env")));
  } finally {
    server.close();
  }
});
