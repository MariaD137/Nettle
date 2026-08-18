import { ssrfSafeFetch, SsrfBlockedError, type SafeFetchResult } from "./ssrfSafeFetch";
import type { Finding, Pass } from "./types";

/**
 * External, non-destructive security assessment of a live URL — distinct
 * from source/repository scanning, which reads code. This only ever
 * issues plain GET requests (no auth bypass attempts, no payloads, no
 * write operations) and reports on what the live HTTP response actually
 * shows. See ssrfSafeFetch.ts for the SSRF hardening every request here
 * goes through.
 *
 * Findings from this module always carry evidence phrased as "observed
 * in the live response" to make clear this is direct external evidence,
 * not inference from source code — the two are complementary, not
 * duplicates, even where the underlying concern (e.g. missing HSTS) is
 * the same one securityHeaders.ts also checks for from source.
 */

export class UrlScanUnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UrlScanUnreachableError";
  }
}

interface HeaderCheck {
  header: string;
  severity: Finding["severity"];
  detail: string;
  remediation: string;
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    severity: "high",
    detail: "Without HSTS, browsers may connect over HTTP first on a future visit, exposing that initial request to man-in-the-middle downgrade attacks.",
    remediation: "Configure the web server/CDN/load balancer to send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
  },
  {
    header: "content-security-policy",
    severity: "high",
    detail: "Without a CSP, the browser has no restriction on which scripts/resources it will execute, widening the impact of any XSS that does occur.",
    remediation: "Configure a Content-Security-Policy header appropriate to the app's actual script/style/resource origins.",
  },
  {
    header: "x-frame-options",
    severity: "medium",
    detail: "Without X-Frame-Options (or an equivalent frame-ancestors CSP directive), the page can be embedded in a hidden iframe for clickjacking.",
    remediation: "Send X-Frame-Options: DENY (or SAMEORIGIN if the app legitimately frames its own pages).",
  },
  {
    header: "x-content-type-options",
    severity: "medium",
    detail: "Without nosniff, some browsers may MIME-sniff a response and execute it as script/HTML regardless of its declared Content-Type.",
    remediation: "Send X-Content-Type-Options: nosniff.",
  },
  {
    header: "referrer-policy",
    severity: "low",
    detail: "Without a Referrer-Policy, the full URL (including any sensitive query parameters) may be leaked to third-party sites via the Referer header.",
    remediation: "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter).",
  },
  {
    header: "permissions-policy",
    severity: "low",
    detail: "Without a Permissions-Policy, the page has no explicit restriction on browser features (camera, microphone, geolocation) it doesn't need.",
    remediation: "Send a Permissions-Policy header disabling unused features, e.g. camera=(), microphone=(), geolocation=().",
  },
];

// A deliberately small, conservative set — enough to catch the most common
// accidental exposures without turning this into a path-guessing scanner.
const EXPOSED_PATH_CHECKS: Array<{ path: string; label: string }> = [
  { path: "/.env", label: ".env file" },
  { path: "/.git/HEAD", label: ".git directory" },
  { path: "/.git/config", label: ".git directory" },
];

function evidence(detail: string): string {
  return `${detail} (observed directly in the live HTTP response)`;
}

function parseSetCookies(headers: SafeFetchResult["headers"]): string[] {
  const raw = headers["set-cookie"];
  if (!raw) return [];
  return Array.isArray(raw) ? raw : [raw];
}

export function checkTls(target: URL, res: SafeFetchResult): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  if (target.protocol !== "https:") {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      title: "Target does not use HTTPS",
      detail: evidence("The scanned URL uses plain HTTP, so all traffic (including any credentials or session tokens) is sent unencrypted and can be intercepted or modified in transit."),
      file: null,
      line: null,
      remediation: "Serve the application over HTTPS with a valid certificate, and redirect all HTTP traffic to HTTPS.",
    });
    return { findings, passed };
  }

  if (!res.tls) {
    return { findings, passed };
  }

  if (!res.tls.authorized) {
    findings.push({
      severity: "critical",
      category: "Cryptography",
      title: "TLS certificate is not valid",
      detail: evidence(`The TLS certificate presented by the server did not validate${res.tls.error ? `: ${res.tls.error}` : "."}`),
      file: null,
      line: null,
      remediation: "Install a valid certificate from a trusted CA (e.g. via Let's Encrypt/ACM) and ensure the certificate chain is complete.",
    });
  } else {
    passed.push({ category: "Cryptography", title: "TLS certificate is valid and trusted" });
  }

  return { findings, passed };
}

export function checkHttpRedirectsToHttps(originalUrl: URL, finalUrl: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  if (originalUrl.protocol !== "http:") return { findings, passed };

  if (finalUrl.startsWith("https://")) {
    passed.push({ category: "Cryptography", title: "HTTP requests are redirected to HTTPS" });
  } else {
    findings.push({
      severity: "high",
      category: "Cryptography",
      title: "HTTP is not redirected to HTTPS",
      detail: evidence("A plain HTTP request to this host did not redirect to an HTTPS URL, meaning the site can be accessed insecurely."),
      file: null,
      line: null,
      remediation: "Configure the web server/load balancer to redirect all HTTP requests to the HTTPS equivalent (301/308).",
    });
  }
  return { findings, passed };
}

export function checkSecurityHeaders(res: SafeFetchResult): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  for (const check of HEADER_CHECKS) {
    const present = res.headers[check.header] !== undefined;
    if (present) {
      passed.push({ category: "Security", title: `${check.header} header is present in the live response` });
    } else {
      findings.push({
        severity: check.severity,
        category: "Security",
        title: `${check.header} header not present in live response`,
        detail: evidence(check.detail),
        file: null,
        line: null,
        remediation: check.remediation,
      });
    }
  }

  return { findings, passed };
}

export function checkCookies(res: SafeFetchResult): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const cookies = parseSetCookies(res.headers);
  if (cookies.length === 0) return { findings, passed };

  let anyMissingSecure = false;
  let anyMissingHttpOnly = false;
  let anyMissingSameSite = false;

  for (const cookie of cookies) {
    const lower = cookie.toLowerCase();
    const cookieName = cookie.split("=")[0]?.trim() || "cookie";
    if (!lower.includes("secure")) {
      anyMissingSecure = true;
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: `Cookie "${cookieName}" set without the Secure flag`,
        detail: evidence("Without Secure, this cookie can be sent over an unencrypted HTTP connection if one is ever made, exposing it to interception."),
        file: null,
        line: null,
        remediation: `Set the Secure attribute on the "${cookieName}" cookie.`,
      });
    }
    if (!lower.includes("httponly")) {
      anyMissingHttpOnly = true;
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: `Cookie "${cookieName}" set without the HttpOnly flag`,
        detail: evidence("Without HttpOnly, this cookie is readable from JavaScript, so a successful XSS on this page could steal it directly."),
        file: null,
        line: null,
        remediation: `Set the HttpOnly attribute on the "${cookieName}" cookie.`,
      });
    }
    if (!lower.includes("samesite")) {
      anyMissingSameSite = true;
      findings.push({
        severity: "low",
        category: "Session Management",
        title: `Cookie "${cookieName}" set without a SameSite attribute`,
        detail: evidence("Without SameSite, this cookie is sent on cross-site requests by default in older browsers, widening CSRF exposure."),
        file: null,
        line: null,
        remediation: `Set SameSite=Lax (or Strict) on the "${cookieName}" cookie.`,
      });
    }
  }

  if (!anyMissingSecure) passed.push({ category: "Session Management", title: "Cookies set the Secure flag" });
  if (!anyMissingHttpOnly) passed.push({ category: "Session Management", title: "Cookies set the HttpOnly flag" });
  if (!anyMissingSameSite) passed.push({ category: "Session Management", title: "Cookies set a SameSite attribute" });

  return { findings, passed };
}

export function checkTechnologyDisclosure(res: SafeFetchResult): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const server = res.headers["server"];
  const poweredBy = res.headers["x-powered-by"];

  if (poweredBy) {
    findings.push({
      severity: "info",
      category: "Security",
      title: "X-Powered-By header discloses backend technology",
      detail: evidence(`The response includes "X-Powered-By: ${poweredBy}", which tells an attacker what framework/version to target with known exploits.`),
      file: null,
      line: null,
      remediation: "Disable the X-Powered-By header (e.g. app.disable('x-powered-by') in Express).",
    });
  } else {
    passed.push({ category: "Security", title: "No X-Powered-By technology disclosure header" });
  }

  if (typeof server === "string" && /\d/.test(server)) {
    findings.push({
      severity: "info",
      category: "Security",
      title: "Server header discloses a specific software version",
      detail: evidence(`The response includes "Server: ${server}", which discloses a specific version an attacker can match against known vulnerabilities.`),
      file: null,
      line: null,
      remediation: "Configure the web server to omit its version from the Server header.",
    });
  }

  return { findings, passed };
}

export async function checkExposedPaths(
  baseUrl: URL,
  fetcher: (url: string) => Promise<SafeFetchResult> = ssrfSafeFetch
): Promise<{ findings: Finding[]; passed: Pass[] }> {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  for (const check of EXPOSED_PATH_CHECKS) {
    try {
      const probeUrl = new URL(check.path, baseUrl).toString();
      const res = await fetcher(probeUrl);
      // A 200 with plausible content is treated as exposed; most sites
      // 404 (or serve a catch-all HTML page) for these paths, so a
      // non-2xx or an HTML error page is not flagged.
      const looksLikeRealFile = res.statusCode === 200 && !/<html/i.test(res.body.slice(0, 200));
      if (looksLikeRealFile) {
        findings.push({
          severity: "critical",
          category: "Security",
          title: `${check.label} appears to be publicly accessible`,
          detail: evidence(`A GET request to ${check.path} returned HTTP 200 with content that doesn't look like a standard error page, suggesting the file/directory is served directly.`),
          file: null,
          line: null,
          remediation: `Remove or block public access to ${check.path} — this content should never be served to the public.`,
        });
      } else {
        passed.push({ category: "Security", title: `${check.label} is not publicly accessible` });
      }
    } catch {
      // A failed probe (timeout, connection error) isn't evidence either
      // way — silently skip rather than claim a check that didn't complete.
    }
  }

  return { findings, passed };
}

export interface UrlScanResult {
  findings: Finding[];
  passed: Pass[];
  finalUrl: string;
}

/**
 * Runs the full URL check set against a single target. Throws
 * UrlScanUnreachableError if the target can't be reached at all (DNS
 * failure, connection refused, timeout) — that's a scan-level failure,
 * not a finding, since there's nothing to report findings about.
 */
export async function scanUrl(
  targetUrl: string,
  fetcher: (url: string) => Promise<SafeFetchResult> = ssrfSafeFetch
): Promise<UrlScanResult> {
  const url = new URL(targetUrl);

  let res: SafeFetchResult;
  try {
    res = await fetcher(targetUrl);
  } catch (err) {
    if (err instanceof SsrfBlockedError) throw err;
    throw new UrlScanUnreachableError(`Couldn't reach ${targetUrl}: ${(err as Error).message}`);
  }

  const results = [
    checkTls(url, res),
    checkHttpRedirectsToHttps(url, res.finalUrl),
    checkSecurityHeaders(res),
    checkCookies(res),
    checkTechnologyDisclosure(res),
    await checkExposedPaths(new URL(res.finalUrl), fetcher),
  ];

  return {
    findings: results.flatMap((r) => r.findings),
    passed: results.flatMap((r) => r.passed),
    finalUrl: res.finalUrl,
  };
}
