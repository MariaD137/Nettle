import fs from "fs";
import type { CheckResult, Severity } from "../../types";
import { generateCheckId } from "../../threeStateModel";

interface HeaderCheck {
  name: string;
  patterns: RegExp[];
  severity: Severity;
  detail: string;
  remediation: string;
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    name: "Helmet middleware",
    patterns: [/require\(\s*['"]helmet['"]\s*\)/, /from\s+['"]helmet['"]/],
    severity: "high",
    detail: "Helmet sets sensible security headers (CSP, HSTS, X-Frame-Options, etc.) in one line. Without it, the app relies on browser defaults that leave known attack surfaces open.",
    remediation: "Install helmet (npm install helmet) and add app.use(helmet()) before your routes.",
  },
  {
    name: "Content Security Policy",
    patterns: [/content-security-policy/i, /contentSecurityPolicy/, /\.csp\s*\(/, /helmet\.contentSecurityPolicy/],
    severity: "high",
    detail: "CSP prevents XSS, clickjacking, and data injection attacks by restricting which resources the browser can load.",
    remediation: "Configure a Content-Security-Policy header. With helmet: helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } }).",
  },
  {
    name: "HSTS (HTTP Strict Transport Security)",
    patterns: [/strict-transport-security/i, /hsts/, /strictTransportSecurity/],
    severity: "high",
    detail: "Without HSTS, browsers may connect over HTTP first, exposing the initial request to man-in-the-middle attacks.",
    remediation: "Set the Strict-Transport-Security header with a long max-age. With helmet: helmet({ hsts: { maxAge: 31536000, includeSubDomains: true } }).",
  },
  {
    name: "X-Frame-Options",
    patterns: [/x-frame-options/i, /frameguard/, /xFrameOptions/],
    severity: "medium",
    detail: "Without X-Frame-Options or frame-ancestors CSP, the app can be embedded in iframes for clickjacking attacks.",
    remediation: "Set X-Frame-Options: DENY (or SAMEORIGIN if you need to iframe your own pages). Helmet does this by default.",
  },
  {
    name: "X-Content-Type-Options",
    patterns: [/x-content-type-options/i, /noSniff/, /xContentTypeOptions/],
    severity: "medium",
    detail: "Without nosniff, browsers may MIME-sniff responses and interpret uploaded content as executable scripts.",
    remediation: "Set X-Content-Type-Options: nosniff. Helmet does this by default.",
  },
  {
    name: "Referrer-Policy",
    patterns: [/referrer-policy/i, /referrerPolicy/],
    severity: "low",
    detail: "Without a Referrer-Policy, the browser may leak full URLs (including query parameters with tokens) to third-party sites.",
    remediation: "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for stricter control). Helmet sets this by default.",
  },
  {
    name: "Permissions-Policy",
    patterns: [/permissions-policy/i, /permissionsPolicy/, /feature-policy/i],
    severity: "low",
    detail: "Permissions-Policy restricts browser features (camera, microphone, geolocation) that the app doesn't need.",
    remediation: "Set a Permissions-Policy header disabling unused features: Permissions-Policy: camera=(), microphone=(), geolocation=().",
  },
];

/**
 * BROWSER-001, wired to the control library. Moved from
 * scanner/securityHeaders.ts (now deleted -- every check it made is
 * promoted here, none left as legacy) with the same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file.
 */
export function scanSecurityHeadersControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const serverFiles = files.filter((f) => /\.(js|ts)$/.test(f));

  let allSource = "";
  let anyReadable = false;
  for (const file of serverFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
      anyReadable = true;
    } catch {
      // fall through; handled below if nothing at all could be read
    }
  }

  if (serverFiles.length > 0 && !anyReadable) {
    return [
      {
        checkId: generateCheckId("Configuration", "BROWSER-001:unreadable"),
        status: "NOT_VERIFIED",
        category: "Configuration",
        title: "No server file could be read for security-header analysis",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "BROWSER-001",
      },
    ];
  }

  const hasHelmet = HEADER_CHECKS[0].patterns.some((p) => p.test(allSource));

  if (hasHelmet) {
    results.push({
      checkId: generateCheckId("Configuration", "BROWSER-001:helmet:pass"),
      status: "PASS",
      category: "Configuration",
      title: "Helmet security headers middleware is installed",
      confidence: 85,
      detectionMethod: "heuristic",
      controlKey: "BROWSER-001",
    });
    for (const check of HEADER_CHECKS.slice(1)) {
      results.push({
        checkId: generateCheckId("Configuration", `BROWSER-001:pass:${check.name}`),
        status: "PASS",
        category: "Configuration",
        title: `${check.name} (covered by Helmet)`,
        confidence: 85,
        detectionMethod: "heuristic",
        controlKey: "BROWSER-001",
      });
    }
    return results;
  }

  results.push({
    checkId: generateCheckId("Configuration", "BROWSER-001:no-middleware"),
    status: "FAIL",
    category: "Configuration",
    title: "No security headers middleware detected",
    detail: HEADER_CHECKS[0].detail,
    severity: HEADER_CHECKS[0].severity,
    confidence: 75,
    detectionMethod: "heuristic",
    remediation: HEADER_CHECKS[0].remediation,
    controlKey: "BROWSER-001",
  });

  for (const check of HEADER_CHECKS.slice(1)) {
    const found = check.patterns.some((p) => p.test(allSource));
    if (found) {
      results.push({
        checkId: generateCheckId("Configuration", `BROWSER-001:pass:${check.name}`),
        status: "PASS",
        category: "Configuration",
        title: `${check.name} header is configured`,
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "BROWSER-001",
      });
    } else {
      results.push({
        checkId: generateCheckId("Configuration", `BROWSER-001:fail:${check.name}`),
        status: "FAIL",
        category: "Configuration",
        title: `Missing ${check.name} header`,
        detail: check.detail,
        severity: check.severity,
        confidence: 75,
        detectionMethod: "heuristic",
        remediation: check.remediation,
        controlKey: "BROWSER-001",
      });
    }
  }

  return results;
}
