import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface HeaderCheck {
  name: string;
  patterns: RegExp[];
  severity: Finding["severity"];
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

export function scanSecurityHeaders(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const serverFiles = files.filter((f) => /\.(js|ts)$/.test(f));
  const allSource = serverFiles.map((f) => fs.readFileSync(f, "utf8")).join("\n");

  const hasHelmet = HEADER_CHECKS[0].patterns.some((p) => p.test(allSource));

  if (hasHelmet) {
    passed.push({ category: "Security", title: "Helmet security headers middleware is installed" });
    for (const check of HEADER_CHECKS.slice(1)) {
      passed.push({ category: "Security", title: `${check.name} (covered by Helmet)` });
    }
    return { findings, passed };
  }

  findings.push({
    severity: HEADER_CHECKS[0].severity,
    category: "Security",
    title: "No security headers middleware detected",
    detail: HEADER_CHECKS[0].detail,
    file: null,
    remediation: HEADER_CHECKS[0].remediation,
  });

  for (const check of HEADER_CHECKS.slice(1)) {
    const found = check.patterns.some((p) => p.test(allSource));
    if (found) {
      passed.push({ category: "Security", title: `${check.name} header is configured` });
    } else {
      findings.push({
        severity: check.severity,
        category: "Security",
        title: `Missing ${check.name} header`,
        detail: check.detail,
        file: null,
        remediation: check.remediation,
      });
    }
  }

  return { findings, passed };
}
