import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

/**
 * Topics a privacy policy is generally expected to address under GDPR/CCPA.
 * Heuristic keyword matching, same as everything else in this file — it
 * can't judge whether the disclosure is actually adequate, only whether the
 * topic appears to be addressed at all.
 */
const DATA_HANDLING_TOPICS: { pattern: RegExp; label: string }[] = [
  { pattern: /collect/i, label: "what data is collected" },
  { pattern: /\buse(s|d)?\b.{0,15}\b(data|information)\b|how we use|purpose of (the |your )?(data|collection)/i, label: "how the data is used" },
  { pattern: /third[- ]part|\bshare\b.{0,20}\b(data|information)\b|\bsell\b.{0,20}\b(data|information)\b/i, label: "third-party sharing" },
  { pattern: /retai?n|how long we (keep|store)/i, label: "data retention" },
  { pattern: /right to (access|delet|erasure|be forgotten|rectif)|request (deletion|access)|opt[- ]out|data subject/i, label: "user rights (access, deletion, opt-out)" },
];

/** Cookie-setting or third-party tracking/analytics usage in application code. */
const TRACKING_PATTERNS = [
  /document\.cookie/,
  /res\.cookie\s*\(/,
  /gtag\s*\(/,
  /googletagmanager\.com/i,
  /google-analytics\.com/i,
  /fbq\s*\(/,
  /mixpanel/i,
  /hotjar/i,
  /amplitude/i,
  /segment\.(io|com)/i,
];

/** Cookie-consent / opt-in libraries or hand-rolled consent state. */
const CONSENT_PATTERNS = [
  /cookie[-_]?consent/i,
  /gdpr[-_]?consent/i,
  /consentGiven/i,
  /hasConsented/i,
  /acceptCookies/i,
  /CookieBanner/i,
  /accepted[-_]?terms/i,
];

export function scanLegalPolicy(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  let allFiles: string[] = [];
  try { allFiles = fs.readdirSync(targetRoot); } catch { /* empty */ }

  const privacyPolicyFile = allFiles.find((f) => /privacy[-_]?policy/i.test(f));
  const hasTerms = allFiles.some((f) => /terms/i.test(f));
  const hasCookiePolicy = allFiles.some((f) => /cookie[-_]?policy/i.test(f));
  const hasContact = allFiles.some((f) => /contact/i.test(f));

  if (!privacyPolicyFile) {
    findings.push({
      severity: "critical",
      category: "Legal & Policy",
      title: "No privacy policy found",
      detail: "Required for App Store / Play Store submission and for GDPR/CCPA compliance if the app collects any user data.",
      file: null,
      line: null,
      remediation: "Create a PRIVACY_POLICY.md (or host one at /privacy) covering what data you collect, how it's used, and how users can request deletion.",
    });
  } else {
    passed.push({ category: "Legal & Policy", title: "Privacy policy file present" });

    // Content-level check, distinct from the file-presence check above: a
    // privacy policy that exists but says nothing about what's actually
    // done with the data isn't much of a disclosure.
    let policyText = "";
    try {
      policyText = fs.readFileSync(path.join(targetRoot, privacyPolicyFile), "utf8");
    } catch {
      // Unreadable (odd permissions, symlink race, etc.) — skip the content
      // check rather than fail the whole scan over it.
    }
    if (policyText) {
      const missingTopics = DATA_HANDLING_TOPICS.filter((t) => !t.pattern.test(policyText)).map((t) => t.label);
      if (missingTopics.length > 0) {
        findings.push({
          severity: "medium",
          category: "Legal & Policy",
          title: "Privacy policy doesn't disclose key data-handling practices",
          detail: `The privacy policy exists but doesn't appear to address: ${missingTopics.join(", ")}. Privacy policies are generally expected to cover what's collected, how it's used, whether it's shared with third parties, how long it's kept, and how users can exercise their rights over it.`,
          file: privacyPolicyFile,
          line: null,
          remediation: `Add sections covering: ${missingTopics.join(", ")}.`,
        });
      } else {
        passed.push({ category: "Legal & Policy", title: "Privacy policy discloses data collection, usage, sharing, retention, and user rights" });
      }
    }
  }

  if (!hasTerms) {
    findings.push({
      severity: "medium",
      category: "Legal & Policy",
      title: "No terms of service found",
      detail: "Not always legally required, but standard for apps handling accounts or payments, and reduces dispute risk.",
      file: null,
      line: null,
      remediation: "Create a TERMS.md (or host at /terms) outlining acceptable use, liability limitations, and dispute resolution.",
    });
  } else {
    passed.push({ category: "Legal & Policy", title: "Terms of service file present" });
  }

  if (!hasCookiePolicy) {
    findings.push({
      severity: "low",
      category: "Legal & Policy",
      title: "No cookie policy found",
      detail: "If your application uses cookies or similar tracking, a cookie policy may be required under ePrivacy/GDPR regulations.",
      file: null,
      line: null,
      remediation: "Create a COOKIE_POLICY.md or add a cookie section to your privacy policy if your app uses cookies.",
    });
  } else {
    passed.push({ category: "Legal & Policy", title: "Cookie policy file present" });
  }

  if (!hasContact) {
    findings.push({
      severity: "low",
      category: "Legal & Policy",
      title: "No contact information page found",
      detail: "Users should have a way to reach you for data deletion requests, support, and legal inquiries.",
      file: null,
      line: null,
      remediation: "Create a CONTACT.md or include contact details in your privacy policy and terms of service.",
    });
  } else {
    passed.push({ category: "Legal & Policy", title: "Contact information present" });
  }

  // Consent mechanisms: only relevant if the app appears to set cookies or
  // load tracking/analytics at all. An app that does neither has nothing to
  // get consent for, so this check is skipped entirely rather than flagged
  // or passed — flagging it anyway would just be noise, and "passing" it
  // would misleadingly imply consent was verified for something that isn't
  // there.
  const sourceFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  const sourceText = sourceFiles
    .map((f) => {
      try {
        return fs.readFileSync(f, "utf8");
      } catch {
        return "";
      }
    })
    .join("\n");
  const usesTracking = TRACKING_PATTERNS.some((p) => p.test(sourceText));
  if (usesTracking) {
    const hasConsentMechanism = CONSENT_PATTERNS.some((p) => p.test(sourceText));
    if (!hasConsentMechanism) {
      findings.push({
        severity: "high",
        category: "Legal & Policy",
        title: "No consent mechanism detected despite cookie/tracking usage",
        detail: "This codebase appears to set cookies or load a tracking/analytics script, but no cookie-consent or opt-in pattern was found. Under GDPR/ePrivacy rules, non-essential cookies and tracking generally require the user's consent before they run.",
        file: null,
        line: null,
        remediation: "Gate non-essential cookies and tracking scripts behind explicit user opt-in — e.g. a cookie-consent banner (such as react-cookie-consent) that only loads them after consent is given.",
      });
    } else {
      passed.push({ category: "Legal & Policy", title: "A consent mechanism is present alongside cookie/tracking usage" });
    }
  }

  return { findings, passed };
}
