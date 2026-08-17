import fs from "fs";
import type { Finding, Pass } from "./types";

export function scanLegalPolicy(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  let allFiles: string[] = [];
  try { allFiles = fs.readdirSync(targetRoot); } catch { /* empty */ }

  const hasPrivacyPolicy = allFiles.some((f) => /privacy[-_]?policy/i.test(f));
  const hasTerms = allFiles.some((f) => /terms/i.test(f));
  const hasCookiePolicy = allFiles.some((f) => /cookie[-_]?policy/i.test(f));
  const hasContact = allFiles.some((f) => /contact/i.test(f));

  if (!hasPrivacyPolicy) {
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

  return { findings, passed };
}
