import fs from "fs";
import type { Finding, Pass } from "./types";

export function scanLegalPolicy(targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const rootFiles = fs.readdirSync(targetRoot);

  const hasPrivacyPolicy = rootFiles.some((f) => /privacy[-_]?policy/i.test(f));
  const hasTerms = rootFiles.some((f) => /terms/i.test(f));

  if (!hasPrivacyPolicy) {
    findings.push({
      severity: "critical",
      category: "Legal & Policy",
      title: "No privacy policy found",
      detail: "Required for App Store / Play Store submission and for GDPR/CCPA compliance if the app collects any user data.",
      file: null,
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
      remediation: "Create a TERMS.md (or host at /terms) outlining acceptable use, liability limitations, and dispute resolution.",
    });
  } else {
    passed.push({ category: "Legal & Policy", title: "Terms of service file present" });
  }

  return { findings, passed };
}
