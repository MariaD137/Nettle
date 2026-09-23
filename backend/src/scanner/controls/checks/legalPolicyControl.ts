import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next"]);

/**
 * Lists every filename in the project tree, regardless of extension.
 *
 * The shared walk() used by the rest of the scanner is deliberately
 * extension-filtered (.js/.ts/.jsx/.tsx/.env/.json) for content scanning —
 * a legal document is typically .md, .html, or .txt, none of which are in
 * that list, so this control needs its own listing. It only ever reads
 * filenames, never file contents, so the broader surface carries none of
 * the risk a content-reading walk over arbitrary file types would.
 */
function listAllFilenames(dir: string, out: string[] = [], maxDepth = 100, currentDepth = 1): string[] {
  if (currentDepth > maxDepth) return out;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isSymbolicLink()) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      listAllFilenames(full, out, maxDepth, currentDepth + 1);
    } else {
      out.push(entry.name);
    }
  }
  return out;
}

interface LegalDocCheck {
  controlKey: string;
  pattern: RegExp;
  title: string;
  /** Emitted when the pattern isn't found. NOT_VERIFIED when legal
   *  applicability can't be determined from source alone; FAIL when the
   *  document is a best-practice completeness item, not a compliance claim. */
  absentStatus: "FAIL" | "NOT_VERIFIED";
  absentTitle: string;
  absentDetail: string;
  severity?: "medium" | "low";
  remediation?: string;
}

const CHECKS: LegalDocCheck[] = [
  {
    controlKey: "LEGAL-001",
    pattern: /privacy[-_]?policy/i,
    title: "Privacy policy file present",
    absentStatus: "NOT_VERIFIED",
    absentTitle: "No privacy policy found in the scanned project",
    absentDetail: "This may not mean the application lacks one — it may be hosted externally (a marketing site, a legal/compliance platform) outside what was scanned. Whether one is legally required depends on what data the application collects and which jurisdictions its users are in, which this scan cannot determine. Human review is needed.",
  },
  {
    controlKey: "LEGAL-002",
    pattern: /terms/i,
    title: "Terms of service file present",
    absentStatus: "FAIL",
    absentTitle: "No terms of service found",
    absentDetail: "Not always legally required, but standard for apps handling accounts or payments, and reduces dispute risk.",
    severity: "medium",
    remediation: "Create a TERMS.md (or host at /terms) outlining acceptable use, liability limitations, and dispute resolution.",
  },
  {
    controlKey: "LEGAL-003",
    pattern: /cookie[-_]?policy/i,
    title: "Cookie policy file present",
    absentStatus: "NOT_VERIFIED",
    absentTitle: "No cookie policy found in the scanned project",
    absentDetail: "This does not confirm the application needs one: it may not use cookies or tracking at all, may cover cookies within its privacy policy instead, or may not be subject to the regulations that require one. Human review is needed.",
  },
  {
    controlKey: "LEGAL-004",
    pattern: /contact/i,
    title: "Contact information present",
    absentStatus: "FAIL",
    absentTitle: "No contact information page found",
    absentDetail: "Users should have a way to reach you for data deletion requests, support, and legal inquiries.",
    severity: "low",
    remediation: "Create a CONTACT.md or include contact details in your privacy policy and terms of service.",
  },
];

/**
 * LEGAL-001..004, wired to the control library. Extracted from
 * legalPolicy.ts's former inline checks -- same filename patterns, but with
 * two changes:
 *
 * 1. Recursive, not shallow: the legacy module used fs.readdirSync(root)
 *    directly, checking only the project's top-level directory. A privacy
 *    policy living in legal/, docs/, or frontend/public/ — all common real
 *    locations — was invisible to it. This walks the full tree.
 * 2. LEGAL-001 (privacy policy) and LEGAL-003 (cookie policy) no longer
 *    FAIL at critical/low severity when absent. Per the product's own
 *    legal-framing requirement: Nettle cannot determine from source alone
 *    whether a privacy or cookie policy is actually legally required for a
 *    given app (that depends on what data it collects and which
 *    jurisdictions its users are in) or whether one exists outside the
 *    scanned file set (hosted externally). Asserting a "critical" finding
 *    on a fact Nettle can't verify is exactly the fabricated-certainty
 *    failure mode the three-state model exists to prevent — so absence is
 *    now NOT_VERIFIED, not FAIL. Terms of service and contact information
 *    were already framed as best-practice/completeness items rather than
 *    compliance claims, so those keep their original FAIL/PASS shape.
 */
export function scanLegalPolicyControl(targetRoot: string): CheckResult[] {
  const filenames = listAllFilenames(targetRoot);

  return CHECKS.map((check): CheckResult => {
    const found = filenames.some((f) => check.pattern.test(f));

    if (found) {
      return {
        checkId: generateCheckId("Legal & Policy", `${check.controlKey}:pass`),
        status: "PASS",
        category: "Legal & Policy",
        title: check.title,
        confidence: 85,
        detectionMethod: "heuristic",
        controlKey: check.controlKey,
      };
    }

    if (check.absentStatus === "NOT_VERIFIED") {
      return {
        checkId: generateCheckId("Legal & Policy", `${check.controlKey}:not-verified`),
        status: "NOT_VERIFIED",
        category: "Legal & Policy",
        title: check.absentTitle,
        detail: check.absentDetail,
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: check.controlKey,
      };
    }

    return {
      checkId: generateCheckId("Legal & Policy", `${check.controlKey}:fail`),
      status: "FAIL",
      category: "Legal & Policy",
      title: check.absentTitle,
      detail: check.absentDetail,
      severity: check.severity,
      confidence: 85,
      detectionMethod: "heuristic",
      remediation: check.remediation,
      controlKey: check.controlKey,
    };
  });
}
