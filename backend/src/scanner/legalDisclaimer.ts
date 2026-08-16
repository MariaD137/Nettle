/**
 * Legal disclaimers: GDPR, liability waivers, accuracy statements.
 * Ensures users understand the scope and limitations of the scanner.
 */

export type DisclaimerType = "liability" | "accuracy" | "gdpr" | "ai-generated" | "scope-limitation";

export interface DisclaimerText {
  title: string;
  text: string;
  version: string;
  updatedAt: string;
}

/**
 * Library of legal disclaimer templates.
 */
const DISCLAIMERS: Record<DisclaimerType, DisclaimerText> = {
  "liability": {
    title: "Limitation of Liability",
    text: `
Nettle is provided "as-is" without any warranties. The scanner performs static
analysis to identify potential security issues in your code, but it is not perfect
and may miss actual vulnerabilities or report false positives.

YOU ACKNOWLEDGE THAT NETTLE'S FINDINGS ARE NOT A SUBSTITUTE FOR:
- Professional security audits by qualified security experts
- Code review by experienced developers
- Penetration testing in production environments
- Compliance with industry standards and regulations

Nettle makes no warranty that the scanner will detect all security issues. Use of
this tool is at your own risk. In no event shall Nettle or its authors be liable
for any damages arising from use of this scanner, including lost revenue, lost
profits, or data loss.

You are responsible for verifying all findings and determining their applicability
to your specific use case.
    `.trim(),
    version: "1.0",
    updatedAt: "2026-08-16",
  },

  "accuracy": {
    title: "Accuracy & False Positives",
    text: `
While Nettle uses established security analysis techniques, its findings may include:

- FALSE POSITIVES: Issues flagged that aren't actually security problems in your
  specific context (e.g., public API intentionally without authentication)

- FALSE NEGATIVES: Real vulnerabilities that the scanner misses (e.g., complex
  business logic flaws, timing-based attacks)

- INCOMPLETE ANALYSIS: Some findings are marked as "NOT_VERIFIED" when analysis
  tools are unavailable, meaning potential issues weren't fully investigated

Security issues often depend on context, threat model, and how the code is deployed.
Always have findings reviewed by a human security expert before assuming they are
genuine risks or safe to dismiss.

Nettle reports findings based on patterns and known vulnerability databases as of
its last update. New vulnerability types and attack techniques may not be detected.
    `.trim(),
    version: "1.0",
    updatedAt: "2026-08-16",
  },

  "gdpr": {
    title: "GDPR & Data Privacy",
    text: `
NETTLE PROCESSES SOURCE CODE
When you upload code to Nettle for analysis, that code is:
- Scanned by the backend service
- Not stored for marketing or improvement purposes (delete after scan completes)
- Not shared with third parties
- Used only for the analysis you requested

We are the Data Processor. You (the uploader) are the Data Controller and are
responsible for:
- Having rights to upload the code (not someone else's proprietary code)
- Ensuring no secrets (API keys, passwords) are included
- Complying with licenses and confidentiality agreements

USER RIGHTS (Articles 15-20, GDPR)
You have the right to:
- Access your scans and results (data portability)
- Deletion of scans (request via email to [CONTACT])
- Correction of inaccurate metadata
- Restriction of processing for specific requests

AUDIT & COMPLIANCE
Nettle is designed to be used in development environments, not production. If
processing production data, you must ensure adequate Data Protection Impact
Assessment (DPIA) and compliance with your applicable data protection laws.

DATA RETENTION
Scan reports are retained for [YOUR RETENTION POLICY]. Audit logs are retained
separately per compliance requirements. Contact us to request earlier deletion.
    `.trim(),
    version: "1.0",
    updatedAt: "2026-08-16",
  },

  "ai-generated": {
    title: "AI-Generated Content & Explanations",
    text: `
ABOUT AI-GENERATED REMEDIATION GUIDANCE

Some findings include remediation suggestions and explanations that are generated
or assisted by AI models (Claude). These are provided for educational purposes and
as starting points, not as professional security advice.

AI LIMITATIONS
- May oversimplify complex security concepts
- May suggest approaches that don't fit your specific architecture
- May miss edge cases or unusual threat models
- Should not replace human security expertise

HUMAN REVIEW REQUIRED
Always have AI-generated remediation reviewed by a qualified developer or security
professional before implementing. Test thoroughly in a non-production environment
before deploying any security-related changes.

BEST USE
Use AI explanations as:
✓ Educational material to understand why something is flagged
✓ Starting points for remediation research
✓ Quick references while reviewing code

NOT as:
✗ Final security decisions without human review
✗ Compliance certifications or audit evidence
✗ Replacement for professional security consulting

If a remediation suggestion conflicts with your architecture or threat model,
defer to your own expertise and threat modeling.
    `.trim(),
    version: "1.0",
    updatedAt: "2026-08-16",
  },

  "scope-limitation": {
    title: "Scope & Limitations",
    text: `
WHAT NETTLE ANALYZES

✓ Static code patterns (hardcoded secrets, SQL injection patterns, etc.)
✓ Known vulnerable dependencies (npm, pip, etc.)
✓ Common misconfigurations (missing auth, weak encryption, etc.)
✓ Framework-specific patterns (Express middleware, Django decorators, etc.)

WHAT NETTLE DOES NOT ANALYZE

✗ Runtime behavior (how the code actually executes)
✗ Business logic flaws (authorization decisions based on wrong data)
✗ Infrastructure security (server configuration, network policy, etc.)
✗ Deployment security (CI/CD pipeline, container images, etc.)
✗ Cryptographic implementation details (side-channel attacks, etc.)
✗ Advanced attacks (timing attacks, symbolic execution paths, etc.)

ANALYSIS BOUNDARIES

- File size limits: Projects over 500MB may be skipped
- Timeout limits: Analysis stops after 30 seconds per component
- Framework detection: Limited to major frameworks
- Dependency scanning: Works best with lock files (package-lock.json, etc.)

DEPENDENCIES & THIRD-PARTY DATA

Nettle uses publicly available vulnerability databases (OSV, npm, PyPI). These
databases may lag behind actual vulnerability disclosure (typically 7-30 days).
Vulnerabilities may be under-reported, especially in niche packages.

TESTING ENVIRONMENT

Nettle is designed for development and CI/CD environments. Do not rely on it
as your sole security mechanism for production systems. Layer multiple security
controls: code review, static analysis, dynamic testing, penetration testing.
    `.trim(),
    version: "1.0",
    updatedAt: "2026-08-16",
  },
};

/**
 * Get a disclaimer by type.
 */
export function getDisclaimer(type: DisclaimerType): DisclaimerText {
  return DISCLAIMERS[type] || DISCLAIMERS["liability"];
}

/**
 * Get all disclaimers as a composite document.
 */
export function getFullLegalDocument(): string {
  const disclaimerTypes: DisclaimerType[] = ["liability", "accuracy", "scope-limitation", "gdpr", "ai-generated"];

  const sections = disclaimerTypes.map((type) => {
    const disclaimer = getDisclaimer(type);
    return `## ${disclaimer.title}\n\n${disclaimer.text}`;
  });

  return `# Nettle Security Scanner - Legal Notices & Disclaimers

Last Updated: ${new Date().toISOString()}

${sections.join("\n\n---\n\n")}

---

**By using Nettle, you acknowledge that you have read and understood these
disclaimers and limitations.**
  `.trim();
}

/**
 * Get disclaimer summary for inclusion in reports.
 */
export function getDisclaimerSummary(): string {
  return `⚠ DISCLAIMER: Nettle's findings are based on static analysis and may include
false positives or miss real vulnerabilities. Always have findings reviewed by
a human security expert. See full disclaimers at /docs/legal`;
}

/**
 * Get disclaimer for API responses.
 */
export function getAPIDisclaimer(): string {
  return `This scan includes static analysis findings. Findings marked as NOT_VERIFIED
were not fully analyzed. See disclaimer for limitations and accuracy caveats.`;
}
