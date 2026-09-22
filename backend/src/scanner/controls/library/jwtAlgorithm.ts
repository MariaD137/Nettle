import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_002: Control = {
  controlKey: "AUTH-002",
  category: "Session Management",
  subcategory: "JWT signing",
  name: "No 'none' algorithm for JWT signing",
  description:
    "A JWT library configured with algorithm: 'none' issues and accepts tokens with no cryptographic signature at " +
    "all — anyone can construct an arbitrary token by hand and have it accepted as valid.",
  question: "Is the application's JWT signing/verification configured to allow the 'none' algorithm?",
  defaultSeverity: "critical",

  passCriteria: "No JWT configuration in the scanned source sets algorithm: 'none'.",
  failCriteria: "A JWT sign or verify call is configured with algorithm: 'none'.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its JWT configuration was not checked.",

  whyItMatters:
    "This is CVE-class: several real-world JWT library vulnerabilities have come from exactly this — an attacker " +
    "takes a legitimate token, changes its header to declare algorithm 'none', strips the signature, and a verifier " +
    "that honors the token's own declared algorithm accepts it as valid. With 'none' configured deliberately, the " +
    "same bypass requires no exploit at all — it's the intended behavior.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Remove algorithm: 'none' from the JWT configuration immediately and redeploy — this is a live authentication bypass, not a hardening suggestion.",
      developerFix: "Use a strong signing algorithm (RS256, ES256, or at minimum HS256 with a properly random secret) and, on verification, pass an explicit algorithms allowlist so a token can't declare its own algorithm.",
      architectureFix: "Prefer asymmetric signing (RS256/ES256) so the verifying service only needs the public key, never the signing secret — limits the blast radius if a verifying service is compromised.",
      codeExample: "jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // explicit allowlist, never derived from the token itself",
    },
  ],

  longTermHardening: "Add a test that asserts a hand-crafted token with alg: 'none' and no signature is rejected — this is cheap to test and catches a regression immediately.",
  verificationMethod: "Rescan and confirm no JWT configuration in the source sets algorithm: 'none'.",
  references: ["CVE-2015-9235 (jsonwebtoken)", "CWE-347: Improper Verification of Cryptographic Signature"],
  complianceMappings: ["SOC 2 CC6.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "BLOCK_RELEASE",
    medium: "REVIEW_BEFORE_RELEASE",
    low: "FIX_RECOMMENDED",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(AUTH_002);
