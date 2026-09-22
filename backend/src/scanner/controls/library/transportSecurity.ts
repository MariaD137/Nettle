import type { Control } from "../types";
import { registerControl } from "../registry";

export const NET_001: Control = {
  controlKey: "NET-001",
  category: "Security",
  subcategory: "Transport security",
  name: "Encrypted transport enforced (HTTPS/TLS)",
  description:
    "Outbound and inbound connections should use HTTPS, and TLS certificate verification must never be disabled — " +
    "both a non-HTTPS URL and rejectUnauthorized: false remove the confidentiality/integrity guarantee TLS exists " +
    "to provide.",
  question: "Does the application use HTTPS for network connections, and does it verify TLS certificates?",
  defaultSeverity: "medium",

  passCriteria: "No plain-HTTP URL (other than localhost/loopback) and no TLS-verification bypass were found in the scanned source.",
  failCriteria: "Either a non-localhost http:// URL, or rejectUnauthorized: false (or an equivalent TLS-verification bypass), was found.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its network configuration was not checked.",

  whyItMatters:
    "Disabling certificate verification (rejectUnauthorized: false) removes TLS's ability to confirm the server on " +
    "the other end is who it claims to be — a connection an attacker can trivially intercept and impersonate. A " +
    "plain HTTP URL has no encryption at all: anything sent over it, including credentials or tokens, is readable " +
    "by anyone on the network path.",

  technologyFixes: [
    {
      technology: "node",
      quickFix: "Remove rejectUnauthorized: false, and change any non-localhost http:// URL to https://.",
      developerFix: "If a custom or internal CA is the actual reason verification was disabled, configure that CA explicitly (the ca option on https.Agent / tls.connect) instead of disabling verification entirely.",
      architectureFix: "For service-to-service calls inside a private network, prefer mTLS or a service mesh's transport encryption over disabling verification as a shortcut.",
      codeExample: "const agent = new https.Agent({ ca: fs.readFileSync('internal-ca.pem') }); // not rejectUnauthorized: false",
    },
    {
      technology: "generic",
      quickFix: "Enable TLS certificate verification (it should never be explicitly disabled) and use HTTPS for any non-local network call.",
      developerFix: "If verification was disabled to trust a self-signed or internal certificate, configure that certificate explicitly as a trusted CA rather than turning verification off entirely.",
      architectureFix: "Standardize on HTTPS-only outbound calls at the HTTP client/library level, so a new call can't accidentally use plain HTTP.",
    },
  ],

  longTermHardening: "Add a network policy or egress rule that blocks plain HTTP outbound entirely, so a regression fails at the network layer even if it passes code review.",
  verificationMethod: "Rescan and confirm no non-localhost HTTP URL or TLS-verification bypass remains in the source.",
  references: ["OWASP Top 10: A02:2021 – Cryptographic Failures", "CWE-295: Improper Certificate Validation"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS Req. 4"],

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

registerControl(NET_001);
