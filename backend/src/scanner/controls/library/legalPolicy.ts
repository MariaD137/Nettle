import type { Control } from "../types";
import { registerControl } from "../registry";

export const LEGAL_001: Control = {
  controlKey: "LEGAL-001",
  category: "Legal & Policy",
  subcategory: "Privacy documentation",
  name: "Privacy policy present",
  description:
    "A privacy policy is standard for any app that collects, stores, or processes user data, and is required by " +
    "most app store submission processes. Whether one is legally required for a given app depends on facts this " +
    "scanner cannot determine from source alone: what data is actually collected, which jurisdictions its users " +
    "are in, and which distribution channels it uses.",
  question: "Is a privacy policy document present in the project?",
  defaultSeverity: "medium",

  passCriteria: "A file whose name matches a privacy-policy naming pattern was found in the scanned project.",
  failCriteria: "This control never emits FAIL — legal applicability cannot be determined from source alone, so its absence is reported as NOT_VERIFIED rather than a compliance failure.",
  notVerifiedCriteria: "No privacy-policy-named file was found in the scanned project. This does not mean the application is non-compliant: it may host its privacy policy externally (a marketing site, a legal/compliance platform) outside what was scanned, or may not be required to have one depending on what data it actually collects and where its users are. Human review is needed to determine actual applicability.",

  whyItMatters:
    "Nettle can reliably detect whether a privacy-policy-shaped file exists in what was scanned — that's a " +
    "verifiable fact. Whether GDPR, CCPA, or an app store's own submission requirements actually apply to this " +
    "specific application is a legal determination Nettle is not positioned to make from static analysis, so it " +
    "is reported as something requiring human review rather than asserted as a violation.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "If the application collects any user data, add a privacy policy (e.g. PRIVACY_POLICY.md, or hosted at /privacy) describing what's collected, how it's used, and how users can request deletion.",
      developerFix: "Review what personal data the application actually collects and which jurisdictions its users are in, then draft or link a privacy policy that reflects those facts — a generic template not matched to actual data practices creates its own compliance risk.",
      architectureFix: "Have legal counsel review the privacy policy against the application's actual data flows, especially if it processes data from EU (GDPR), California (CCPA), or other regulated jurisdictions.",
    },
  ],

  longTermHardening: "Keep the privacy policy under version control alongside the code so changes to data collection practices and the policy that describes them stay in sync.",
  verificationMethod: "Rescan and confirm a privacy-policy-named file is now present, and confirm separately (outside Nettle) that its content matches the application's actual data practices and applicable jurisdictions.",
  references: ["GDPR Art. 13 (Information to be provided)", "CCPA § 1798.100"],
  complianceMappings: ["GDPR", "CCPA"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

export const LEGAL_002: Control = {
  controlKey: "LEGAL-002",
  category: "Legal & Policy",
  subcategory: "Terms documentation",
  name: "Terms of service present",
  description:
    "Terms of service aren't universally legally required, but are standard practice for any application handling " +
    "user accounts or payments, and reduce dispute risk by setting explicit expectations with users up front.",
  question: "Is a terms-of-service document present in the project?",
  defaultSeverity: "medium",

  passCriteria: "A file whose name matches a terms-of-service naming pattern was found in the scanned project.",
  failCriteria: "No terms-of-service-named file was found anywhere in the scanned project.",
  notVerifiedCriteria: "Not applicable — this control does not depend on facts outside the scanned file set.",

  whyItMatters:
    "Terms of service establish acceptable use, liability limits, and dispute resolution up front, before a " +
    "disagreement happens rather than during one. Their absence is a completeness gap in the application's own " +
    "documentation, not a legal violation.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Create a TERMS.md (or host at /terms) outlining acceptable use, liability limitations, and dispute resolution.",
      developerFix: "Draft terms of service covering acceptable use, account termination conditions, liability limitations, and how disputes are resolved, tailored to what the application actually does.",
    },
  ],

  longTermHardening: "Version the terms of service alongside the application and note the effective date of each revision.",
  verificationMethod: "Rescan and confirm a terms-of-service-named file is now present.",
  references: [],
  complianceMappings: [],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

export const LEGAL_003: Control = {
  controlKey: "LEGAL-003",
  category: "Legal & Policy",
  subcategory: "Privacy documentation",
  name: "Cookie policy present",
  description:
    "If an application uses cookies or similar tracking technology, a cookie policy may be required under " +
    "ePrivacy/GDPR-derived regulations. Whether that applies to a given application depends on whether it actually " +
    "uses cookies or tracking and which jurisdictions its users are in — neither of which this file-existence " +
    "check determines.",
  question: "Is a cookie policy document present in the project?",
  defaultSeverity: "low",

  passCriteria: "A file whose name matches a cookie-policy naming pattern was found in the scanned project.",
  failCriteria: "This control never emits FAIL — whether a cookie policy is required depends on facts this scanner cannot verify (actual cookie/tracking usage, applicable jurisdiction), so its absence is reported as NOT_VERIFIED rather than a compliance failure.",
  notVerifiedCriteria: "No cookie-policy-named file was found in the scanned project. This does not confirm the application needs one: it may not use cookies or tracking at all, may cover cookies within its privacy policy instead, or may not be subject to the regulations that require one. Human review is needed to determine actual applicability.",

  whyItMatters:
    "Cookie/tracking disclosure requirements are conditional on both what the application actually does and where " +
    "its users are, not universal. Reporting a missing cookie-policy file as NOT_VERIFIED rather than a failure " +
    "avoids asserting a legal requirement Nettle has no way to confirm applies.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "If the application uses cookies or similar tracking, add a cookie policy (e.g. COOKIE_POLICY.md) or a cookie section within the privacy policy.",
      developerFix: "Inventory what cookies/tracking technology the application actually sets, then document their purpose and any consent mechanism in a cookie policy matched to that inventory.",
    },
  ],

  longTermHardening: "Re-audit the cookie inventory whenever a new analytics, advertising, or tracking integration is added.",
  verificationMethod: "Rescan and confirm a cookie-policy-named file is now present, and confirm separately (outside Nettle) that it accurately reflects the application's actual cookie/tracking usage.",
  references: ["ePrivacy Directive 2002/58/EC"],
  complianceMappings: ["GDPR"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

export const LEGAL_004: Control = {
  controlKey: "LEGAL-004",
  category: "Legal & Policy",
  subcategory: "Contact documentation",
  name: "Contact information present",
  description:
    "Users should have a documented way to reach the application's operator for support, legal inquiries, and " +
    "data deletion requests.",
  question: "Is contact information present in the project?",
  defaultSeverity: "low",

  passCriteria: "A file whose name matches a contact-information naming pattern was found in the scanned project.",
  failCriteria: "No contact-information-named file was found anywhere in the scanned project.",
  notVerifiedCriteria: "Not applicable — this control does not depend on facts outside the scanned file set.",

  whyItMatters:
    "Without a documented contact channel, users have no clear way to request data deletion, report a security " +
    "issue, or reach the operator for a legal matter — all things GDPR/CCPA-style data-subject rights depend on " +
    "being actually reachable, not just described in policy text.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Create a CONTACT.md, or include contact details directly in the privacy policy and terms of service.",
      developerFix: "Publish a monitored contact channel (an email address or a contact form) and reference it from the privacy policy's data-deletion-request section.",
    },
  ],

  longTermHardening: "Route the contact channel to a team that actually monitors and responds to it, not an inbox nobody checks.",
  verificationMethod: "Rescan and confirm a contact-information-named file is now present.",
  references: [],
  complianceMappings: [],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(LEGAL_001);
registerControl(LEGAL_002);
registerControl(LEGAL_003);
registerControl(LEGAL_004);
