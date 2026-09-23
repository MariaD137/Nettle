import type { Control } from "../types";
import { registerControl } from "../registry";

export const AI_005: Control = {
  controlKey: "AI-005",
  category: "AI Disclosure",
  subcategory: "Content labeling",
  name: "AI-generated content has a visible disclosure marker",
  description:
    "Some jurisdictions (e.g. California SB 942) require AI-generated content shown to users to carry a " +
    "disclosure — a visible label, or embedded provenance metadata such as C2PA. This check looks for generic " +
    "content-generation terminology (\"generate\", \"avatar\", AI-image/AI-content variants) alongside the absence " +
    "of a recognized disclosure marker.",
  question: "Does content that appears to be AI-generated carry a visible disclosure marker?",
  defaultSeverity: "high",

  passCriteria: "Generic content-generation terminology is present alongside a recognized disclosure marker (an AI-disclosure phrase, C2PA metadata, or an AI-generated-content notice).",
  failCriteria: "Generic content-generation terminology is present with no recognized disclosure marker found anywhere in the scanned source.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so content disclosure was not checked.",

  whyItMatters:
    "The underlying terminology this checks for (\"generate\", \"avatar\") is common in ordinary, non-AI features " +
    "too — a user profile-picture upload route matches \"avatar\" with nothing to do with AI. This is a broad, " +
    "low-specificity heuristic, not confirmation that the application actually generates and serves AI content to " +
    "users without disclosure. Whether SB 942 or a similar law actually applies depends on what the application " +
    "does and where its users are, which this scan cannot determine — treat a FAIL here as a prompt to review, not " +
    "as a determination that the application is out of compliance.",

  technologyFixes: [
    {
      technology: "generic",
      quickFix: "If the application generates and returns AI-generated content (images, video, audio) to users, add a visible disclosure label in the UI.",
      developerFix: "Add a visible \"AI-generated\" label near any content the model produces, and consider embedding C2PA provenance metadata in generated media so the disclosure survives outside the app's own UI.",
      architectureFix: "Have legal counsel confirm which AI-content-labeling regulations (SB 942 and equivalents) actually apply to the application's users and jurisdictions before relying on this check alone.",
    },
  ],

  longTermHardening: "Track which endpoints return model-generated content and keep the disclosure requirement in the same review checklist as any change to them.",
  verificationMethod: "Rescan and confirm a disclosure marker is now present alongside the content-generation terminology.",
  references: ["California SB 942 (AI Transparency Act)", "C2PA (Coalition for Content Provenance and Authenticity)"],
  complianceMappings: ["California SB 942"],

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

registerControl(AI_005);
