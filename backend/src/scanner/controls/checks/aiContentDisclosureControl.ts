import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const LOOKS_LIKE_AI_CONTENT = /generate|avatar|ai[-_]?image|ai[-_]?content/i;
const HAS_DISCLOSURE_MARKER = /ai[-_ ]?disclosure|c2pa|ai[-_ ]?generated content notice/i;

/**
 * AI-005, wired to the control library. Extracted from aiDisclosure.ts's
 * former inline check -- same detection patterns, restructured to emit
 * CheckResult with a controlKey, with two fixes:
 *
 * 1. The legacy module called fs.readFileSync with no try/catch at all, so
 *    one unreadable file would throw and abort the entire scan, not just
 *    this check -- same defect class already fixed for SECRET-001. Now
 *    survives an unreadable file and reports NOT_VERIFIED for it instead.
 * 2. LOOKS_LIKE_AI_CONTENT is a deliberately broad, low-specificity
 *    heuristic ("avatar" and "generate" alone are common in ordinary,
 *    non-AI features -- an /avatar upload route matches with nothing to do
 *    with AI). The legacy finding asserted "California SB 942 requires
 *    this kind of content to be labeled" as settled fact from that weak
 *    signal alone. Confidence is now set low (40, triggering the release
 *    gate's two-step low-confidence downgrade) and the title/detail were
 *    softened to a review prompt rather than an asserted legal violation --
 *    matching the same legal-framing correction applied to LEGAL-001/003.
 */
export function scanAiContentDisclosureControl(files: string[], targetRoot: string): CheckResult[] {
  // No extension filter, matching the legacy module's behavior — it read
  // every file in the scanned set (including .env/.json), not just JS/TS.
  let allSource = "";
  let anyUnreadable = false;
  for (const file of files) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const looksLikeAiContent = LOOKS_LIKE_AI_CONTENT.test(allSource);
  if (!looksLikeAiContent) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("AI Disclosure", "AI-005:unreadable"),
          status: "NOT_VERIFIED",
          category: "AI Disclosure",
          title: "Some files could not be read for AI content-disclosure analysis",
          detail: "No AI-content-generation terminology was found in the files that could be read, but at least one file was unreadable and may have used it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AI-005",
        },
      ];
    }
    return []; // no content-generation terminology at all — nothing to check
  }

  const hasDisclosureMarker = HAS_DISCLOSURE_MARKER.test(allSource);
  if (hasDisclosureMarker) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-005:pass"),
        status: "PASS",
        category: "AI Disclosure",
        title: "AI-generated content endpoints have a disclosure marker",
        confidence: 40,
        detectionMethod: "heuristic",
        controlKey: "AI-005",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("AI Disclosure", "AI-005:unreadable"),
        status: "NOT_VERIFIED",
        category: "AI Disclosure",
        title: "Content-generation terminology is present but not every file could be read for disclosure analysis",
        detail: "No disclosure marker was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AI-005",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("AI Disclosure", "AI-005:fail"),
      status: "FAIL",
      category: "AI Disclosure",
      title: "Possible AI-generated content with no visible disclosure marker",
      detail: "Content-generation terminology (e.g. a generated image) was found with no accompanying disclosure or C2PA provenance metadata nearby. This is a broad heuristic, not confirmation the application serves AI-generated content without disclosure — review whether it applies before treating this as a compliance gap.",
      severity: "high",
      confidence: 40,
      detectionMethod: "heuristic",
      remediation: "If this applies, add visible AI-generated content labels to your UI and consider embedding C2PA provenance metadata in generated images/media.",
      controlKey: "AI-005",
    },
  ];
}
