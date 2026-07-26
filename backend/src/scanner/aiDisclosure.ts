import fs from "fs";
import type { Finding, Pass } from "./types";

const LOOKS_LIKE_AI_CONTENT = /generate|avatar|ai[-_]?image|ai[-_]?content/i;
const HAS_DISCLOSURE_MARKER = /ai[-_ ]?disclosure|c2pa|ai[-_ ]?generated content notice/i;

export function scanAIDisclosure(files: string[]): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];
  const allText = files.map((f) => fs.readFileSync(f, "utf8")).join("\n");

  const looksLikeAIGeneratedContent = LOOKS_LIKE_AI_CONTENT.test(allText);
  const hasDisclosureMarker = HAS_DISCLOSURE_MARKER.test(allText);

  if (looksLikeAIGeneratedContent && !hasDisclosureMarker) {
    findings.push({
      severity: "critical",
      category: "AI Disclosure",
      title: "AI-generated content returned to users with no disclosure label",
      detail: "Found an endpoint that appears to return AI-generated content (e.g. a generated image) with no accompanying disclosure or C2PA provenance metadata. California SB 942 requires this kind of content to be labeled.",
      file: null,
    });
  } else if (looksLikeAIGeneratedContent) {
    passed.push({ category: "AI Disclosure", title: "AI-generated content endpoints have a disclosure marker" });
  }

  return { findings, passed };
}
