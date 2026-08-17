import { test } from "node:test";
import assert from "node:assert/strict";
import {
  getDisclaimer,
  getFullLegalDocument,
  getDisclaimerSummary,
  getAPIDisclaimer,
} from "../src/scanner/legalDisclaimer";

test("M-5/M-6: Get liability disclaimer", () => {
  const disclaimer = getDisclaimer("liability");

  assert.equal(disclaimer.title, "Limitation of Liability");
  assert.ok(disclaimer.text.includes("as-is"));
  assert.ok(disclaimer.text.includes("no warranty"));
  assert.ok(disclaimer.text.includes("NOT A SUBSTITUTE"));
  assert.equal(disclaimer.version, "1.0");
});

test("M-5/M-6: Get accuracy disclaimer", () => {
  const disclaimer = getDisclaimer("accuracy");

  assert.equal(disclaimer.title, "Accuracy & False Positives");
  assert.ok(disclaimer.text.includes("FALSE POSITIVES"));
  assert.ok(disclaimer.text.includes("FALSE NEGATIVES"));
  assert.ok(disclaimer.text.includes("NOT_VERIFIED"));
});

test("M-5/M-6: Get GDPR disclaimer", () => {
  const disclaimer = getDisclaimer("gdpr");

  assert.equal(disclaimer.title, "GDPR & Data Privacy");
  assert.ok(disclaimer.text.includes("Data Processor"));
  assert.ok(disclaimer.text.includes("Data Controller"));
  assert.ok(disclaimer.text.includes("data portability"));
  assert.ok(disclaimer.text.includes("Articles 15-20"));
});

test("M-5/M-6: Get AI-generated disclaimer", () => {
  const disclaimer = getDisclaimer("ai-generated");

  assert.equal(disclaimer.title, "AI-Generated Content & Explanations");
  assert.ok(disclaimer.text.includes("AI models"));
  assert.ok(disclaimer.text.includes("educational purposes"));
  assert.ok(disclaimer.text.toLowerCase().includes("human review"));
});

test("M-5/M-6: Get scope limitation disclaimer", () => {
  const disclaimer = getDisclaimer("scope-limitation");

  assert.equal(disclaimer.title, "Scope & Limitations");
  assert.ok(disclaimer.text.toLowerCase().includes("what nettle analyzes"));
  assert.ok(disclaimer.text.toLowerCase().includes("what nettle does not analyze"));
  assert.ok(disclaimer.text.toLowerCase().includes("static code patterns"));
});

test("M-5/M-6: All disclaimers have version and date", () => {
  const types = ["liability", "accuracy", "gdpr", "ai-generated", "scope-limitation"];

  for (const type of types as any[]) {
    const disclaimer = getDisclaimer(type);
    assert.ok(disclaimer.version);
    assert.ok(disclaimer.updatedAt);
    assert.ok(new Date(disclaimer.updatedAt) instanceof Date);
  }
});

test("M-5/M-6: Get full legal document", () => {
  const doc = getFullLegalDocument();

  assert.ok(doc.includes("## Limitation of Liability"));
  assert.ok(doc.includes("## Accuracy & False Positives"));
  assert.ok(doc.includes("## GDPR & Data Privacy"));
  assert.ok(doc.includes("## AI-Generated Content"));
  assert.ok(doc.includes("## Scope & Limitations"));
  assert.ok(doc.includes("By using Nettle, you acknowledge"));
});

test("M-5/M-6: Full document is properly formatted", () => {
  const doc = getFullLegalDocument();

  assert.ok(doc.startsWith("# Nettle Security Scanner"));
  assert.ok(doc.includes("Last Updated:"));
  assert.ok(doc.includes("---"));
  assert.ok(doc.length > 1000);
});

test("M-5/M-6: Get disclaimer summary for reports", () => {
  const summary = getDisclaimerSummary();

  assert.ok(summary.includes("⚠"));
  assert.ok(summary.includes("static analysis"));
  assert.ok(summary.includes("false positives"));
  assert.ok(summary.includes("human security expert"));
});

test("M-5/M-6: Get API disclaimer", () => {
  const disclaimer = getAPIDisclaimer();

  assert.ok(disclaimer.includes("static analysis"));
  assert.ok(disclaimer.includes("NOT_VERIFIED"));
  assert.ok(disclaimer.includes("limitations"));
});

test("M-5/M-6: Disclaimer summary is brief", () => {
  const summary = getDisclaimerSummary();

  // Should be short enough for UI display
  assert.ok(summary.length < 500);
});

test("M-5/M-6: API disclaimer is brief", () => {
  const disclaimer = getAPIDisclaimer();

  // Should be short enough for API response
  assert.ok(disclaimer.length < 300);
});

test("M-5/M-6: Liability disclaimer mentions key protections", () => {
  const liability = getDisclaimer("liability");

  assert.ok(liability.text.toLowerCase().includes("no warranty"));
  assert.ok(liability.text.toLowerCase().includes("security audit"));
  assert.ok(liability.text.toLowerCase().includes("code review"));
  assert.ok(liability.text.toLowerCase().includes("penetration"));
});

test("M-5/M-6: Scope limitation lists specific capabilities", () => {
  const scope = getDisclaimer("scope-limitation");

  // Check for what it DOES
  assert.ok(scope.text.includes("hardcoded secrets"));
  assert.ok(scope.text.includes("SQL injection"));
  assert.ok(scope.text.includes("vulnerable dependencies"));

  // Check for what it DOESN'T
  assert.ok(scope.text.includes("Runtime behavior"));
  assert.ok(scope.text.includes("Business logic flaws"));
  assert.ok(scope.text.includes("Infrastructure security"));
});

test("M-5/M-6: GDPR disclaimer mentions retention", () => {
  const gdpr = getDisclaimer("gdpr");

  assert.ok(gdpr.text.includes("DATA RETENTION"));
  assert.ok(gdpr.text.includes("deletion"));
});

test("M-5/M-6: AI disclaimer has clear action items", () => {
  const ai = getDisclaimer("ai-generated");

  assert.ok(ai.text.includes("✓"));
  assert.ok(ai.text.includes("✗"));
  assert.ok(ai.text.includes("Educational material"));
  assert.ok(ai.text.includes("Starting points"));
});
