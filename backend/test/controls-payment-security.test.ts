import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import "../src/scanner/controls";
import { getControl } from "../src/scanner/controls/registry";
import { hydrateCheckResult } from "../src/scanner/controls/hydrate";
import { scanPaymentSecurityControl } from "../src/scanner/controls/checks/paymentSecurityControl";
import { compareScans, type ScanForComparison } from "../src/scanner/scanComparison";
import type { ScanReport, CheckResult } from "../src/scanner/types";

/**
 * PAY-001..004: the first Phase B category (Payment Security — master spec
 * §21), entirely new rather than migrated from a legacy module. No existing
 * control anywhere in the library covered webhook signature verification,
 * client-trusted payment amounts, payment idempotency, or raw card-data
 * handling — confirmed via grep before writing anything.
 *
 * Gated in two layers: nothing runs at all unless the scanned files
 * reference a payment SDK (stripe/paypal/braintree/adyen) at all, and each
 * control has its own narrower applicability gate within that (a webhook
 * route for PAY-001, an actual payment-creation call for PAY-002/003).
 */

function writeTempFile(dir: string, name: string, content: string): string {
  const file = path.join(dir, name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content, "utf8");
  return file;
}

function tmpDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

const ALL_KEYS = ["PAY-001", "PAY-002", "PAY-003", "PAY-004"];

test("PAY-001..004 are registered", () => {
  for (const key of ALL_KEYS) {
    assert.ok(getControl(key), `${key} should be registered`);
  }
});

test("scanPaymentSecurityControl: no result at all when no payment SDK is referenced anywhere", () => {
  const dir = tmpDir("nettle-pay-none-");
  const file = writeTempFile(dir, "app.js", `function add(a, b) { return a + b; }\n`);

  assert.equal(scanPaymentSecurityControl([file], dir).length, 0);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- PAY-001: webhook signature verification ---

test("scanPaymentSecurityControl: PAY-001 FAILs for a payment webhook route with no signature verification", () => {
  const dir = tmpDir("nettle-pay-webhook-nosig-");
  const file = writeTempFile(
    dir,
    "webhook.js",
    `const stripe = require('stripe')(key);\napp.post('/api/stripe/webhook', (req, res) => {\n  const event = JSON.parse(req.body);\n  res.json({ received: true });\n});\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-001");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: PAY-001 PASSes when the webhook verifies the signature", () => {
  const dir = tmpDir("nettle-pay-webhook-sig-");
  const file = writeTempFile(
    dir,
    "webhook.js",
    `const stripe = require('stripe')(key);\napp.post('/api/stripe/webhook', (req, res) => {\n  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret);\n  res.json({ received: true });\n});\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-001");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: PAY-001 produces no result when there's no webhook route at all (payment code present, but not applicable)", () => {
  const dir = tmpDir("nettle-pay-nowebhook-");
  const file = writeTempFile(dir, "checkout.js", `const stripe = require('stripe')(key);\nstripe.paymentIntents.create({ amount, currency: 'usd' });\n`);

  const results = scanPaymentSecurityControl([file], dir);
  assert.equal(results.find((r) => r.controlKey === "PAY-001"), undefined);

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- PAY-002: amount not trusted from client ---

test("scanPaymentSecurityControl: PAY-002 FAILs when the amount comes directly from req.body", () => {
  const dir = tmpDir("nettle-pay-amount-client-");
  const file = writeTempFile(
    dir,
    "checkout.js",
    `const stripe = require('stripe')(key);\nstripe.paymentIntents.create({\n  amount: req.body.amount,\n  currency: 'usd',\n});\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-002");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: PAY-002 PASSes when the amount is computed server-side", () => {
  const dir = tmpDir("nettle-pay-amount-server-");
  const file = writeTempFile(
    dir,
    "checkout.js",
    `const stripe = require('stripe')(key);\nconst amount = PRICES[req.body.planId];\nstripe.paymentIntents.create({ amount, currency: 'usd' });\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-002");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- PAY-003: idempotency key ---

test("scanPaymentSecurityControl: PAY-003 FAILs when a payment-creation call has no idempotency key anywhere in the file", () => {
  const dir = tmpDir("nettle-pay-noidem-");
  const file = writeTempFile(dir, "checkout.js", `const stripe = require('stripe')(key);\nstripe.paymentIntents.create({ amount, currency: 'usd' });\n`);

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-003");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "medium");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: PAY-003 PASSes when an idempotency key is used", () => {
  const dir = tmpDir("nettle-pay-idem-");
  const file = writeTempFile(
    dir,
    "checkout.js",
    `const stripe = require('stripe')(key);\nstripe.paymentIntents.create({ amount, currency: 'usd' }, { idempotencyKey: order.id });\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-003");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- PAY-004: raw card data ---

test("scanPaymentSecurityControl: PAY-004 FAILs when a card number is read directly from req.body", () => {
  const dir = tmpDir("nettle-pay-rawcard-");
  const file = writeTempFile(dir, "checkout.js", `const stripe = require('stripe')(key);\nconst { cardNumber, cvv } = req.body;\n`);

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-004");
  assert.ok(result);
  assert.equal(result!.status, "FAIL");
  assert.equal(result!.severity, "critical");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: PAY-004 PASSes when only a tokenized payment method is used", () => {
  const dir = tmpDir("nettle-pay-tokenized-");
  const file = writeTempFile(
    dir,
    "checkout.js",
    `const stripe = require('stripe')(key);\nconst { paymentMethodId } = req.body;\nstripe.paymentIntents.create({ payment_method: paymentMethodId });\n`
  );

  const results = scanPaymentSecurityControl([file], dir);
  const result = results.find((r) => r.controlKey === "PAY-004");
  assert.ok(result);
  assert.equal(result!.status, "PASS");

  fs.rmSync(dir, { recursive: true, force: true });
});

test("scanPaymentSecurityControl: NOT_VERIFIED when a file is unreadable and no evidence was found elsewhere", () => {
  const dir = tmpDir("nettle-pay-unread-");
  const good = writeTempFile(dir, "webhook.js", `const stripe = require('stripe')(key);\napp.post('/api/stripe/webhook', (req, res) => {\n  const event = stripe.webhooks.constructEvent(req.body, sig, secret);\n});\n`);
  const missing = path.join(dir, "missing.js");

  const results = scanPaymentSecurityControl([good, missing], dir);
  const result = results.find((r) => r.controlKey === "PAY-001");
  assert.ok(result);
  assert.equal(result!.status, "NOT_VERIFIED");

  fs.rmSync(dir, { recursive: true, force: true });
});

// --- hydration ---

test("hydration gives PAY-001 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Payment Security", title: "Payment webhook handler does not verify the provider's signature", severity: "critical", confidence: 75, controlKey: "PAY-001" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /signature/i);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE"); // confidence 75 is not < 75, so no downgrade applies
});

test("hydration gives PAY-004 a real fix", () => {
  const hydrated = hydrateCheckResult(
    { checkId: "x", status: "FAIL", category: "Payment Security", title: "Raw card data read directly from the request body", severity: "critical", confidence: 85, controlKey: "PAY-004" },
    { detectedTechnology: "generic" }
  );
  assert.ok(hydrated.recommendation);
  assert.match(hydrated.recommendation!.quickFix, /tokeniz/i);
  assert.equal(hydrated.releaseImpact, "BLOCK_RELEASE");
});

// --- scan comparison: a newly-added Phase B control participates in the diff engine ---

function report(checkResults: CheckResult[]): ScanReport {
  return {
    scannedAt: "2026-01-01T00:00:00.000Z",
    target: "app",
    scannerVersion: "1.3.0",
    score: 80,
    findings: [],
    passed: [],
    checkResults,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 },
  };
}

function scanAt(id: string, scannedAt: string, checkResults: CheckResult[]): ScanForComparison {
  return { id, scannedAt, status: "COMPLETED", report: report(checkResults) };
}

test("PAY-004 participates fully in scan comparison: open -> fixed -> regressed", () => {
  const dirRaw = tmpDir("nettle-pay-cmp-raw-");
  writeTempFile(dirRaw, "checkout.js", `const stripe = require('stripe')(key);\nconst { cardNumber } = req.body;\n`);
  const dirTokenized = tmpDir("nettle-pay-cmp-tok-");
  writeTempFile(dirTokenized, "checkout.js", `const stripe = require('stripe')(key);\nconst { paymentMethodId } = req.body;\n`);

  const rawResults = scanPaymentSecurityControl([path.join(dirRaw, "checkout.js")], dirRaw);
  const tokenizedResults = scanPaymentSecurityControl([path.join(dirTokenized, "checkout.js")], dirTokenized);

  const s1 = scanAt("s1", "2026-01-01T00:00:00Z", rawResults); // open
  const s2 = scanAt("s2", "2026-01-02T00:00:00Z", tokenizedResults); // fixed
  const s3 = scanAt("s3", "2026-01-03T00:00:00Z", rawResults); // regressed
  const history = [s1, s2, s3];

  const openToFixed = compareScans(history, "s1", "s2");
  assert.ok(openToFixed.fixed.some((f) => f.finding.controlKey === "PAY-004"));

  const fixedToRegressed = compareScans(history, "s2", "s3");
  assert.ok(fixedToRegressed.regressed.some((f) => f.finding.controlKey === "PAY-004"));
  assert.equal(fixedToRegressed.summary.new, 0, "a regression must not be miscounted as NEW");

  fs.rmSync(dirRaw, { recursive: true, force: true });
  fs.rmSync(dirTokenized, { recursive: true, force: true });
});
