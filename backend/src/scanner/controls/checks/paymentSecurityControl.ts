import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const WEBHOOK_ROUTE_PATTERN = /app\.(post|use)\s*\(\s*['"`][^'"`]*(?:stripe|paypal|payment)[^'"`]*webhook/i;
const SIGNATURE_VERIFICATION_PATTERN = /stripe\.webhooks\.constructEvent|verifyWebhookSignature|constructEventAsync|paypal.*verify.*signature/i;
const AMOUNT_FROM_CLIENT_PATTERN = /\.(paymentIntents|charges)\.create\s*\(\s*\{[^}]*\b(amount|price)\s*:\s*req\.body/s;
const PAYMENT_CREATE_CALL = /\.(paymentIntents|charges)\.create\s*\(/;
const IDEMPOTENCY_KEY_PATTERN = /idempotencyKey/;
const RAW_CARD_FIELD_PATTERN = /req\.body\.(cardNumber|card_number|creditCardNumber|cvv|cvc|securityCode)\b|const\s*\{[^}]*\b(cardNumber|card_number|creditCardNumber|cvv|cvc)\b[^}]*\}\s*=\s*req\.body/;
const PAYMENT_SDK_PATTERN = /\bstripe\b|\bpaypal\b|braintree|adyen/i;

/**
 * PAY-001..004, wired to the control library. New in Phase B — the first
 * of the master spec's entirely-new security categories (§19-§26):
 * Payment Security had no coverage anywhere in the existing control
 * library. Added the "Payment Security" FindingCategory to support it.
 *
 * Gated in two layers, mirroring the "no unearned PASS/FAIL" pattern used
 * throughout Phase A (e.g. CORS/session-store controls returning nothing
 * at all when the relevant framework isn't used):
 * - If nothing in the scanned files even looks like a payment integration
 *   (no stripe/paypal/braintree/adyen reference anywhere), none of the 4
 *   controls produce a result at all — asserting "no payment security
 *   issues" for an app that doesn't process payments isn't a finding
 *   worth reporting.
 * - Within that, each control has its own narrower applicability gate:
 *   PAY-001 only applies to files with a webhook-shaped route; PAY-002/003
 *   only apply to files with an actual payment-creation call; PAY-004
 *   applies whenever payment code exists at all (raw card data could leak
 *   in without a create-call being anywhere nearby).
 */
export function scanPaymentSecurityControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  const perFile: { rel: string; text: string }[] = [];

  for (const file of jsFiles) {
    try {
      const text = fs.readFileSync(file, "utf8");
      allSource += text + "\n";
      perFile.push({ rel: path.relative(targetRoot, file), text });
    } catch {
      anyUnreadable = true;
    }
  }

  if (!PAYMENT_SDK_PATTERN.test(allSource)) {
    return []; // no payment integration detected at all — nothing to check
  }

  const results: CheckResult[] = [];
  let hasWebhookRoute = false;
  let webhookFailed = false;
  let hasPaymentCreateCall = false;
  let amountFailed = false;
  let idempotencyFailed = false;
  let cardFailed = false;

  for (const { rel, text } of perFile) {
    if (WEBHOOK_ROUTE_PATTERN.test(text)) {
      hasWebhookRoute = true;
      if (!SIGNATURE_VERIFICATION_PATTERN.test(text)) {
        webhookFailed = true;
        results.push({
          checkId: generateCheckId("Payment Security", "PAY-001:fail", rel),
          status: "FAIL",
          category: "Payment Security",
          title: "Payment webhook handler does not verify the provider's signature",
          detail: "A webhook route matching a payment provider was found with no recognized signature-verification call in the same file.",
          severity: "critical",
          file: rel,
          confidence: 75,
          detectionMethod: "regex",
          remediation: "Verify the webhook signature (e.g. stripe.webhooks.constructEvent) before processing the event.",
          controlKey: "PAY-001",
        });
      }
    }

    if (PAYMENT_CREATE_CALL.test(text)) {
      hasPaymentCreateCall = true;

      if (AMOUNT_FROM_CLIENT_PATTERN.test(text)) {
        amountFailed = true;
        results.push({
          checkId: generateCheckId("Payment Security", "PAY-002:fail", rel),
          status: "FAIL",
          category: "Payment Security",
          title: "Payment amount taken directly from the client request",
          detail: "A payment-creation call reads its amount/price value from req.body instead of computing or looking it up server-side.",
          severity: "critical",
          file: rel,
          confidence: 80,
          detectionMethod: "regex",
          remediation: "Look up the price server-side by product/plan ID rather than trusting the client-supplied amount.",
          controlKey: "PAY-002",
        });
      }

      if (!IDEMPOTENCY_KEY_PATTERN.test(text)) {
        idempotencyFailed = true;
        results.push({
          checkId: generateCheckId("Payment Security", "PAY-003:fail", rel),
          status: "FAIL",
          category: "Payment Security",
          title: "Payment-creation call has no idempotency key",
          detail: "A payment-creation call was found with no idempotency key referenced anywhere in the file, risking a duplicate charge on retry.",
          severity: "medium",
          file: rel,
          confidence: 65,
          detectionMethod: "regex",
          remediation: "Pass a unique, stable idempotency key (derived from the order ID) to the payment-creation call.",
          controlKey: "PAY-003",
        });
      }
    }

    if (RAW_CARD_FIELD_PATTERN.test(text)) {
      cardFailed = true;
      results.push({
        checkId: generateCheckId("Payment Security", "PAY-004:fail", rel),
        status: "FAIL",
        category: "Payment Security",
        title: "Raw card data read directly from the request body",
        detail: "A card-number/CVV-shaped field was read directly from req.body, putting the server in full PCI DSS scope instead of using client-side tokenization.",
        severity: "critical",
        file: rel,
        confidence: 85,
        detectionMethod: "regex",
        remediation: "Use the payment provider's client-side tokenization (Stripe Elements, PayPal Hosted Fields) so raw card data never reaches the server.",
        controlKey: "PAY-004",
      });
    }
  }

  if (hasWebhookRoute && !webhookFailed) {
    if (anyUnreadable) {
      results.push(notVerified("PAY-001", "webhook signature verification"));
    } else {
      results.push(pass("PAY-001", "Payment webhook handler verifies the provider's signature"));
    }
  }

  if (hasPaymentCreateCall && !amountFailed) {
    if (anyUnreadable) {
      results.push(notVerified("PAY-002", "payment amount handling"));
    } else {
      results.push(pass("PAY-002", "Payment amount is not taken directly from the client"));
    }
  }

  if (hasPaymentCreateCall && !idempotencyFailed) {
    if (anyUnreadable) {
      results.push(notVerified("PAY-003", "idempotency key usage"));
    } else {
      results.push(pass("PAY-003", "Payment-creation calls use an idempotency key"));
    }
  }

  if (!cardFailed) {
    if (anyUnreadable) {
      results.push(notVerified("PAY-004", "raw card data handling"));
    } else {
      results.push(pass("PAY-004", "No raw card data read directly from the request body"));
    }
  }

  return results;
}

function pass(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Payment Security", `${controlKey}:pass`),
    status: "PASS",
    category: "Payment Security",
    title,
    confidence: 80,
    detectionMethod: "regex",
    controlKey,
  };
}

function notVerified(controlKey: string, what: string): CheckResult {
  return {
    checkId: generateCheckId("Payment Security", `${controlKey}:unreadable`),
    status: "NOT_VERIFIED",
    category: "Payment Security",
    title: `Some files could not be read for ${what} analysis`,
    confidence: 0,
    detectionMethod: "regex",
    controlKey,
  };
}
