import type { Control } from "../types";
import { registerControl } from "../registry";

export const PAY_001: Control = {
  controlKey: "PAY-001",
  category: "Payment Security",
  subcategory: "Webhook verification",
  name: "Payment webhook signature verification",
  description:
    "A payment provider's webhook endpoint (Stripe, PayPal, etc.) receives events over an unauthenticated public " +
    "URL — the only thing distinguishing a real event from a forged one is the provider's signature on the " +
    "request. A webhook handler that doesn't verify that signature will process a forged event exactly as if it " +
    "were real.",
  question: "Does the payment webhook handler verify the provider's signature before processing the event?",
  defaultSeverity: "critical",
  passCriteria: "A file with a payment-webhook-shaped route (a path containing \"webhook\" alongside stripe/paypal/payment) also contains a recognized signature-verification call.",
  failCriteria: "A file with a payment-webhook-shaped route contains no recognized signature-verification call.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so webhook signature verification was not checked in it.",
  whyItMatters:
    "Without signature verification, anyone who knows (or guesses) the webhook URL can POST a fabricated " +
    "\"payment succeeded\" event and get the application to grant whatever that event normally grants — " +
    "unlocking paid content, marking an order fulfilled, crediting an account — with no actual payment having " +
    "occurred.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Verify the webhook signature before processing the event, using the raw request body and the provider's signing secret.",
      developerFix: "For Stripe: use stripe.webhooks.constructEvent(rawBody, signatureHeader, endpointSecret) and reject the request if it throws. Make sure the raw, unparsed body is what's passed — a JSON-parsing body parser applied before this check breaks signature verification, since the signature is computed over the exact raw bytes.",
      architectureFix: "Keep the webhook endpoint's signing secret in the same secret-management mechanism as other credentials, scoped separately per environment (test vs. live) so a leaked test secret can't forge production events.",
      codeExample: "app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {\n  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);\n  // ... handle event\n});",
    },
  ],
  longTermHardening: "Add a test that POSTs an unsigned/forged event to the webhook endpoint and asserts it's rejected.",
  verificationMethod: "Rescan and confirm the webhook handler now verifies the signature before processing the event.",
  references: ["Stripe: Verify webhook signatures", "PayPal: Verify webhook signatures"],
  complianceMappings: ["PCI DSS"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const PAY_002: Control = {
  controlKey: "PAY-002",
  category: "Payment Security",
  subcategory: "Price integrity",
  name: "Payment amount not trusted from the client",
  description:
    "A payment-creation call (a Stripe PaymentIntent/charge, a PayPal order) that takes its amount or price " +
    "directly from the request body lets the client decide how much it pays — trivially bypassed with a modified " +
    "request.",
  question: "Is the payment amount looked up or computed server-side, rather than taken from the client's request?",
  defaultSeverity: "critical",
  passCriteria: "No scanned file passes req.body's amount/price value directly into a payment-creation call.",
  failCriteria: "A scanned file passes req.body's amount/price value directly into a payment-creation call (stripe.paymentIntents.create/stripe.charges.create or equivalent).",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so payment amount handling was not checked in it.",
  whyItMatters:
    "The browser, and everything in it, is fully under the user's control. Any value the client sends — including " +
    "an \"amount\" field — can be edited before the request is sent, no special tooling required beyond browser " +
    "devtools. The price the application actually charges must come from the server's own knowledge of what the " +
    "product/plan costs, never from what the client claims it costs.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Look up the price server-side by product/plan ID, and pass that value to the payment-creation call — never the client-supplied amount.",
      developerFix: "Replace amount: req.body.amount with a server-side lookup: amount: PRICES[req.body.planId], validating planId against a known set first.",
      codeExample: "const PRICES = { basic: 999, pro: 2999 };\nconst amount = PRICES[req.body.planId];\nif (!amount) return res.status(400).json({ error: 'invalid plan' });\nawait stripe.paymentIntents.create({ amount, currency: 'usd' });",
    },
  ],
  longTermHardening: "Add a test that submits a payment request with a tampered amount and asserts the server-computed price is what's actually charged.",
  verificationMethod: "Rescan and confirm the payment-creation call no longer reads its amount from the client request.",
  references: ["OWASP: Business Logic Vulnerabilities"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const PAY_003: Control = {
  controlKey: "PAY-003",
  category: "Payment Security",
  subcategory: "Idempotency",
  name: "Payment-creation calls use an idempotency key",
  description:
    "A payment-creation call made without an idempotency key will create a second, separate charge if the " +
    "request is retried — a network timeout, a double-click, or an automatic client retry after a slow response " +
    "can all trigger a duplicate charge for the same purchase.",
  question: "Do payment-creation calls include an idempotency key?",
  defaultSeverity: "medium",
  passCriteria: "A file that calls a payment-creation method (paymentIntents.create/charges.create or equivalent) also references an idempotency key.",
  failCriteria: "A file calls a payment-creation method with no idempotency key referenced anywhere in the file.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so idempotency-key usage was not checked in it.",
  whyItMatters:
    "Retries are a normal, expected part of network communication — clients retry on timeout, mobile connections " +
    "drop mid-request, load balancers can duplicate a request under failover. Without an idempotency key, the " +
    "payment provider has no way to recognize a retried request as \"the same purchase\" rather than a new one, " +
    "and charges the customer twice.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Pass a unique idempotency key (derived from the order/cart ID, not regenerated per request) to the payment-creation call.",
      developerFix: "Generate the idempotency key once per logical purchase attempt (e.g. a UUID stored alongside the pending order) and reuse the same key if the client retries — a key that changes on every call defeats the purpose.",
      codeExample: "await stripe.paymentIntents.create(\n  { amount, currency: 'usd' },\n  { idempotencyKey: order.id }\n);",
    },
  ],
  longTermHardening: "Add a test that fires the same payment request twice with the same idempotency key and asserts only one charge results.",
  verificationMethod: "Rescan and confirm the payment-creation call now includes an idempotency key.",
  references: ["Stripe: Idempotent requests"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const PAY_004: Control = {
  controlKey: "PAY-004",
  category: "Payment Security",
  subcategory: "Card data handling",
  name: "Raw card data not handled server-side",
  description:
    "A server reading a raw card number, CVV, or security code directly from the request body means that data " +
    "transited and touched the application's own servers — putting the application in full PCI DSS scope (SAQ D) " +
    "instead of the drastically reduced scope a tokenized integration (Stripe Elements, PayPal's own hosted " +
    "fields) gets.",
  question: "Is raw card data (number, CVV) kept off the server entirely, handled only by the payment provider's own client-side SDK?",
  defaultSeverity: "critical",
  passCriteria: "No scanned file reads a card-number/CVV-shaped field directly from the request body.",
  failCriteria: "A scanned file reads a card-number/CVV-shaped field (cardNumber, card_number, creditCardNumber, cvv, cvc, securityCode) directly from the request body.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so card-data handling was not checked in it.",
  whyItMatters:
    "A tokenized integration means the raw card number never reaches the application's server at all — the " +
    "provider's client-side SDK exchanges it for a token in the browser, and the server only ever sees that " +
    "token. A server that reads req.body.cardNumber has broken that boundary: the raw PAN now exists in the " +
    "application's own request logs, memory, and potentially its database, each of which is now PCI DSS scope " +
    "the application almost certainly isn't built or audited to handle.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Switch to the payment provider's client-side tokenization (Stripe Elements, PayPal Hosted Fields) so the server only ever receives a token, never the raw card number.",
      developerFix: "Replace the form fields posting cardNumber/cvv directly to your server with the provider's client-side SDK — it collects card details in an iframe it controls and returns a single-use token or payment method ID, which is what your server should receive instead.",
      codeExample: "// Client (Stripe Elements): const { paymentMethod } = await stripe.createPaymentMethod({ type: 'card', card: cardElement });\n// Server receives only paymentMethod.id, never the raw card number.",
    },
  ],
  longTermHardening: "If a PCI compliance audit is required, confirm with a QSA that no code path still reads or stores raw card data before certifying SAQ A eligibility.",
  verificationMethod: "Rescan and confirm no code path reads a raw card-number/CVV field from the request body.",
  references: ["PCI Security Standards Council: SAQ A vs SAQ D"],
  complianceMappings: ["PCI DSS"],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(PAY_001);
registerControl(PAY_002);
registerControl(PAY_003);
registerControl(PAY_004);
