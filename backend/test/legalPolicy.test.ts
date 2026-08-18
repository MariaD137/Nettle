import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import { scanLegalPolicy } from "../src/scanner/legalPolicy";
import { runScan } from "../src/scanner";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nettle-legalpolicy-"));
}

const FULL_DISCLOSURE_POLICY = `
# Privacy Policy

We collect your email address and usage data when you use our service.

We use this information to operate and improve the product.

We do not sell your data. We may share it with third-party processors
(e.g. our hosting provider) strictly to run the service.

We retain account data for as long as your account is active, and delete
it within 30 days of account closure.

You have the right to access, correct, or delete your data at any time,
and may opt-out of non-essential communications.
`;

const THIN_POLICY = `
# Privacy Policy

We take your privacy seriously.
`;

// --- Cookie policy / contact info: already-existing checks, still work ---

test("cookie policy and contact info are flagged as missing when absent", () => {
  const dir = tempDir();
  try {
    const { findings, passed } = scanLegalPolicy([], dir);
    assert.ok(findings.some((f) => f.title === "No cookie policy found"));
    assert.ok(findings.some((f) => f.title === "No contact information page found"));
    assert.equal(passed.some((p) => p.title === "Cookie policy file present"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("cookie policy and contact info pass when the files are present", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "COOKIE_POLICY.md"), "We use cookies.");
  fs.writeFileSync(path.join(dir, "CONTACT.md"), "support@example.com");
  try {
    const { findings, passed } = scanLegalPolicy([], dir);
    assert.equal(findings.some((f) => f.title === "No cookie policy found"), false);
    assert.equal(findings.some((f) => f.title === "No contact information page found"), false);
    assert.ok(passed.some((p) => p.title === "Cookie policy file present"));
    assert.ok(passed.some((p) => p.title === "Contact information present"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- Data handling disclosures (content-level, new) ---

test("no privacy policy at all skips the data-handling content check (already covered by the file-presence finding)", () => {
  const dir = tempDir();
  try {
    const { findings } = scanLegalPolicy([], dir);
    assert.ok(findings.some((f) => f.title === "No privacy policy found"));
    assert.equal(findings.some((f) => f.title === "Privacy policy doesn't disclose key data-handling practices"), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a privacy policy that doesn't cover key topics is flagged with the specific gaps", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "PRIVACY_POLICY.md"), THIN_POLICY);
  try {
    const { findings } = scanLegalPolicy([], dir);
    const finding = findings.find((f) => f.title === "Privacy policy doesn't disclose key data-handling practices");
    assert.ok(finding, "expected a data-handling disclosure finding");
    assert.equal(finding!.severity, "medium");
    assert.ok(finding!.detail.includes("what data is collected"));
    assert.ok(finding!.detail.includes("user rights"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a privacy policy covering collection, usage, sharing, retention, and rights passes cleanly", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "PRIVACY_POLICY.md"), FULL_DISCLOSURE_POLICY);
  try {
    const { findings, passed } = scanLegalPolicy([], dir);
    assert.equal(findings.some((f) => f.title === "Privacy policy doesn't disclose key data-handling practices"), false);
    assert.ok(passed.some((p) => p.title.includes("discloses data collection")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- Consent mechanisms (code-level, new) ---

test("an app with no cookie/tracking usage at all gets no consent finding or pass (not applicable)", () => {
  const dir = tempDir();
  const file = path.join(dir, "app.js");
  fs.writeFileSync(file, "app.get('/health', (req, res) => res.send('ok'));");
  try {
    const { findings, passed } = scanLegalPolicy([file], dir);
    assert.equal(findings.some((f) => f.title.includes("consent mechanism")), false);
    assert.equal(passed.some((p) => p.title.includes("consent mechanism")), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("tracking code with no consent mechanism is flagged at high severity", () => {
  const dir = tempDir();
  const file = path.join(dir, "app.js");
  fs.writeFileSync(
    file,
    `
      gtag('config', 'UA-XXXXX-Y');
      document.cookie = "session=abc123";
    `
  );
  try {
    const { findings } = scanLegalPolicy([file], dir);
    const finding = findings.find((f) => f.title === "No consent mechanism detected despite cookie/tracking usage");
    assert.ok(finding, "expected a missing-consent-mechanism finding");
    assert.equal(finding!.severity, "high");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("tracking code alongside a cookie-consent pattern passes", () => {
  const dir = tempDir();
  const file = path.join(dir, "app.js");
  fs.writeFileSync(
    file,
    `
      import CookieConsent from 'react-cookie-consent';
      if (hasConsented) {
        gtag('config', 'UA-XXXXX-Y');
      }
    `
  );
  try {
    const { findings, passed } = scanLegalPolicy([file], dir);
    assert.equal(findings.some((f) => f.title.includes("consent mechanism")), false);
    assert.ok(passed.some((p) => p.title === "A consent mechanism is present alongside cookie/tracking usage"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- Wiring ---

test("both new checks reach the aggregated scan report", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "PRIVACY_POLICY.md"), THIN_POLICY);
  fs.writeFileSync(path.join(dir, "app.js"), "fbq('track', 'PageView');");
  try {
    const report = runScan(dir);
    assert.ok(report.findings.some((f) => f.title === "Privacy policy doesn't disclose key data-handling practices"));
    assert.ok(report.findings.some((f) => f.title === "No consent mechanism detected despite cookie/tracking usage"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
