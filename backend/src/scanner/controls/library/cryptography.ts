import type { Control } from "../types";
import { registerControl } from "../registry";

export const CRYPTO_001: Control = {
  controlKey: "CRYPTO-001",
  category: "Cryptography",
  subcategory: "Weak/deprecated primitives",
  name: "No weak or deprecated cryptographic primitives",
  description:
    "Cryptographic operations (hashing, encryption, random generation) must use algorithms and modes that are " +
    "still considered secure — not MD5, SHA-1, DES/3DES, RC4, ECB mode, the deterministic-IV form of " +
    "crypto.createCipher, or Math.random() for anything security-sensitive.",
  question: "Does the application avoid weak, deprecated, or broken cryptographic primitives?",
  defaultSeverity: "high",

  passCriteria: "No weak-cryptography pattern (see failCriteria) was matched in the scanned source.",
  failCriteria: "A weak or deprecated cryptographic primitive was matched: MD5 or SHA-1 hashing, DES/3DES/RC4 encryption, ECB mode, crypto.createCipher (no IV), Math.random() used for a token/secret/key, or a hardcoded encryption key.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so its cryptographic usage was not checked.",

  whyItMatters:
    "Each of these primitives has a known, practical break: MD5 and SHA-1 have demonstrated collision attacks, " +
    "DES's 56-bit key is brute-forceable in hours, RC4 has statistical biases that leak plaintext, ECB mode leaks " +
    "data patterns between identical blocks, and Math.random() is not cryptographically unpredictable — an attacker " +
    "who can observe enough output can predict future values. Using any of these for security-sensitive data is a " +
    "known, not theoretical, weakness.",

  technologyFixes: [
    {
      technology: "node-crypto",
      quickFix: "Swap the weak primitive for its modern equivalent: SHA-256 for hashing, AES-256-GCM for encryption, crypto.randomBytes()/randomUUID() for random values, Argon2id/bcrypt for passwords.",
      developerFix: "Use crypto.createHash('sha256') or a purpose-built password hash (argon2, bcrypt — never a raw hash for passwords); crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(16)) for encryption; crypto.randomBytes()/crypto.randomUUID() for tokens, keys, and session IDs.",
      architectureFix: "Centralize cryptographic operations behind a small internal module (hashPassword, encrypt, generateToken) so a future audit only has to check one place, not every call site.",
      codeExample: "const iv = crypto.randomBytes(16);\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv);",
    },
    {
      technology: "generic",
      quickFix: "Replace the weak primitive with its modern, still-secure equivalent for the same purpose (hashing, encryption, or random generation).",
      developerFix: "Use SHA-256+ for integrity hashing, a dedicated password hash (Argon2id/bcrypt) for passwords, AES-256 in an authenticated mode (GCM) for encryption, and your platform's cryptographically secure random source for tokens/keys/IVs — never a general-purpose PRNG.",
      architectureFix: "Centralize cryptographic operations in one module so future changes and audits touch one place, not every call site.",
    },
  ],

  longTermHardening: "Add a lint rule or pre-commit check that flags createHash('md5'/'sha1'), createCipher( no iv), and Math.random() near token/secret/key-shaped variable names.",
  verificationMethod: "Rescan and confirm no weak-cryptography pattern remains in the source.",
  references: ["OWASP Top 10: A02:2021 – Cryptographic Failures", "NIST SP 800-131A (algorithm transitions)"],
  complianceMappings: ["SOC 2 CC6.1", "PCI DSS Req. 3, 4"],

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

registerControl(CRYPTO_001);
