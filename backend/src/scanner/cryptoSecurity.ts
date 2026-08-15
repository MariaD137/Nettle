import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

interface CryptoCheck {
  name: string;
  regex: RegExp;
  severity: Finding["severity"];
  detail: string;
  remediation: string;
}

const WEAK_CRYPTO: CryptoCheck[] = [
  {
    name: "MD5 hash usage",
    regex: /createHash\s*\(\s*['"]md5['"]\s*\)|\.md5\s*\(|MD5\s*\(/g,
    severity: "high",
    detail: "MD5 is cryptographically broken — collisions can be generated in seconds. It must not be used for passwords, integrity checks, or digital signatures.",
    remediation: "Replace MD5 with SHA-256 (for integrity) or Argon2id/bcrypt (for passwords).",
  },
  {
    name: "SHA-1 hash usage",
    regex: /createHash\s*\(\s*['"]sha1?['"]\s*\)/g,
    severity: "medium",
    detail: "SHA-1 has known collision attacks (SHAttered, 2017). Most security standards prohibit it for new applications.",
    remediation: "Replace SHA-1 with SHA-256 or SHA-3. For passwords, use Argon2id or bcrypt instead of any SHA variant.",
  },
  {
    name: "DES/3DES encryption",
    regex: /createCipher(iv)?\s*\(\s*['"]des(-ede3)?(-cbc|-ecb)?['"]/gi,
    severity: "high",
    detail: "DES uses a 56-bit key that can be brute-forced in hours. 3DES is deprecated by NIST as of 2023.",
    remediation: "Replace DES/3DES with AES-256-GCM: crypto.createCipheriv('aes-256-gcm', key, iv).",
  },
  {
    name: "RC4 cipher usage",
    regex: /createCipher(iv)?\s*\(\s*['"]rc4['"]/gi,
    severity: "high",
    detail: "RC4 has known statistical biases that allow plaintext recovery. It is prohibited by RFC 7465.",
    remediation: "Replace RC4 with AES-256-GCM.",
  },
  {
    name: "ECB mode encryption",
    regex: /createCipher(iv)?\s*\(\s*['"][a-z0-9]+-ecb['"]/gi,
    severity: "high",
    detail: "ECB mode encrypts identical plaintext blocks to identical ciphertext, leaking data patterns. The classic 'ECB penguin' demonstrates this visually.",
    remediation: "Use GCM mode (authenticated encryption) instead of ECB: aes-256-gcm.",
  },
  {
    name: "Deprecated crypto.createCipher (no IV)",
    regex: /crypto\.createCipher\s*\(/g,
    severity: "high",
    detail: "crypto.createCipher derives the IV from the password, making it deterministic and vulnerable to pattern analysis. It was deprecated in Node.js 10.",
    remediation: "Use crypto.createCipheriv with a random IV: crypto.randomBytes(16) for the IV, and AES-256-GCM for the algorithm.",
  },
  {
    name: "Math.random used for security",
    regex: /Math\.random\s*\(\s*\).*?(token|secret|key|password|salt|nonce|iv|session|csrf|otp|code)/gi,
    severity: "high",
    detail: "Math.random() is not cryptographically secure — its output is predictable. Using it for tokens, keys, or session IDs allows attackers to guess values.",
    remediation: "Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive random values.",
  },
  {
    name: "Hardcoded encryption key",
    regex: /(encrypt|cipher|aes|createCipher)\w*\s*\([^)]*['"][a-zA-Z0-9+/=]{16,}['"]/gi,
    severity: "critical",
    detail: "Hardcoded encryption keys in source code can be extracted by anyone with repository access, defeating the purpose of encryption.",
    remediation: "Load encryption keys from environment variables or a secrets manager (e.g. AWS KMS, HashiCorp Vault).",
  },
];

const GOOD_PATTERNS = {
  argon2: /(argon2|argon2id)/i,
  bcrypt: /bcrypt/i,
  aesGcm: /aes-256-gcm|aes-128-gcm/i,
  secureRandom: /crypto\.randomBytes|crypto\.randomUUID|randomBytes|getRandomValues/,
};

export function scanCrypto(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  let hasStrongHashing = false;
  let hasStrongEncryption = false;
  let hasSecureRandom = false;
  let usesCrypto = false;

  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    if (GOOD_PATTERNS.argon2.test(text) || GOOD_PATTERNS.bcrypt.test(text)) hasStrongHashing = true;
    if (GOOD_PATTERNS.aesGcm.test(text)) hasStrongEncryption = true;
    if (GOOD_PATTERNS.secureRandom.test(text)) hasSecureRandom = true;
    if (/crypto\.|require\(['"]crypto['"]\)|from ['"]crypto['"]/.test(text)) usesCrypto = true;

    for (const check of WEAK_CRYPTO) {
      const matches = text.match(check.regex);
      if (matches) {
        findings.push({
          severity: check.severity,
          category: "Cryptography",
          title: check.name,
          detail: check.detail,
          file: rel,
          remediation: check.remediation,
        });
      }
    }
  }

  if (hasStrongHashing) passed.push({ category: "Cryptography", title: "Strong password hashing detected (Argon2id or bcrypt)" });
  if (hasSecureRandom) passed.push({ category: "Cryptography", title: "Cryptographically secure random generation used" });
  if (usesCrypto && findings.length === 0) {
    passed.push({ category: "Cryptography", title: "No weak or deprecated cryptographic algorithms detected" });
  }

  return { findings, passed };
}
