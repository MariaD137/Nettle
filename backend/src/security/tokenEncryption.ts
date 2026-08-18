import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export class MissingEncryptionKeyError extends Error {
  constructor() {
    super(
      "NETTLE_TOKEN_ENCRYPTION_KEY is not configured — third-party credentials (e.g. a private repo access " +
        "token) cannot be stored until it is. Generate one with: openssl rand -base64 32"
    );
  }
}

function getKey(): Buffer {
  const raw = process.env.NETTLE_TOKEN_ENCRYPTION_KEY;
  if (!raw) throw new MissingEncryptionKeyError();
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("NETTLE_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes (a base64-encoded AES-256 key)");
  }
  return key;
}

/**
 * Encrypts an arbitrary secret (a third-party credential, not a Nettle
 * password — those are hashed, never encrypted) for storage at rest.
 * AES-256-GCM: the auth tag means a tampered ciphertext fails to decrypt
 * rather than silently producing garbage. Format is `iv:tag:ciphertext`,
 * each base64, so it round-trips through a single TEXT column.
 */
export function encryptToken(plaintext: string): string {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted.toString("base64")}`;
}

export function decryptToken(stored: string): string {
  const key = getKey();
  const parts = stored.split(":");
  if (parts.length !== 3) throw new Error("Malformed encrypted token");
  const [ivB64, tagB64, dataB64] = parts;
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(tagB64, "base64");
  const data = Buffer.from(dataB64, "base64");
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString("utf8");
}
