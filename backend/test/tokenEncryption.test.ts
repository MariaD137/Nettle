import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { encryptToken, decryptToken, MissingEncryptionKeyError } from "../src/security/tokenEncryption";

// The key is read from the environment lazily, at call time (not at import
// time), so setting it here before any test runs is sufficient.
process.env.NETTLE_TOKEN_ENCRYPTION_KEY = crypto.randomBytes(32).toString("base64");

test("encryptToken/decryptToken round-trips a secret", () => {
  const plaintext = "ghp_aRealLookingGitHubTokenValue1234567890";
  const encrypted = encryptToken(plaintext);
  assert.notEqual(encrypted, plaintext);
  assert.equal(decryptToken(encrypted), plaintext);
});

test("encrypting the same plaintext twice produces different ciphertext (random IV)", () => {
  const a = encryptToken("same-secret");
  const b = encryptToken("same-secret");
  assert.notEqual(a, b);
  assert.equal(decryptToken(a), "same-secret");
  assert.equal(decryptToken(b), "same-secret");
});

test("a tampered ciphertext fails to decrypt instead of silently returning garbage", () => {
  const encrypted = encryptToken("hunter2");
  const [iv, tag, data] = encrypted.split(":");
  const tamperedByte = Buffer.from(data, "base64");
  tamperedByte[0] ^= 0xff;
  const tampered = `${iv}:${tag}:${tamperedByte.toString("base64")}`;
  assert.throws(() => decryptToken(tampered));
});

test("encryptToken throws MissingEncryptionKeyError when the key env var is unset", async () => {
  const saved = process.env.NETTLE_TOKEN_ENCRYPTION_KEY;
  delete process.env.NETTLE_TOKEN_ENCRYPTION_KEY;
  try {
    assert.throws(() => encryptToken("anything"), MissingEncryptionKeyError);
  } finally {
    process.env.NETTLE_TOKEN_ENCRYPTION_KEY = saved;
  }
});

test("rejects a key that doesn't decode to 32 bytes", async () => {
  const saved = process.env.NETTLE_TOKEN_ENCRYPTION_KEY;
  process.env.NETTLE_TOKEN_ENCRYPTION_KEY = Buffer.from("too-short").toString("base64");
  try {
    assert.throws(() => encryptToken("anything"), /32 bytes/);
  } finally {
    process.env.NETTLE_TOKEN_ENCRYPTION_KEY = saved;
  }
});
