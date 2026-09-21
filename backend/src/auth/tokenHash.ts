import crypto from "crypto";

/**
 * One-way hash for bearer-style tokens held in the database (session tokens,
 * password-reset tokens).
 *
 * Storing the raw token means anyone who can read the table — a backup, a log
 * export, a SQL-injection read, a stolen volume — holds credentials they can
 * replay directly. Storing a hash means they hold something they cannot
 * present to the API.
 *
 * SHA-256 rather than scrypt/argon2 on purpose: these tokens are 32 bytes from
 * crypto.randomBytes, so there is no guessable plaintext to slow an attacker
 * down over, and lookups sit on the hot path of every authenticated request.
 * That reasoning does NOT transfer to passwords, which are low-entropy and
 * must keep using the KDF in passwords.ts.
 */
export function hashToken(rawToken: string): string {
  return crypto.createHash("sha256").update(rawToken, "utf8").digest("hex");
}

/**
 * The short, non-secret label shown for a session in the UI ("which of my
 * sessions is this?") and used to address one for revocation. Derived from the
 * hash, never from the raw token, so the label cannot narrow a search for the
 * real credential.
 */
export function tokenLabel(tokenHash: string): string {
  return tokenHash.slice(0, 8);
}
