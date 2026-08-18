import crypto from "crypto";
import { db, newSessionToken } from "../db";

const SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// The `sessions.token` column stores SHA-256(token), never the raw session
// token itself — a plaintext session token at rest is a bearer credential
// anyone with DB read access could use directly. SHA-256 (not a slow,
// salted hash like passwords use) is deliberate: this is looked up on
// every authenticated request and doesn't need password-hash-style
// brute-force resistance — the input space is already a 256-bit random
// token, not a guessable human password. The column name is unchanged
// from when it held the raw token, so every query below still reads
// "WHERE token = ?" — it's just matching a hash now. createSession()
// still *returns* the real, unhashed token; that's the only place the raw
// value ever exists outside the client that's holding it.
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function createSession(userId: string): string {
  const token = newSessionToken();
  const now = new Date();
  db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)").run(
    hashToken(token),
    userId,
    now.toISOString(),
    new Date(now.getTime() + SESSION_LIFETIME_MS).toISOString()
  );
  return token;
}

export function resolveSession(token: string): { userId: string } | null {
  const hashed = hashToken(token);
  const row = db.prepare("SELECT user_id, expires_at FROM sessions WHERE token = ?").get(hashed) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(hashed);
    return null;
  }
  return { userId: row.user_id };
}

export function destroySession(token: string): void {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(hashToken(token));
}

export interface SessionInfo {
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export function listSessions(userId: string, currentToken?: string): SessionInfo[] {
  const rows = db.prepare("SELECT token, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC").all(userId) as unknown as { token: string; created_at: string; expires_at: string }[];
  const now = Date.now();
  const currentHashed = currentToken ? hashToken(currentToken) : undefined;
  return rows
    .filter((r) => new Date(r.expires_at).getTime() > now)
    .map((r) => ({
      // A prefix of the hash, not the real token — still a stable,
      // per-session display identifier for a "manage sessions" UI, since
      // each session's hash is as unique as the token it came from.
      tokenPrefix: r.token.slice(0, 8) + "…",
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      current: r.token === currentHashed,
    }));
}

export function destroyAllSessions(userId: string): void {
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
}

export function destroySessionByPrefix(userId: string, tokenPrefix: string): boolean {
  const prefix = tokenPrefix.replace("…", "");
  const rows = db.prepare("SELECT token FROM sessions WHERE user_id = ? AND token LIKE ?").all(userId, `${prefix}%`) as unknown as { token: string }[];
  if (rows.length === 0) return false;
  for (const row of rows) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(row.token);
  }
  return true;
}

/**
 * Sweeps rows for sessions nobody ever came back to use (resolveSession
 * only lazily deletes a session at the exact moment its own token is
 * presented again — an abandoned session otherwise sits in the table
 * forever). Returns the number of rows removed, mainly so tests can
 * assert on it directly rather than waiting for the interval below.
 */
export function sweepExpiredSessions(): number {
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(new Date().toISOString());
  return Number(result.changes);
}

const SESSION_SWEEP_INTERVAL_MS = 60 * 60 * 1000; // hourly
const sessionSweepInterval = setInterval(() => sweepExpiredSessions(), SESSION_SWEEP_INTERVAL_MS);
sessionSweepInterval.unref();
