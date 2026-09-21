import { db, newSessionToken } from "../db";
import { hashToken, tokenLabel } from "./tokenHash";

const SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// The raw token is returned to the caller once, at creation, and never stored.
// Everything persisted and every lookup goes through hashToken().
export function createSession(userId: string): string {
  const token = newSessionToken();
  const now = new Date();
  db.prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)").run(
    hashToken(token),
    userId,
    now.toISOString(),
    new Date(now.getTime() + SESSION_LIFETIME_MS).toISOString()
  );
  return token;
}

export function resolveSession(token: string): { userId: string } | null {
  const row = db.prepare("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?").get(hashToken(token)) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
    return null;
  }
  return { userId: row.user_id };
}

export function destroySession(token: string): void {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
}

export interface SessionInfo {
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export function listSessions(userId: string, currentToken?: string): SessionInfo[] {
  const rows = db.prepare("SELECT token_hash, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC").all(userId) as unknown as { token_hash: string; created_at: string; expires_at: string }[];
  const now = Date.now();
  const currentHash = currentToken ? hashToken(currentToken) : undefined;
  return rows
    .filter((r) => new Date(r.expires_at).getTime() > now)
    .map((r) => ({
      // A prefix of the hash, not of the token: this is a display/addressing
      // label, and deriving it from the real credential would publish the
      // first third of it to anyone who can call GET /api/auth/sessions.
      tokenPrefix: tokenLabel(r.token_hash),
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      current: currentHash !== undefined && r.token_hash === currentHash,
    }));
}

/**
 * Revokes every session for a user. Used on logout-everywhere, and on any
 * credential change — a password change or reset must not leave an attacker's
 * existing session alive, which is the whole point of changing the password.
 */
export function destroyAllSessions(userId: string): void {
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
}

/**
 * Revokes every session for a user except the one presented with the request.
 *
 * This is what a password change needs: an attacker who already holds a
 * session must lose it, while the person doing the change stays signed in on
 * the device they are using. A reset (where there is no trusted current
 * session) uses destroyAllSessions instead.
 */
export function destroyOtherSessions(userId: string, currentToken: string): number {
  const result = db
    .prepare("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?")
    .run(userId, hashToken(currentToken));
  return Number(result.changes ?? 0);
}

export function destroySessionByPrefix(userId: string, tokenPrefix: string): boolean {
  // Scoped to the caller's own rows, so a guessed prefix cannot reach another
  // account's session.
  const prefix = tokenPrefix.replace("…", "");
  if (!/^[0-9a-f]{1,64}$/.test(prefix)) return false;
  const rows = db.prepare("SELECT token_hash FROM sessions WHERE user_id = ? AND token_hash LIKE ?").all(userId, `${prefix}%`) as unknown as { token_hash: string }[];
  if (rows.length === 0) return false;
  for (const row of rows) {
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(row.token_hash);
  }
  return true;
}

/**
 * Removes sessions whose expiry has passed. Expiry is already enforced on
 * every lookup in resolveSession; this only stops rows accumulating for
 * sessions that are never presented again.
 */
export function purgeExpiredSessions(now = new Date()): number {
  const result = db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now.toISOString());
  return Number(result.changes ?? 0);
}
